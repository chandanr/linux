// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_bit.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_inode.h"
#include "xfs_icache.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_dir2.h"
#include "xfs_bmap_btree.h"
#include "xfs_dir2_priv.h"
#include "xfs_trans_space.h"
#include "xfs_iwalk.h"
#include "xfs_health.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/trace.h"
#include "scrub/repair.h"
#include "scrub/parent.h"

/*
 * Scanning Directory Trees for Parent Pointers
 * ============================================
 *
 * Walk the inode table looking for directories.  Scan each directory looking
 * for directory entries that point to the target inode.  Call a function on
 * each match.
 */

typedef int (*xrep_parents_walk_fn)(struct xfs_inode *dp, struct xfs_name *name,
               unsigned int dtype, void *data);

struct xrep_parents_scan {
	/* Context for scanning all dentries in a directory. */
	struct dir_context	dc;
	void			*data;
	xrep_parents_walk_fn	fn;

	struct xfs_scrub	*sc;

	/* Potential parent of the directory we're scanning. */
//	xfs_ino_t		*parent_ino;

	/* This is the inode for which we want to find the parent. */
	xfs_ino_t		target_ino;

	/* Directory that we're scanning. */
	struct xfs_inode	*scan_dir;

	/* Errors encountered during scanning. */
	int			scan_error;
};

/*
 * If this directory entry points to the directory we're rebuilding, then the
 * directory we're scanning is the parent.  Call our function.
 *
 * Note that the vfs readdir functions squash the nonzero codes that we return
 * here into a "short" directory read, so the actual error codes are tracked
 * and returned separately.
 */
STATIC int
xrep_parents_iwalk_dirents(
	struct dir_context	*dc,
	const char		*name,
	int			namelen,
	loff_t			pos,
	u64			ino,
	unsigned		type)
{
	struct xrep_parents_scan *rps;

	rps = container_of(dc, struct xrep_parents_scan, dc);

	if (ino == rps->target_ino) {
		struct xfs_name	xname = { .name = name, .len = namelen };

		rps->scan_error = rps->fn(rps->scan_dir, &xname, type,
					  rps->data);
		if (rps->scan_error)
			return 1;
	}

	return 0;
}

/*
 * If this is a directory, walk the dirents looking for any that point to the
 * target directory.
 */
STATIC int
xrep_parents_iwalk(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_ino_t		ino,
	void			*data)
{
	struct xrep_parents_scan *rps = data;
	struct xfs_inode	*dp;
	loff_t			oldpos;
	size_t			bufsize;
	unsigned int		lock_mode;
	int			error;

	/* Skip the inode that we're trying to find the parents of. */
	if (ino == rps->target_ino)
		return 0;

	/*
	 * Grab inode and lock it so we can scan it.  If the inode is unlinked
	 * or free or corrupt we'll just ignore it, since callers must be able
	 * to handle the case that no parent is ever found.
	 */
	error = xfs_iget(mp, tp, ino, XFS_IGET_UNTRUSTED, 0, &dp);
	if (error)
		return 0;

	if (!S_ISDIR(VFS_I(dp)->i_mode))
		goto out_rele;

	/* Don't mix metadata and regular directory trees. */
	if (xfs_is_metadata_inode(dp) ^ xfs_is_metadata_inode(rps->sc->ip))
		goto out_rele;

	/*
	 * Try to get the parent directory's IOLOCK.  We still hold the child's
	 * IOLOCK in exclusive mode, so we must avoid an ABBA deadlock.
	 */
	error = xchk_ilock_inverted(dp, XFS_IOLOCK_SHARED);
	if (error)
		goto out_rele;

	/*
	 * If there are any blocks, read-ahead block 0 as we're almost certain
	 * to have the next operation be a read there.  This is how we
	 * guarantee that the directory's extent map has been loaded, if there
	 * is one.
	 */
	lock_mode = xfs_ilock_data_map_shared(dp);
	if (dp->i_df.if_nextents > 0)
		error = xfs_dir3_data_readahead(dp, 0, 0);
	xfs_iunlock(dp, lock_mode);
	if (error)
		goto out_unlock;

	/*
	 * Scan the directory to see if there it contains an entry pointing to
	 * the directory that we are repairing.
	 */
	rps->scan_dir = dp;
	bufsize = (size_t)min_t(loff_t, XFS_READDIR_BUFSIZE, dp->i_disk_size);
	oldpos = 0;
	while (true) {
		error = xfs_readdir(tp, dp, &rps->dc, bufsize);
		if (error)
			break;
		if (rps->scan_error) {
			error = rps->scan_error;
			break;
		}
		if (oldpos == rps->dc.pos)
			break;
		oldpos = rps->dc.pos;
	}

out_unlock:
	xfs_iunlock(dp, XFS_IOLOCK_SHARED);
out_rele:
	xfs_irele(dp);
	return error;
}

/*
 * Walk every dirent of every directory in the filesystem to find the entries
 * that point to the target inode.
 */
STATIC int
xrep_parents_walk(
	struct xfs_scrub	*sc,
	xfs_ino_t		target_ino,
	xrep_parents_walk_fn	fn,
	void			*data)
{
	struct xrep_parents_scan rps = {
		.sc		= sc,
		.dc.actor	= xrep_parents_iwalk_dirents,
		.data		= data,
		.fn		= fn,
		.target_ino	= target_ino,
	};

	return xfs_iwalk(sc->mp, sc->tp, 0, 0, xrep_parents_iwalk, 0,
			&rps);
}

/*
 * Repairing The Directory Parent Pointer
 * ======================================
 *
 * Currently, only directories support parent pointers (in the form of '..'
 * entries), so we simply scan the filesystem and update the '..' entry.
 *
 * Note that because the only parent pointer is the dotdot entry, we won't
 * touch an unhealthy directory, since the directory repair code is perfectly
 * capable of rebuilding a directory with the proper parent inode.
 */

/* Check the dentry cache to see if it thinks it knows of a parent. */
STATIC xfs_ino_t
xrep_parent_check_dcache(
	struct xfs_inode	*dp)
{
	struct inode		*pip = NULL;
	struct dentry		*dentry, *parent;
	xfs_ino_t		ret = NULLFSINO;

	ASSERT(S_ISDIR(VFS_I(dp)->i_mode));

	dentry = d_find_alias(VFS_I(dp));
	if (!dentry)
		goto out;

	parent = dget_parent(dentry);
	if (!parent)
		goto out_dput;

	if (parent->d_sb != dp->i_mount->m_super) {
		dput(parent);
		goto out_dput;
	}

	pip = igrab(d_inode(parent));
	dput(parent);

	if (S_ISDIR(pip->i_mode))
		ret = XFS_I(pip)->i_ino;

	xfs_irele(XFS_I(pip));

out_dput:
	dput(dentry);
out:
	return ret;
}

struct xrep_dir_parent_pick_info {
	struct xfs_scrub	*sc;
	xfs_ino_t		found_parent;
};

/*
 * If this directory entry points to the directory we're rebuilding, then the
 * directory we're scanning is the parent.  Remember the parent.
 */
STATIC int
xrep_dir_parent_pick(
	struct xfs_inode	*dp,
	struct xfs_name		*name,
	unsigned int		dtype,
	void			*data)
{
	struct xrep_dir_parent_pick_info *dpi = data;
	int			error = 0;

	/* Uhoh, more than one parent for a dir? */
	if (dpi->found_parent != NULLFSINO)
		return -EFSCORRUPTED;

	if (xchk_should_terminate(dpi->sc, &error))
		return error;

	/* We found a potential parent; remember this. */
	dpi->found_parent = dp->i_ino;
	return 0;
}

/*
 * Scan the directory @parent_ino to see if it has exactly one dirent that
 * points to the directory that we're examining.
 */
STATIC int
xrep_dir_parent_check(
	struct xfs_scrub	*sc,
	xfs_ino_t		parent_ino,
	bool			*is_parent)
{
	struct xrep_dir_parent_pick_info dpi = {
		.sc		= sc,
		.found_parent	= NULLFSINO,
	};
	struct xrep_parents_scan rps = {
		.sc		= sc,
		.dc.actor	= xrep_parents_iwalk_dirents,
		.data		= &dpi,
		.fn		= xrep_dir_parent_pick,
		.target_ino	= sc->ip->i_ino,
	};
	int			error;

	error = xrep_parents_iwalk(sc->mp, sc->tp, parent_ino, &rps);
	if (error)
		return error;

	*is_parent = dpi.found_parent == parent_ino;
	return 0;
}

/*
 * Find the parent of a directory.  Callers can pass in a suggested parent as
 * the initial value of @parent_ino, or NULLFSINO if they don't know.  If a
 * parent directory is found, it will be passed back out via @parent_ino.
 */
int
xrep_dir_parent_find(
	struct xfs_scrub	*sc,
	xfs_ino_t		*parent_ino)
{
	struct xrep_dir_parent_pick_info dpi = {
		.sc		= sc,
		.found_parent	= NULLFSINO,
	};
	xfs_ino_t		suggestion;
	bool			is_parent = false;
	int			error;

	/*
	 * If we are the root directory, then we are our own parent.  Return
	 * the root directory.
	 */
	if (sc->ip == sc->mp->m_rootip) {
		*parent_ino = sc->mp->m_sb.sb_rootino;
		return 0;
	}

	/*
	 * If we are the metadata root directory, then we are our own parent.
	 * Return the root directory.
	 */
	if (sc->ip == sc->mp->m_metadirip) {
		*parent_ino = sc->mp->m_sb.sb_metadirino;
		return 0;
	}

	/*
	 * If we are an unlinked directory, the parent won't have a link to us.
	 * We might as well return the suggestion, or the root directory if the
	 * suggestion is NULLFSINO or garbage.  There's no point in scanning
	 * the filesystem.
	 */
	if (VFS_I(sc->ip)->i_nlink == 0) {
		if (!xfs_verify_dir_ino(sc->mp, *parent_ino))
			*parent_ino = sc->mp->m_sb.sb_rootino;
		return 0;
	}

	/*
	 * If the caller provided a suggestion, check to see if that's really
	 * the parent.
	 */
	if (xfs_verify_dir_ino(sc->mp, *parent_ino)) {
		error = xrep_dir_parent_check(sc, *parent_ino, &is_parent);
		if (error || is_parent)
			return error;
	}

	/* Maybe the dcache will supply us with a parent? */
	suggestion = xrep_parent_check_dcache(sc->ip);
	if (!xfs_verify_dir_ino(sc->mp, suggestion)) {
		error = xrep_dir_parent_check(sc, suggestion, &is_parent);
		if (error)
			return error;
		if (is_parent) {
			*parent_ino = suggestion;
			return 0;
		}
	}

	/* Otherwise, scan the entire filesystem to find a parent. */
	error = xrep_parents_walk(sc, sc->ip->i_ino, xrep_dir_parent_pick,
			&dpi);
	if (error)
		return error;

	*parent_ino = dpi.found_parent;
	return 0;
}

/* Replace a directory's parent '..' pointer. */
STATIC int
xrep_dir_parent_replace(
	struct xfs_scrub	*sc,
	xfs_ino_t		parent_ino)
{
	xfs_ino_t		curr_parent = NULLFSINO;
	unsigned int		spaceres;
	int			error;

	/* If the '..' entry is already set to the parent inode, we're done. */
	error = xfs_dir_lookup(sc->tp, sc->ip, &xfs_name_dotdot, &curr_parent,
			NULL);
	if (!error && curr_parent == parent_ino)
		return 0;

	trace_xrep_dir_parent_replace(sc->ip, curr_parent, parent_ino);

	/* Reserve more space just in case we have to expand the dir. */
	spaceres = XFS_RENAME_SPACE_RES(sc->mp, 2);
	error = xfs_trans_reserve_more(sc->tp, spaceres, 0);
	if (error)
		return error;

	/* Re-take the ILOCK, we're going to need it to modify the dir. */
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);

	/* Replace the dotdot entry. */
	xfs_trans_ijoin(sc->tp, sc->ip, 0);
	return xfs_dir_replace(sc->tp, sc->ip, &xfs_name_dotdot, parent_ino,
			spaceres);
}

int
xrep_parent(
	struct xfs_scrub	*sc)
{
	xfs_ino_t		parent_ino = NULLFSINO;
	unsigned int		sick, checked;
	int			error;

	/*
	 * Avoid sick directories.  The parent pointer scrubber dropped the
	 * ILOCK, but we still hold IOLOCK_EXCL on the directory, so there
	 * shouldn't be anyone else clearing the directory's sick status.
	 */
	xfs_inode_measure_sickness(sc->ip, &sick, &checked);
	if (sick & XFS_SICK_INO_DIR)
		return -EFSCORRUPTED;

	/*
	 * Try to find the parent of this directory.  If we can't find it,
	 * we'll move the directory to lost+found.
	 */
	error = xrep_dir_parent_find(sc, &parent_ino);
	if (error)
		return error;
	if (parent_ino == NULLFSINO)
		return xrep_move_to_orphanage(sc);

	return xrep_dir_parent_replace(sc, parent_ino);
}
