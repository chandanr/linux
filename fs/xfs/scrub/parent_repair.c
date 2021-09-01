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

struct findparent_info {
	/* Context for scanning all dirents in a directory. */
	struct dir_context	dc;

	struct xfs_scrub	*sc;

	/* Directory that we're walking. */
	struct xfs_inode	*dp;

	/* Parent that we've found for sc->ip. */
	xfs_ino_t		found_parent;

	/*
	 * Errors encountered during scanning.  Note that the vfs readdir
	 * functions squash the nonzero codes that we return here into a
	 * "short" directory read, so the actual error codes are tracked and
	 * returned separately.
	 */
	int			scan_error;
};

#define FINDPARENT_INIT \
{ \
	.dc.actor	= findparent_visit_dirent, \
	.sc		= sc, \
	.found_parent	= NULLFSINO, \
}

/*
 * If this directory entry points to the scrub target inode, then the directory
 * we're scanning is the parent of the scrub target inode.
 */
STATIC int
findparent_visit_dirent(
	struct dir_context	*dc,
	const char		*name,
	int			namelen,
	loff_t			pos,
	u64			ino,
	unsigned		type)
{
	struct findparent_info	*fpi;

	fpi = container_of(dc, struct findparent_info, dc);

	if (xchk_should_terminate(fpi->sc, &fpi->scan_error))
		return 1;

	if (ino != fpi->sc->ip->i_ino)
		return 0;

	/* Uhoh, more than one parent for a dir? */
	if (fpi->found_parent != NULLFSINO) {
		trace_xrep_findparent_dirent(fpi->sc->ip, 0);
		fpi->scan_error = -ECANCELED;
		return 1;
	}

	/* We found a potential parent; remember this. */
	trace_xrep_findparent_dirent(fpi->sc->ip, fpi->dp->i_ino);
	fpi->found_parent = fpi->dp->i_ino;
	return 0;
}

/*
 * If this is a directory, walk the dirents looking for any that point to the
 * scrub target inode.
 */
STATIC int
findparent_walk_directory(
	struct xfs_mount	*mp,
	struct xfs_trans	*tp,
	xfs_ino_t		ino,
	void			*data)
{
	struct findparent_info	*fpi = data;
	struct xfs_inode	*dp;
	loff_t			oldpos;
	size_t			bufsize;
	unsigned int		lock_mode;
	int			error;

	/* Skip the inode that we're trying to find the parents of. */
	if (ino == fpi->sc->ip->i_ino)
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
	if (xfs_is_metadata_inode(dp) ^ xfs_is_metadata_inode(fpi->sc->ip))
		goto out_rele;

	/*
	 * Try to get the parent directory's IOLOCK.  We still hold the child's
	 * IOLOCK in exclusive mode, so we must avoid an ABBA deadlock.
	 */
	error = xchk_ilock_inverted(dp, XFS_IOLOCK_SHARED);
	if (error)
		goto out_rele;

	/*
	 * If this directory is known to be sick, we cannot scan it reliably
	 * and must abort.
	 */
	if (xfs_inode_has_sickness(dp, XFS_SICK_INO_CORE |
				       XFS_SICK_INO_BMBTD |
				       XFS_SICK_INO_DIR)) {
		error = -EFSCORRUPTED;
		goto out_unlock;
	}

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
	fpi->dp = dp;
	bufsize = (size_t)min_t(loff_t, XFS_READDIR_BUFSIZE, dp->i_disk_size);
	oldpos = 0;
	while (true) {
		error = xfs_readdir(tp, dp, &fpi->dc, bufsize);
		if (error)
			break;
		if (fpi->scan_error) {
			error = fpi->scan_error;
			break;
		}
		if (oldpos == fpi->dc.pos)
			break;
		oldpos = fpi->dc.pos;
	}

out_unlock:
	xfs_iunlock(dp, XFS_IOLOCK_SHARED);
out_rele:
	xfs_irele(dp);
	return error;
}

/*
 * Walk every dirent of every directory in the filesystem to find the parent
 * of the scrub target inode.
 */
STATIC int
findparent_walk_inodes(
	struct xfs_scrub	*sc,
	xfs_ino_t		*found_parent)
{
	struct findparent_info	fpi = FINDPARENT_INIT;
	unsigned int		flags = 0;
	int			error;

	if (xfs_is_metadata_inode(sc->ip))
		flags |= XFS_IWALK_METADIR;

	error = xfs_iwalk(sc->mp, sc->tp, 0, flags, findparent_walk_directory,
			0, &fpi);
	if (error == -ECANCELED) {
		/* Found multiple candidate parent for a dir. */
		*found_parent = NULLFSINO;
		return 0;
	}
	if (error)
		return error;

	*found_parent = fpi.found_parent;
	return 0;
}

/*
 * Decide if the directory @parent_ino has exactly one dirent that points to
 * the scrub target directory.
 */
STATIC bool
findparent_check_dir(
	struct xfs_scrub	*sc,
	xfs_ino_t		parent_ino)
{
	struct findparent_info	fpi = FINDPARENT_INIT;
	int			error;

	if (parent_ino == NULLFSINO ||
	    !xfs_verify_dir_ino(sc->mp, parent_ino))
		return false;

	error = findparent_walk_directory(sc->mp, sc->tp, parent_ino, &fpi);
	if (error)
		return false;

	return fpi.found_parent == parent_ino;
}

/* Check the dentry cache to see if knows of a parent for the scrub target. */
STATIC xfs_ino_t
findparent_from_dcache(
	struct xfs_scrub	*sc)
{
	struct inode		*pip = NULL;
	struct dentry		*dentry, *parent;
	xfs_ino_t		ret = NULLFSINO;

	dentry = d_find_alias(VFS_I(sc->ip));
	if (!dentry)
		goto out;

	parent = dget_parent(dentry);
	if (!parent)
		goto out_dput;

	if (parent->d_sb != sc->ip->i_mount->m_super) {
		dput(parent);
		goto out_dput;
	}

	pip = igrab(d_inode(parent));
	dput(parent);

	if (S_ISDIR(pip->i_mode)) {
		trace_xrep_findparent_dcache(sc->ip, XFS_I(pip)->i_ino);
		ret = XFS_I(pip)->i_ino;
	}

	xfs_irele(XFS_I(pip));

out_dput:
	dput(dentry);
out:
	return ret;
}

/*
 * Find the parent of the scrub target directory.  Callers can pass in a
 * suggested parent as the initial value of @parent_ino, or NULLFSINO if they
 * don't know.  If a parent directory is found, it will be passed back out via
 * @parent_ino.
 */
int
xrep_findparent(
	struct xfs_scrub	*sc,
	xfs_ino_t		*parent_ino)
{
	xfs_ino_t		ino;

	ASSERT(S_ISDIR(VFS_I(sc->ip)->i_mode));

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
		if (!xfs_verify_dir_ino(sc->mp, *parent_ino)) {
			if (xfs_is_metadata_inode(sc->ip))
				*parent_ino = sc->mp->m_sb.sb_metadirino;
			else
				*parent_ino = sc->mp->m_sb.sb_rootino;
		}
		return 0;
	}

	/*
	 * If the caller provided a suggestion, check to see if that's really
	 * the parent.
	 */
	if (findparent_check_dir(sc, *parent_ino))
		return 0;

	/* Maybe the vfs dentry cache will supply us with a parent? */
	ino = findparent_from_dcache(sc);
	if (findparent_check_dir(sc, ino)) {
		*parent_ino = ino;
		return 0;
	}

	/* Otherwise, scan the entire filesystem to find a parent. */
	return findparent_walk_inodes(sc, parent_ino);
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

	/* Re-take the ILOCK, we're going to need it to modify the dir. */
	sc->ilock_flags |= XFS_ILOCK_EXCL;
	xfs_ilock(sc->ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(sc->tp, sc->ip, 0);

	/* Reserve more space just in case we have to expand the dir. */
	spaceres = XFS_RENAME_SPACE_RES(sc->mp, 2);
	error = xfs_trans_reserve_more_inode(sc->tp, sc->ip, spaceres, 0);
	if (error)
		return error;

	/* Replace the dotdot entry. */
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
	 * we'll move the directory to the orphanage.
	 */
	error = xrep_findparent(sc, &parent_ino);
	if (error)
		return error;
	if (parent_ino == NULLFSINO)
		return xrep_move_to_orphanage(sc);

	error = xrep_ino_dqattach(sc);
	if (error)
		return error;

	return xrep_dir_parent_replace(sc, parent_ino);
}
