// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_trans.h"
#include "xfs_imeta.h"
#include "xfs_trace.h"
#include "xfs_inode.h"
#include "xfs_quota.h"
#include "xfs_bmap_btree.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_trans_space.h"
#include "xfs_dir2.h"

/*
 * Metadata Inode Number Management
 * ================================
 *
 * These functions provide an abstraction layer for looking up, creating, and
 * deleting metadata inodes.  These pointers live in the in-core superblock,
 * so the functions moderate access to those fields and take care of logging.
 *
 * For the five existing metadata inodes (real time bitmap & summary; and the
 * user, group, and quotas) we'll continue to maintain the in-core superblock
 * inodes for reads and only require xfs_imeta_create and xfs_imeta_unlink to
 * persist changes.  New metadata inode types must only use the xfs_imeta_*
 * functions.
 *
 * Callers wishing to create or unlink a metadata inode must pass in a
 * xfs_imeta_end structure.  After committing or cancelling the transaction,
 * this structure must be passed to xfs_imeta_end_update to free resources that
 * cannot be freed during the transaction.
 *
 * When the metadata directory tree (metadir) feature is enabled, we can create
 * a complex directory tree in which to store metadata inodes.  Inodes within
 * the metadata directory tree should have the "metadata" inode flag set to
 * prevent them from being exposed to the outside world.
 *
 * Callers are expected to take the ILOCK of metadata inodes to synchronize
 * access to the file.  This includes directory operations.  It is not
 * necessary to take the IOLOCK or MMAPLOCK since metadata inodes should never
 * be exposed to user space.
 */

/* Static metadata inode paths */
static const char *rtbitmap_path[]	= {"realtime", "0.bitmap"};
static const char *rtsummary_path[]	= {"realtime", "0.summary"};
static const char *usrquota_path[]	= {"quota", "user"};
static const char *grpquota_path[]	= {"quota", "group"};
static const char *prjquota_path[]	= {"quota", "project"};

XFS_IMETA_DEFINE_PATH(XFS_IMETA_RTBITMAP,	rtbitmap_path);
XFS_IMETA_DEFINE_PATH(XFS_IMETA_RTSUMMARY,	rtsummary_path);
XFS_IMETA_DEFINE_PATH(XFS_IMETA_USRQUOTA,	usrquota_path);
XFS_IMETA_DEFINE_PATH(XFS_IMETA_GRPQUOTA,	grpquota_path);
XFS_IMETA_DEFINE_PATH(XFS_IMETA_PRJQUOTA,	prjquota_path);

const struct xfs_imeta_path XFS_IMETA_METADIR = {
	.im_depth = 0,
	.im_ftype = XFS_DIR3_FT_DIR,
};

/* Are these two paths equal? */
STATIC bool
xfs_imeta_path_compare(
	const struct xfs_imeta_path	*a,
	const struct xfs_imeta_path	*b)
{
	unsigned int			i;

	if (a == b)
		return true;

	if (a->im_depth != b->im_depth)
		return false;

	for (i = 0; i < a->im_depth; i++)
		if (a->im_path[i] != b->im_path[i] &&
		    strcmp(a->im_path[i], b->im_path[i]))
			return false;

	return true;
}

/* Is this path ok? */
static inline bool
xfs_imeta_path_check(
	const struct xfs_imeta_path	*path)
{
	return path->im_depth <= XFS_IMETA_MAX_DEPTH;
}

/* Functions for storing and retrieving superblock inode values. */

/* Mapping of metadata inode paths to in-core superblock values. */
static const struct xfs_imeta_sbmap {
	const struct xfs_imeta_path	*path;
	unsigned int			offset;
} xfs_imeta_sbmaps[] = {
	{
		.path	= &XFS_IMETA_RTBITMAP,
		.offset	= offsetof(struct xfs_sb, sb_rbmino),
	},
	{
		.path	= &XFS_IMETA_RTSUMMARY,
		.offset	= offsetof(struct xfs_sb, sb_rsumino),
	},
	{
		.path	= &XFS_IMETA_USRQUOTA,
		.offset	= offsetof(struct xfs_sb, sb_uquotino),
	},
	{
		.path	= &XFS_IMETA_GRPQUOTA,
		.offset	= offsetof(struct xfs_sb, sb_gquotino),
	},
	{
		.path	= &XFS_IMETA_PRJQUOTA,
		.offset	= offsetof(struct xfs_sb, sb_pquotino),
	},
	{
		.path	= &XFS_IMETA_METADIR,
		.offset	= offsetof(struct xfs_sb, sb_metadirino),
	},
	{ NULL, 0 },
};

/* Return a pointer to the in-core superblock inode value. */
static inline xfs_ino_t *
xfs_imeta_sbmap_to_inop(
	struct xfs_mount		*mp,
	const struct xfs_imeta_sbmap	*map)
{
	return (xfs_ino_t *)(((char *)&mp->m_sb) + map->offset);
}

/* Compute location of metadata inode pointer in the in-core superblock */
static inline xfs_ino_t *
xfs_imeta_path_to_sb_inop(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path)
{
	const struct xfs_imeta_sbmap	*p;

	for (p = xfs_imeta_sbmaps; p->path; p++)
		if (xfs_imeta_path_compare(p->path, path))
			return xfs_imeta_sbmap_to_inop(mp, p);

	return NULL;
}

/* Look up a superblock metadata inode by its path. */
STATIC int
xfs_imeta_sb_lookup(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path,
	xfs_ino_t			*inop)
{
	xfs_ino_t			*sb_inop;

	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (!sb_inop)
		return -EINVAL;

	trace_xfs_imeta_sb_lookup(mp, sb_inop);
	*inop = *sb_inop;
	return 0;
}

/*
 * Create a new metadata inode and set a superblock pointer to this new inode.
 * The superblock field must not already be pointing to an inode.
 */
STATIC int
xfs_imeta_sb_create(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	umode_t				mode,
	unsigned int			flags,
	struct xfs_inode		**ipp)
{
	struct xfs_ialloc_args		args = {
		.nlink			= S_ISDIR(mode) ? 2 : 1,
	};
	struct xfs_mount		*mp = (*tpp)->t_mountp;
	xfs_ino_t			*sb_inop;
	int				error;

	xfs_ialloc_internal_args(&args, mode);

	/* Reject if the sb already points to some inode. */
	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (!sb_inop)
		return -EINVAL;

	if (*sb_inop != NULLFSINO)
		return -EEXIST;

	/* Otherwise, create the inode and set the sb pointer. */
	error = xfs_dir_ialloc(tpp, &args, ipp);
	if (error)
		return error;

	/* Attach dquots to this file.  Caller should have allocated them! */
	if (!(flags & XFS_IMETA_CREATE_NOQUOTA)) {
		error = xfs_qm_dqattach_locked(*ipp, false);
		if (error)
			return error;
		xfs_trans_mod_dquot_byino(*tpp, *ipp, XFS_TRANS_DQ_ICOUNT, 1);
	}

	/* Update superblock pointer. */
	*sb_inop = (*ipp)->i_ino;
	trace_xfs_imeta_sb_create(mp, sb_inop);
	xfs_log_sb(*tpp);
	return 0;
}

/*
 * Clear the given inode pointer from the superblock and drop the link count
 * of the metadata inode.
 */
STATIC int
xfs_imeta_sb_unlink(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip)
{
	struct xfs_mount		*mp = (*tpp)->t_mountp;
	xfs_ino_t			*sb_inop;

	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (!sb_inop)
		return -EINVAL;

	/* Reject if the sb doesn't point to the inode that was passed in. */
	if (*sb_inop != ip->i_ino)
		return -ENOENT;

	*sb_inop = NULLFSINO;
	trace_xfs_imeta_sb_unlink(mp, sb_inop);
	xfs_log_sb(*tpp);
	return xfs_droplink(*tpp, ip);
}

/* Set the given inode pointer in the superblock. */
STATIC int
xfs_imeta_sb_link(
	struct xfs_trans		*tp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip)
{
	struct xfs_mount		*mp = tp->t_mountp;
	xfs_ino_t			*sb_inop;

	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (!sb_inop)
		return -EINVAL;
	if (*sb_inop == NULLFSINO)
		return -EEXIST;

	xfs_ilock(ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);

	inc_nlink(VFS_I(ip));
	*sb_inop = ip->i_ino;
	trace_xfs_imeta_sb_link(mp, sb_inop);
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
	xfs_log_sb(tp);
	return 0;
}

/* Functions for storing and retrieving metadata directory inode values. */

static inline void
set_xname(
	struct xfs_name			*xname,
	const struct xfs_imeta_path	*path,
	unsigned int			path_idx,
	unsigned char			ftype)
{
	xname->name = (const unsigned char *)path->im_path[path_idx];
	xname->len = strlen(path->im_path[path_idx]);
	xname->type = ftype;
}

/*
 * Given a parent directory @dp, a metadata inode @path and component
 * @path_idx, and the expected file type @ftype of the path component, fill out
 * the @xname and look up the inode number in the directory, returning it in
 * @ino.
 */
static inline int
xfs_imeta_dir_lookup_component(
	struct xfs_inode		*dp,
	struct xfs_name			*xname,
	xfs_ino_t			*ino)
{
	int				type_wanted = xname->type;
	int				error;

	trace_xfs_imeta_dir_lookup_component(dp, xname, NULLFSINO);

	if (!S_ISDIR(VFS_I(dp)->i_mode))
		return -EFSCORRUPTED;

	error = xfs_dir_lookup(NULL, dp, xname, ino, NULL);
	if (error)
		return error;
	if (!xfs_verify_ino(dp->i_mount, *ino))
		return -EFSCORRUPTED;
	if (type_wanted != XFS_DIR3_FT_UNKNOWN && xname->type != type_wanted)
		return -EFSCORRUPTED;

	trace_xfs_imeta_dir_lookup_found(dp, xname, *ino);
	return 0;
}

/*
 * Traverse a metadata directory tree path, returning the inode corresponding
 * to the parent of the last path component.  If any of the path components do
 * not exist, return -ENOENT.
 */
STATIC int
xfs_imeta_dir_parent(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		**dpp)
{
	struct xfs_name			xname;
	struct xfs_inode		*dp;
	xfs_ino_t			ino;
	unsigned int			i;
	int				error;

	if (mp->m_metadirip == NULL)
		return -ENOENT;

	/* Grab the metadir root. */
	error = xfs_imeta_iget(mp, mp->m_metadirip->i_ino, XFS_DIR3_FT_DIR,
			&dp);
	if (error)
		return error;

	/* Caller wanted the root, we're done! */
	if (path->im_depth == 0) {
		*dpp = dp;
		return 0;
	}

	for (i = 0; i < path->im_depth - 1; i++) {
		/* Look up the name in the current directory. */
		set_xname(&xname, path, i, XFS_DIR3_FT_DIR);
		error = xfs_imeta_dir_lookup_component(dp, &xname, &ino);
		if (error)
			goto out_rele;

		/* Drop the existing dp and pick up the new one. */
		xfs_imeta_irele(dp);
		error = xfs_imeta_iget(mp, ino, XFS_DIR3_FT_DIR, &dp);
		if (error)
			return error;
	}

	*dpp = dp;
	return 0;

out_rele:
	xfs_imeta_irele(dp);
	return error;
}

/*
 * Look up a metadata inode from the metadata directory.  If the last path
 * component doesn't exist, return NULLFSINO.  If any other part of the path
 * does not exist, return -ENOENT so we can distinguish the two.
 */
STATIC int
xfs_imeta_dir_lookup_int(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path,
	xfs_ino_t			*inop)
{
	struct xfs_name			xname;
	struct xfs_inode		*dp = NULL;
	xfs_ino_t			ino;
	int				error;

	/* metadir ino is recorded in superblock */
	if (xfs_imeta_path_compare(path, &XFS_IMETA_METADIR))
		return xfs_imeta_sb_lookup(mp, path, inop);

	ASSERT(path->im_depth > 0);

	/* Find the parent of the last path component. */
	error = xfs_imeta_dir_parent(mp, path, &dp);
	if (error)
		return error;

	/* Look up the name in the current directory. */
	set_xname(&xname, path, path->im_depth - 1, path->im_ftype);
	error = xfs_imeta_dir_lookup_component(dp, &xname, &ino);
	switch (error) {
	case 0:
		*inop = ino;
		break;
	case -ENOENT:
		*inop = NULLFSINO;
		error = 0;
		break;
	}

	xfs_imeta_irele(dp);
	return error;
}

/*
 * Look up a metadata inode from the metadata directory tree.  If any of the
 * middle path components do not exist, we consider this corruption because
 * only the last component is allowed to not exist.
 */
STATIC int
xfs_imeta_dir_lookup(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path,
	xfs_ino_t			*inop)
{
	int				error;

	error = xfs_imeta_dir_lookup_int(mp, path, inop);
	if (error == -ENOENT)
		return -EFSCORRUPTED;
	return error;
}

/*
 * Load all the metadata inode pointers that are cached in the in-core
 * superblock but live somewhere in the metadata directory tree.
 */
STATIC int
xfs_imeta_dir_mount(
	struct xfs_mount		*mp)
{
	const struct xfs_imeta_sbmap	*p;
	xfs_ino_t			*sb_inop;
	int				err2;
	int				error = 0;

	for (p = xfs_imeta_sbmaps; p->path && p->path->im_depth > 0; p++) {
		if (p->path == &XFS_IMETA_METADIR)
			continue;
		sb_inop = xfs_imeta_sbmap_to_inop(mp, p);
		err2 = xfs_imeta_dir_lookup_int(mp, p->path, sb_inop);
		if (err2 == -ENOENT) {
			*sb_inop = NULLFSINO;
			continue;
		}
		if (!error && err2)
			error = err2;
	}

	return error;
}

/* Set up an inode to be recognized as a metadata inode. */
void
xfs_imeta_set_metaflag(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	VFS_I(ip)->i_mode &= ~0777;
	VFS_I(ip)->i_uid = GLOBAL_ROOT_UID;
	VFS_I(ip)->i_gid = GLOBAL_ROOT_GID;
	ip->i_projid = 0;
	ip->i_diflags |= (XFS_DIFLAG_IMMUTABLE | XFS_DIFLAG_SYNC |
			  XFS_DIFLAG_NOATIME | XFS_DIFLAG_NODUMP |
			  XFS_DIFLAG_NODEFRAG);
	if (S_ISDIR(VFS_I(ip)->i_mode))
		ip->i_diflags |= XFS_DIFLAG_NOSYMLINKS;
	ip->i_diflags2 &= ~XFS_DIFLAG2_DAX;
	ip->i_diflags2 |= XFS_DIFLAG2_METADATA;
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
}

/*
 * Create a new metadata inode accessible via the given metadata directory path.
 * Callers must ensure that the directory entry does not already exist; a new
 * one will be created.
 */
STATIC int
xfs_imeta_dir_create(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	umode_t				mode,
	unsigned int			flags,
	struct xfs_inode		**ipp,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_ialloc_args		args = {
		.nlink			= S_ISDIR(mode) ? 2 : 1,
	};
	struct xfs_name			xname;
	struct xfs_mount		*mp = (*tpp)->t_mountp;
	struct xfs_inode		*dp = NULL;
	xfs_ino_t			*sb_inop;
	xfs_ino_t			ino;
	unsigned int			resblks;
	int				error;

	xfs_ialloc_internal_args(&args, mode);

	/* metadir ino is recorded in superblock; only mkfs gets to do this */
	if (xfs_imeta_path_compare(path, &XFS_IMETA_METADIR)) {
		error = xfs_imeta_sb_create(tpp, path, mode, flags, ipp);
		if (error)
			return error;

		/* Set the metadata iflag, initialize directory. */
		xfs_imeta_set_metaflag(*tpp, *ipp);
		return xfs_dir_init(*tpp, *ipp, *ipp);
	}

	ASSERT(path->im_depth > 0);

	/*
	 * Find the parent of the last path component.  If the parent path does
	 * not exist, we consider this corruption because paths are supposed
	 * to exist.
	 */
	error = xfs_imeta_dir_parent(mp, path, &dp);
	if (error == -ENOENT)
		return -EFSCORRUPTED;
	if (error)
		return error;

	/* Check that the name does not already exist in the directory. */
	set_xname(&xname, path, path->im_depth - 1, XFS_DIR3_FT_UNKNOWN);
	error = xfs_imeta_dir_lookup_component(dp, &xname, &ino);
	switch (error) {
	case 0:
		error = -EEXIST;
		break;
	case -ENOENT:
		error = 0;
		break;
	}
	if (error)
		goto out_rele;

	xfs_ilock(dp, XFS_ILOCK_EXCL | XFS_ILOCK_PARENT);

	/*
	 * A newly created regular or special file just has one directory
	 * entry pointing to them, but a directory also the "." entry
	 * pointing to itself.
	 */
	args.pip = dp;
	error = xfs_dir_ialloc(tpp, &args, ipp);
	if (error)
		goto out_ilock;

	xfs_imeta_set_metaflag(*tpp, *ipp);

	/*
	 * Once we join the parent directory to the transaction we can't
	 * release it until after the transaction commits or cancels, so we
	 * must defer releasing it to end_update.  This is different from
	 * regular file creation, where the vfs holds the parent dir reference
	 * and will free it.  The caller is always responsible for releasing
	 * ipp, even if we failed.
	 */
	xfs_trans_ijoin(*tpp, dp, XFS_ILOCK_EXCL);
	cleanup->dp = dp;

	/* Create the entry. */
	if (S_ISDIR(args.mode))
		resblks = XFS_MKDIR_SPACE_RES(mp, xname.len);
	else
		resblks = XFS_CREATE_SPACE_RES(mp, xname.len);
	xname.type = xfs_mode_to_ftype(args.mode);
	trace_xfs_imeta_dir_try_create(dp, &xname, NULLFSINO);
	error = xfs_dir_create_new_child(*tpp, resblks, dp, &xname, *ipp);
	if (error)
		return error;
	trace_xfs_imeta_dir_created(*ipp, &xname, (*ipp)->i_ino);

	/* Attach dquots to this file.  Caller should have allocated them! */
	if (!(flags & XFS_IMETA_CREATE_NOQUOTA)) {
		error = xfs_qm_dqattach_locked(*ipp, false);
		if (error)
			return error;
		xfs_trans_mod_dquot_byino(*tpp, *ipp, XFS_TRANS_DQ_ICOUNT, 1);
	}

	/* Update the in-core superblock value if there is one. */
	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (sb_inop)
		*sb_inop = (*ipp)->i_ino;
	return 0;

out_ilock:
	xfs_iunlock(dp, XFS_ILOCK_EXCL);
out_rele:
	xfs_imeta_irele(dp);
	return error;
}

/*
 * Remove the given entry from the metadata directory and drop the link count
 * of the metadata inode.
 */
STATIC int
xfs_imeta_dir_unlink(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_name			xname;
	struct xfs_mount		*mp = (*tpp)->t_mountp;
	struct xfs_inode		*dp = NULL;
	xfs_ino_t			*sb_inop;
	xfs_ino_t			ino;
	unsigned int			resblks;
	int				error;

	/* Metadata directory root cannot be unlinked. */
	if (xfs_imeta_path_compare(path, &XFS_IMETA_METADIR)) {
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	ASSERT(path->im_depth > 0);

	/*
	 * Find the parent of the last path component.  If the parent path does
	 * not exist, we consider this corruption because paths are supposed
	 * to exist.
	 */
	error = xfs_imeta_dir_parent(mp, path, &dp);
	if (error == -ENOENT)
		return -EFSCORRUPTED;
	if (error)
		return error;

	/* Look up the name in the current directory. */
	set_xname(&xname, path, path->im_depth - 1,
			xfs_mode_to_ftype(VFS_I(ip)->i_mode));
	error = xfs_imeta_dir_lookup_component(dp, &xname, &ino);
	switch (error) {
	case 0:
		if (ino != ip->i_ino)
			error = -ENOENT;
		break;
	case -ENOENT:
		error = -EFSCORRUPTED;
		break;
	}
	if (error)
		goto out_rele;

	xfs_lock_two_inodes(dp, XFS_ILOCK_EXCL, ip, XFS_ILOCK_EXCL);

	/*
	 * Once we join the parent directory to the transaction we can't
	 * release it until after the transaction commits or cancels, so we
	 * must defer releasing it to end_update.  This is different from
	 * regular file removal, where the vfs holds the parent dir reference
	 * and will free it.  The unlink caller is always responsible for
	 * releasing ip, so we don't need to take care of that.
	 */
	xfs_trans_ijoin(*tpp, dp, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(*tpp, ip, XFS_ILOCK_EXCL);
	cleanup->dp = dp;

	resblks = XFS_REMOVE_SPACE_RES(mp);
	error = xfs_dir_remove_child(*tpp, resblks, dp, &xname, ip);
	if (error)
		return error;
	trace_xfs_imeta_dir_unlinked(dp, &xname, ip->i_ino);

	/* Update the in-core superblock value if there is one. */
	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (sb_inop)
		*sb_inop = NULLFSINO;
	return 0;

out_rele:
	xfs_imeta_irele(dp);
	return error;
}

/* Set the given path in the metadata directory to point to an inode. */
STATIC int
xfs_imeta_dir_link(
	struct xfs_trans		*tp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_name			xname;
	struct xfs_mount		*mp = tp->t_mountp;
	struct xfs_inode		*dp = NULL;
	xfs_ino_t			*sb_inop;
	xfs_ino_t			ino;
	unsigned int			resblks;
	int				error;

	/* Metadata directory root cannot be linked. */
	if (xfs_imeta_path_compare(path, &XFS_IMETA_METADIR)) {
		ASSERT(0);
		return -EFSCORRUPTED;
	}

	ASSERT(path->im_depth > 0);

	/*
	 * Find the parent of the last path component.  If the parent path does
	 * not exist, we consider this corruption because paths are supposed
	 * to exist.
	 */
	error = xfs_imeta_dir_parent(mp, path, &dp);
	if (error == -ENOENT)
		return -EFSCORRUPTED;
	if (error)
		return error;

	/* Look up the name in the current directory. */
	set_xname(&xname, path, path->im_depth - 1,
			xfs_mode_to_ftype(VFS_I(ip)->i_mode));
	error = xfs_imeta_dir_lookup_component(dp, &xname, &ino);
	switch (error) {
	case -ENOENT:
		break;
	case 0:
		error = -EEXIST;
		/* fall through */
	default:
		goto out_rele;
	}

	xfs_lock_two_inodes(ip, XFS_ILOCK_EXCL, dp, XFS_ILOCK_EXCL);

	/*
	 * Once we join the parent directory to the transaction we can't
	 * release it until after the transaction commits or cancels, so we
	 * must defer releasing it to end_update.  This is different from
	 * regular file removal, where the vfs holds the parent dir reference
	 * and will free it.  The link caller is always responsible for
	 * releasing ip, so we don't need to take care of that.
	 */
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);
	xfs_trans_ijoin(tp, dp, XFS_ILOCK_EXCL);
	cleanup->dp = dp;

	resblks = XFS_LINK_SPACE_RES(mp, target_name->len);
	error = xfs_dir_link_existing_child(tp, resblks, dp, &xname, ip);
	if (error)
		return error;

	trace_xfs_imeta_dir_link(dp, &xname, ip->i_ino);

	/* Update the in-core superblock value if there is one. */
	sb_inop = xfs_imeta_path_to_sb_inop(mp, path);
	if (sb_inop)
		*sb_inop = ip->i_ino;
	return 0;

out_rele:
	xfs_imeta_irele(dp);
	return error;
}

/* General functions for managing metadata inode pointers */

/*
 * Is this metadata inode pointer ok?  We allow the fields to be set to
 * NULLFSINO if the metadata structure isn't present, and we don't allow
 * obviously incorrect inode pointers.
 */
static inline bool
xfs_imeta_verify(
	struct xfs_mount	*mp,
	xfs_ino_t		ino)
{
	if (ino == NULLFSINO)
		return true;
	return xfs_verify_ino(mp, ino);
}

/* Look up a metadata inode by its path. */
int
xfs_imeta_lookup(
	struct xfs_mount		*mp,
	const struct xfs_imeta_path	*path,
	xfs_ino_t			*inop)
{
	xfs_ino_t			ino;
	int				error;

	ASSERT(xfs_imeta_path_check(path));

	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		error = xfs_imeta_dir_lookup(mp, path, &ino);
	else
		error = xfs_imeta_sb_lookup(mp, path, &ino);
	if (error)
		return error;

	if (!xfs_imeta_verify(mp, ino))
		return -EFSCORRUPTED;

	*inop = ino;
	return 0;
}

/*
 * Create a metadata inode with the given @mode, and insert it into the
 * metadata directory tree at the given @path.  The path (up to the final
 * component) must already exist.  The new metadata inode @ipp will be ijoined
 * and logged to @tpp, with the ILOCK held until the next transaction commit.
 * The caller must provide a @cleanup structure.
 *
 * Callers must ensure that the root dquots are allocated, if applicable.
 *
 * NOTE: This function may pass a child inode @ipp back to the caller even if
 * it returns a negative error code.  If an inode is passed back, the caller
 * must finish setting up the incore inode before releasing it.
 */
int
xfs_imeta_create(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	umode_t				mode,
	unsigned int			flags,
	struct xfs_inode		**ipp,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_mount		*mp = (*tpp)->t_mountp;

	ASSERT(xfs_imeta_path_check(path));
	*ipp = NULL;
	cleanup->dp = NULL;

	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		return xfs_imeta_dir_create(tpp, path, mode, flags, ipp,
				cleanup);
	return xfs_imeta_sb_create(tpp, path, mode, flags, ipp);
}

/*
 * Unlink a metadata inode @ip from the metadata directory given by @path.  The
 * metadata inode must not be ILOCKed.  Upon return, the inode will be ijoined
 * and logged to @tpp, and returned with reduced link count, ready to be
 * released.  The caller must provide a @cleanup structure.
 */
int
xfs_imeta_unlink(
	struct xfs_trans		**tpp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_mount		*mp = (*tpp)->t_mountp;
	cleanup->dp = NULL;

	ASSERT(xfs_imeta_path_check(path));
	ASSERT(xfs_imeta_verify((*tpp)->t_mountp, ip->i_ino));

	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		return xfs_imeta_dir_unlink(tpp, path, ip, cleanup);
	return xfs_imeta_sb_unlink(tpp, path, ip);
}

/*
 * Link the metadata directory given by @path point to the given inode number.
 * The path must not already exist.  The caller must not hold the ILOCK, and
 * the function will return with the inode joined to the transaction.
 */
int
xfs_imeta_link(
	struct xfs_trans		*tp,
	const struct xfs_imeta_path	*path,
	struct xfs_inode		*ip,
	struct xfs_imeta_end		*cleanup)
{
	struct xfs_mount		*mp = tp->t_mountp;

	ASSERT(xfs_imeta_path_check(path));

	cleanup->dp = NULL;
	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		return xfs_imeta_dir_link(tp, path, ip, cleanup);
	return xfs_imeta_sb_link(tp, path, ip);
}

/*
 * Clean up after committing (or cancelling) a metadata inode creation or
 * removal.
 */
void
xfs_imeta_end_update(
	struct xfs_mount		*mp,
	struct xfs_imeta_end		*cleanup,
	int				error)
{
	trace_xfs_imeta_end_update(mp, 0, error, _RET_IP_);

	if (cleanup->dp)
		xfs_imeta_irele(cleanup->dp);
	cleanup->dp = NULL;
}

/* Does this inode number refer to a static metadata inode? */
bool
xfs_is_static_meta_ino(
	struct xfs_mount		*mp,
	xfs_ino_t			ino)
{
	const struct xfs_imeta_sbmap	*p;

	if (ino == NULLFSINO)
		return false;

	for (p = xfs_imeta_sbmaps; p->path; p++)
		if (ino == *xfs_imeta_sbmap_to_inop(mp, p))
			return true;

	return false;
}

/* Ensure that the in-core superblock has all the values that it should. */
int
xfs_imeta_mount(
	struct xfs_mount	*mp)
{
	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		return xfs_imeta_dir_mount(mp);

	return 0;
}

/* Calculate the log block reservation to create a metadata inode. */
unsigned int
xfs_imeta_create_space_res(
	struct xfs_mount	*mp)
{
	if (xfs_sb_version_hasmetadir(&mp->m_sb))
		return max(XFS_MKDIR_SPACE_RES(mp, NAME_MAX),
			   XFS_CREATE_SPACE_RES(mp, NAME_MAX));
	return XFS_IALLOC_SPACE_RES(mp);
}

/* Calculate the log block reservation to unlink a metadata inode. */
unsigned int
xfs_imeta_unlink_space_res(
	struct xfs_mount	*mp)
{
	return XFS_REMOVE_SPACE_RES(mp);
}

/* Clear the metadata iflag if we're unlinking this inode. */
void
xfs_imeta_droplink(
	struct xfs_inode	*ip)
{
	if (VFS_I(ip)->i_nlink == 0 &&
	    xfs_sb_version_hasmetadir(&ip->i_mount->m_sb) &&
	    xfs_is_metadata_inode(ip))
		ip->i_diflags2 &= ~XFS_DIFLAG2_METADATA;
}
