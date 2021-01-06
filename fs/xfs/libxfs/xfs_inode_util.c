// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#include <linux/iversion.h>
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_sb.h"
#include "xfs_mount.h"
#include "xfs_inode.h"
#include "xfs_inode_util.h"
#include "xfs_trans.h"
#include "xfs_ialloc.h"
#include "xfs_health.h"
#include "xfs_bmap.h"
#include "xfs_error.h"
#include "xfs_trace.h"

uint16_t
xfs_flags2diflags(
	struct xfs_inode	*ip,
	unsigned int		xflags)
{
	/* can't set PREALLOC this way, just preserve it */
	uint16_t		di_flags =
		(ip->i_diflags & XFS_DIFLAG_PREALLOC);

	if (xflags & FS_XFLAG_IMMUTABLE)
		di_flags |= XFS_DIFLAG_IMMUTABLE;
	if (xflags & FS_XFLAG_APPEND)
		di_flags |= XFS_DIFLAG_APPEND;
	if (xflags & FS_XFLAG_SYNC)
		di_flags |= XFS_DIFLAG_SYNC;
	if (xflags & FS_XFLAG_NOATIME)
		di_flags |= XFS_DIFLAG_NOATIME;
	if (xflags & FS_XFLAG_NODUMP)
		di_flags |= XFS_DIFLAG_NODUMP;
	if (xflags & FS_XFLAG_NODEFRAG)
		di_flags |= XFS_DIFLAG_NODEFRAG;
	if (xflags & FS_XFLAG_FILESTREAM)
		di_flags |= XFS_DIFLAG_FILESTREAM;
	if (S_ISDIR(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_RTINHERIT)
			di_flags |= XFS_DIFLAG_RTINHERIT;
		if (xflags & FS_XFLAG_NOSYMLINKS)
			di_flags |= XFS_DIFLAG_NOSYMLINKS;
		if (xflags & FS_XFLAG_EXTSZINHERIT)
			di_flags |= XFS_DIFLAG_EXTSZINHERIT;
		if (xflags & FS_XFLAG_PROJINHERIT)
			di_flags |= XFS_DIFLAG_PROJINHERIT;
	} else if (S_ISREG(VFS_I(ip)->i_mode)) {
		if (xflags & FS_XFLAG_REALTIME)
			di_flags |= XFS_DIFLAG_REALTIME;
		if (xflags & FS_XFLAG_EXTSIZE)
			di_flags |= XFS_DIFLAG_EXTSIZE;
	}

	return di_flags;
}

uint64_t
xfs_flags2diflags2(
	struct xfs_inode	*ip,
	unsigned int		xflags)
{
	uint64_t		di_flags2 =
		(ip->i_diflags2 & (XFS_DIFLAG2_REFLINK |
				   XFS_DIFLAG2_BIGTIME));

	if (xflags & FS_XFLAG_DAX)
		di_flags2 |= XFS_DIFLAG2_DAX;
	if (xflags & FS_XFLAG_COWEXTSIZE)
		di_flags2 |= XFS_DIFLAG2_COWEXTSIZE;

	return di_flags2;
}

uint32_t
xfs_ip2xflags(
	struct xfs_inode	*ip)
{
	uint32_t		flags = 0;

	if (ip->i_diflags & XFS_DIFLAG_ANY) {
		if (ip->i_diflags & XFS_DIFLAG_REALTIME)
			flags |= FS_XFLAG_REALTIME;
		if (ip->i_diflags & XFS_DIFLAG_PREALLOC)
			flags |= FS_XFLAG_PREALLOC;
		if (ip->i_diflags & XFS_DIFLAG_IMMUTABLE)
			flags |= FS_XFLAG_IMMUTABLE;
		if (ip->i_diflags & XFS_DIFLAG_APPEND)
			flags |= FS_XFLAG_APPEND;
		if (ip->i_diflags & XFS_DIFLAG_SYNC)
			flags |= FS_XFLAG_SYNC;
		if (ip->i_diflags & XFS_DIFLAG_NOATIME)
			flags |= FS_XFLAG_NOATIME;
		if (ip->i_diflags & XFS_DIFLAG_NODUMP)
			flags |= FS_XFLAG_NODUMP;
		if (ip->i_diflags & XFS_DIFLAG_RTINHERIT)
			flags |= FS_XFLAG_RTINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_PROJINHERIT)
			flags |= FS_XFLAG_PROJINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_NOSYMLINKS)
			flags |= FS_XFLAG_NOSYMLINKS;
		if (ip->i_diflags & XFS_DIFLAG_EXTSIZE)
			flags |= FS_XFLAG_EXTSIZE;
		if (ip->i_diflags & XFS_DIFLAG_EXTSZINHERIT)
			flags |= FS_XFLAG_EXTSZINHERIT;
		if (ip->i_diflags & XFS_DIFLAG_NODEFRAG)
			flags |= FS_XFLAG_NODEFRAG;
		if (ip->i_diflags & XFS_DIFLAG_FILESTREAM)
			flags |= FS_XFLAG_FILESTREAM;
	}

	if (ip->i_diflags2 & XFS_DIFLAG2_ANY) {
		if (ip->i_diflags2 & XFS_DIFLAG2_DAX)
			flags |= FS_XFLAG_DAX;
		if (ip->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE)
			flags |= FS_XFLAG_COWEXTSIZE;
	}

	if (XFS_IFORK_Q(ip))
		flags |= FS_XFLAG_HASATTR;
	return flags;
}

#define XFS_PROJID_DEFAULT	0

prid_t
xfs_get_initial_prid(struct xfs_inode *dp)
{
	if (dp->i_diflags & XFS_DIFLAG_PROJINHERIT)
		return dp->i_projid;

	return XFS_PROJID_DEFAULT;
}

/* Propagate di_flags from a parent inode to a child inode. */
static inline void
xfs_inode_inherit_flags(
	struct xfs_inode	*ip,
	const struct xfs_inode	*pip)
{
	xfs_failaddr_t		failaddr;
	umode_t			mode = VFS_I(ip)->i_mode;

	if (S_ISDIR(mode)) {
		if (pip->i_diflags & XFS_DIFLAG_RTINHERIT)
			ip->i_diflags |= XFS_DIFLAG_RTINHERIT;
		if (pip->i_diflags & XFS_DIFLAG_EXTSZINHERIT) {
			ip->i_diflags |= XFS_DIFLAG_EXTSZINHERIT;
			ip->i_extsize = pip->i_extsize;
		}
		if (pip->i_diflags & XFS_DIFLAG_PROJINHERIT)
			ip->i_diflags |= XFS_DIFLAG_PROJINHERIT;
	} else if (S_ISREG(mode)) {
		if ((pip->i_diflags & XFS_DIFLAG_RTINHERIT) &&
		    xfs_sb_version_hasrealtime(&ip->i_mount->m_sb))
			ip->i_diflags |= XFS_DIFLAG_REALTIME;
		if (pip->i_diflags & XFS_DIFLAG_EXTSZINHERIT) {
			ip->i_diflags |= XFS_DIFLAG_EXTSIZE;
			ip->i_extsize = pip->i_extsize;
		}
	}
	if ((pip->i_diflags & XFS_DIFLAG_NOATIME) &&
	    xfs_inherit_noatime)
		ip->i_diflags |= XFS_DIFLAG_NOATIME;
	if ((pip->i_diflags & XFS_DIFLAG_NODUMP) &&
	    xfs_inherit_nodump)
		ip->i_diflags |= XFS_DIFLAG_NODUMP;
	if ((pip->i_diflags & XFS_DIFLAG_SYNC) &&
	    xfs_inherit_sync)
		ip->i_diflags |= XFS_DIFLAG_SYNC;
	if ((pip->i_diflags & XFS_DIFLAG_NOSYMLINKS) &&
	    xfs_inherit_nosymlinks)
		ip->i_diflags |= XFS_DIFLAG_NOSYMLINKS;
	if ((pip->i_diflags & XFS_DIFLAG_NODEFRAG) &&
	    xfs_inherit_nodefrag)
		ip->i_diflags |= XFS_DIFLAG_NODEFRAG;
	if (pip->i_diflags & XFS_DIFLAG_FILESTREAM)
		ip->i_diflags |= XFS_DIFLAG_FILESTREAM;

	/*
	 * Inode verifiers on older kernels only check that the extent size
	 * hint is an integer multiple of the rt extent size on realtime files.
	 * They did not check the hint alignment on a directory with both
	 * rtinherit and extszinherit flags set.  If the misaligned hint is
	 * propagated from a directory into a new realtime file, new file
	 * allocations will fail due to math errors in the rt allocator and/or
	 * trip the verifiers.  Validate the hint settings in the new file so
	 * that we don't let broken hints propagate.
	 */
	failaddr = xfs_inode_validate_extsize(ip->i_mount, ip->i_extsize,
			VFS_I(ip)->i_mode, ip->i_diflags);
	if (failaddr) {
		ip->i_diflags &= ~(XFS_DIFLAG_EXTSIZE |
				   XFS_DIFLAG_EXTSZINHERIT);
		ip->i_extsize = 0;
	}
}

/* Propagate di_flags2 from a parent inode to a child inode. */
static inline void
xfs_inode_inherit_flags2(
	struct xfs_inode	*ip,
	const struct xfs_inode	*pip)
{
	xfs_failaddr_t		failaddr;

	if (pip->i_diflags2 & XFS_DIFLAG2_COWEXTSIZE) {
		ip->i_diflags2 |= XFS_DIFLAG2_COWEXTSIZE;
		ip->i_cowextsize = pip->i_cowextsize;
	}
	if (pip->i_diflags2 & XFS_DIFLAG2_DAX)
		ip->i_diflags2 |= XFS_DIFLAG2_DAX;

	/* Don't let invalid cowextsize hints propagate. */
	failaddr = xfs_inode_validate_cowextsize(ip->i_mount, ip->i_cowextsize,
			VFS_I(ip)->i_mode, ip->i_diflags, ip->i_diflags2);
	if (failaddr) {
		ip->i_diflags2 &= ~XFS_DIFLAG2_COWEXTSIZE;
		ip->i_cowextsize = 0;
	}
}

/* Initialise an inode's attributes. */
void
xfs_inode_init(
	struct xfs_trans	*tp,
	const struct xfs_ialloc_args *args,
	struct xfs_inode	*ip)
{
	struct xfs_inode	*pip = args->pip;
	struct inode		*dir = pip ? VFS_I(pip) : NULL;
	struct xfs_mount	*mp = tp->t_mountp;
	struct inode		*inode = VFS_I(ip);
	unsigned int		flags;
	int			times = XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG |
					XFS_ICHGTIME_ACCESS;

	set_nlink(inode, args->nlink);
	inode->i_rdev = args->rdev;
	ip->i_projid = args->prid;

	if (dir && !(dir->i_mode & S_ISGID) &&
	    (mp->m_flags & XFS_MOUNT_GRPID)) {
		inode_fsuid_set(inode, args->mnt_userns);
		inode->i_gid = dir->i_gid;
		inode->i_mode = args->mode;
	} else {
		inode_init_owner(args->mnt_userns, inode, dir, args->mode);
	}

	/*
	 * If the group ID of the new file does not match the effective group
	 * ID or one of the supplementary group IDs, the S_ISGID bit is cleared
	 * (and only if the irix_sgid_inherit compatibility variable is set).
	 */
	if (irix_sgid_inherit &&
	    (inode->i_mode & S_ISGID) &&
	    !in_group_p(i_gid_into_mnt(args->mnt_userns, inode)))
		inode->i_mode &= ~S_ISGID;

	/* struct copies */
	if (args->flags & XFS_IALLOC_ARGS_FORCE_UID)
		inode->i_uid = args->uid;
	else
		ASSERT(uid_eq(inode->i_uid, args->uid));
	if (args->flags & XFS_IALLOC_ARGS_FORCE_GID)
		inode->i_gid = args->gid;
	else if (!pip || !XFS_INHERIT_GID(pip))
		ASSERT(gid_eq(inode->i_gid, args->gid));
	if (args->flags & XFS_IALLOC_ARGS_FORCE_MODE)
		inode->i_mode = args->mode;

	ip->i_disk_size = 0;
	ip->i_df.if_nextents = 0;
	ASSERT(ip->i_nblocks == 0);

	ip->i_extsize = 0;
	ip->i_diflags = 0;

	if (xfs_sb_version_has_v3inode(&mp->m_sb)) {
		inode_set_iversion(inode, 1);
		ip->i_cowextsize = 0;
		times |= XFS_ICHGTIME_CREATE;
	}

	xfs_trans_ichgtime(tp, ip, times);

	flags = XFS_ILOG_CORE;
	switch (args->mode & S_IFMT) {
	case S_IFIFO:
	case S_IFCHR:
	case S_IFBLK:
	case S_IFSOCK:
		ip->i_df.if_format = XFS_DINODE_FMT_DEV;
		flags |= XFS_ILOG_DEV;
		break;
	case S_IFREG:
	case S_IFDIR:
		if (pip && (pip->i_diflags & XFS_DIFLAG_ANY))
			xfs_inode_inherit_flags(ip, pip);
		if (pip && (pip->i_diflags2 & XFS_DIFLAG2_ANY))
			xfs_inode_inherit_flags2(ip, pip);
		/* FALLTHROUGH */
	case S_IFLNK:
		ip->i_df.if_format = XFS_DINODE_FMT_EXTENTS;
		ip->i_df.if_bytes = 0;
		ip->i_df.if_u1.if_root = NULL;
		break;
	default:
		ASSERT(0);
	}

	/*
	 * If we need to create attributes immediately after allocating the
	 * inode, initialise an empty attribute fork right now. We use the
	 * default fork offset for attributes here as we don't know exactly what
	 * size or how many attributes we might be adding. We can do this
	 * safely here because we know the data fork is completely empty and
	 * this saves us from needing to run a separate transaction to set the
	 * fork offset in the immediate future.
	 */
	if ((args->flags & XFS_IALLOC_ARGS_INIT_XATTRS) &&
	    xfs_sb_version_hasattr(&mp->m_sb)) {
		ip->i_forkoff = xfs_default_attroffset(ip) >> 3;
		ip->i_afp = xfs_ifork_alloc(XFS_DINODE_FMT_EXTENTS, 0);
	}

	/*
	 * Log the new values stuffed into the inode.
	 */
	xfs_trans_ijoin(tp, ip, XFS_ILOCK_EXCL);
	xfs_trans_log_inode(tp, ip, flags);

	/* now that we have an i_mode we can setup the inode structure */
	xfs_setup_inode(ip);
}

/*
 * Allocates a new inode from disk and return a pointer to the incore copy. This
 * routine will internally commit the current transaction and allocate a new one
 * if we needed to allocate more on-disk free inodes to perform the requested
 * operation.
 *
 * If we are allocating quota inodes, we do not have a parent inode to attach to
 * or associate with (i.e. dp == NULL) because they are not linked into the
 * directory structure - they are attached directly to the superblock - and so
 * have no parent.
 */
int
xfs_dir_ialloc(
	struct xfs_trans	**tpp,
	const struct xfs_ialloc_args *args,
	struct xfs_inode	**ipp)
{
	struct xfs_mount	*mp = (*tpp)->t_mountp;
	struct xfs_inode	*dp = args->pip;
	struct xfs_buf		*agibp;
	xfs_ino_t		parent_ino = dp ? dp->i_ino : 0;
	xfs_ino_t		ino;
	int			error;

	ASSERT((*tpp)->t_flags & XFS_TRANS_PERM_LOG_RES);

	/*
	 * Call the space management code to pick the on-disk inode to be
	 * allocated.
	 */
	error = xfs_dialloc_select_ag(tpp, parent_ino, args->mode, &agibp);
	if (error)
		return error;

	if (!agibp)
		return -ENOSPC;

	/* Allocate an inode from the selected AG */
	error = xfs_dialloc_ag(*tpp, agibp, parent_ino, &ino);
	if (error)
		return error;
	ASSERT(ino != NULLFSINO);

	/*
	 * Protect against obviously corrupt allocation btree records. Later
	 * xfs_iget checks will catch re-allocation of other active in-memory
	 * and on-disk inodes. If we don't catch reallocating the parent inode
	 * here we will deadlock in xfs_iget() so we have to do these checks
	 * first.
	 */
	if ((dp && ino == dp->i_ino) || !xfs_verify_dir_ino(mp, ino)) {
		xfs_alert(mp, "Allocated a known in-use inode 0x%llx!", ino);
		xfs_agno_mark_sick(mp, XFS_INO_TO_AGNO(mp, ino),
				XFS_SICK_AG_INOBT);
		return -EFSCORRUPTED;
	}

	error = xfs_inode_ialloc_iget(*tpp, ino, ipp);
	if (error)
		return error;

	ASSERT(*ipp != NULL);
	xfs_inode_init(*tpp, args, *ipp);
	return 0;
}

/*
 * Point the AGI unlinked bucket at an inode and log the results.  The caller
 * is responsible for validating the old value.
 */
STATIC int
xfs_iunlink_update_bucket(
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	struct xfs_buf		*agibp,
	unsigned int		bucket_index,
	xfs_agino_t		new_agino)
{
	struct xfs_agi		*agi = agibp->b_addr;
	xfs_agino_t		old_value;
	int			offset;

	ASSERT(xfs_verify_agino_or_null(tp->t_mountp, agno, new_agino));

	old_value = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	trace_xfs_iunlink_update_bucket(tp->t_mountp, agno, bucket_index,
			old_value, new_agino);

	/*
	 * We should never find the head of the list already set to the value
	 * passed in because either we're adding or removing ourselves from the
	 * head of the list.
	 */
	if (old_value == new_agino) {
		xfs_buf_mark_corrupt(agibp);
		xfs_agno_mark_sick(tp->t_mountp, agno, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	agi->agi_unlinked[bucket_index] = cpu_to_be32(new_agino);
	offset = offsetof(struct xfs_agi, agi_unlinked) +
			(sizeof(xfs_agino_t) * bucket_index);
	xfs_trans_log_buf(tp, agibp, offset, offset + sizeof(xfs_agino_t) - 1);
	return 0;
}

/* Set an on-disk inode's next_unlinked pointer. */
STATIC void
xfs_iunlink_update_dinode(
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	xfs_agino_t		agino,
	struct xfs_buf		*ibp,
	struct xfs_dinode	*dip,
	struct xfs_imap		*imap,
	xfs_agino_t		next_agino)
{
	struct xfs_mount	*mp = tp->t_mountp;
	int			offset;

	ASSERT(xfs_verify_agino_or_null(mp, agno, next_agino));

	trace_xfs_iunlink_update_dinode(mp, agno, agino,
			be32_to_cpu(dip->di_next_unlinked), next_agino);

	dip->di_next_unlinked = cpu_to_be32(next_agino);
	offset = imap->im_boffset +
			offsetof(struct xfs_dinode, di_next_unlinked);

	/* need to recalc the inode CRC if appropriate */
	xfs_dinode_calc_crc(mp, dip);
	xfs_trans_inode_buf(tp, ibp);
	xfs_trans_log_buf(tp, ibp, offset, offset + sizeof(xfs_agino_t) - 1);
}

/* Set an in-core inode's unlinked pointer and return the old value. */
STATIC int
xfs_iunlink_update_inode(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	xfs_agnumber_t		agno,
	xfs_agino_t		next_agino,
	xfs_agino_t		*old_next_agino)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_dinode	*dip;
	struct xfs_buf		*ibp;
	xfs_agino_t		old_value;
	int			error;

	ASSERT(xfs_verify_agino_or_null(mp, agno, next_agino));

	error = xfs_imap_to_bp(mp, tp, &ip->i_imap, &ibp);
	if (error)
		return error;
	dip = xfs_buf_offset(ibp, ip->i_imap.im_boffset);

	/* Make sure the old pointer isn't garbage. */
	old_value = be32_to_cpu(dip->di_next_unlinked);
	if (!xfs_verify_agino_or_null(mp, agno, old_value)) {
		xfs_inode_verifier_error(ip, -EFSCORRUPTED, __func__, dip,
				sizeof(*dip), __this_address);
		xfs_inode_mark_sick(ip, XFS_SICK_INO_CORE);
		error = -EFSCORRUPTED;
		goto out;
	}

	/*
	 * Since we're updating a linked list, we should never find that the
	 * current pointer is the same as the new value, unless we're
	 * terminating the list.
	 */
	*old_next_agino = old_value;
	if (old_value == next_agino) {
		if (next_agino != NULLAGINO) {
			xfs_inode_verifier_error(ip, -EFSCORRUPTED, __func__,
					dip, sizeof(*dip), __this_address);
			xfs_inode_mark_sick(ip, XFS_SICK_INO_CORE);
			error = -EFSCORRUPTED;
		}
		goto out;
	}

	/* Ok, update the new pointer. */
	xfs_iunlink_update_dinode(tp, agno, XFS_INO_TO_AGINO(mp, ip->i_ino),
			ibp, dip, &ip->i_imap, next_agino);
	return 0;
out:
	xfs_trans_brelse(tp, ibp);
	return error;
}

/*
 * This is called when the inode's link count has gone to 0 or we are creating
 * a tmpfile via O_TMPFILE.  The inode @ip must have nlink == 0.
 *
 * We place the on-disk inode on a list in the AGI.  It will be pulled from this
 * list when the inode is freed.
 */
int
xfs_iunlink(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_agi		*agi;
	struct xfs_buf		*agibp;
	xfs_agino_t		next_agino;
	xfs_agnumber_t		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	short			bucket_index = agino % XFS_AGI_UNLINKED_BUCKETS;
	int			error;

	ASSERT(VFS_I(ip)->i_nlink == 0);
	ASSERT(VFS_I(ip)->i_mode != 0);
	trace_xfs_iunlink(ip);

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	error = xfs_read_agi(mp, tp, agno, &agibp);
	if (error)
		return error;
	agi = agibp->b_addr;

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the pointer isn't garbage and that this inode
	 * isn't already on the list.
	 */
	next_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (next_agino == agino ||
	    !xfs_verify_agino_or_null(mp, agno, next_agino)) {
		xfs_buf_mark_corrupt(agibp);
		xfs_agno_mark_sick(mp, agno, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	if (next_agino != NULLAGINO) {
		xfs_agino_t		old_agino;

		/*
		 * There is already another inode in the bucket, so point this
		 * inode to the current head of the list.
		 */
		error = xfs_iunlink_update_inode(tp, ip, agno, next_agino,
				&old_agino);
		if (error)
			return error;
		ASSERT(old_agino == NULLAGINO);

		/*
		 * agino has been unlinked, add a backref from the next inode
		 * back to agino.
		 */
		error = xfs_iunlink_add_backref(agibp->b_pag, agino, next_agino);
		if (error)
			return error;
	}

	/* Point the head of the list to point to this inode. */
	return xfs_iunlink_update_bucket(tp, agno, agibp, bucket_index, agino);
}

/* Return the imap, dinode pointer, and buffer for an inode. */
STATIC int
xfs_iunlink_map_ino(
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	xfs_agino_t		agino,
	struct xfs_imap		*imap,
	struct xfs_dinode	**dipp,
	struct xfs_buf		**bpp)
{
	struct xfs_mount	*mp = tp->t_mountp;
	int			error;

	imap->im_blkno = 0;
	error = xfs_imap(mp, tp, XFS_AGINO_TO_INO(mp, agno, agino), imap, 0);
	if (error) {
		xfs_warn(mp, "%s: xfs_imap returned error %d.",
				__func__, error);
		return error;
	}

	error = xfs_imap_to_bp(mp, tp, imap, bpp);
	if (error) {
		xfs_warn(mp, "%s: xfs_imap_to_bp returned error %d.",
				__func__, error);
		return error;
	}

	*dipp = xfs_buf_offset(*bpp, imap->im_boffset);
	return 0;
}

/*
 * Walk the unlinked chain from @head_agino until we find the inode that
 * points to @target_agino.  Return the inode number, map, dinode pointer,
 * and inode cluster buffer of that inode as @agino, @imap, @dipp, and @bpp.
 *
 * @tp, @pag, @head_agino, and @target_agino are input parameters.
 * @agino, @imap, @dipp, and @bpp are all output parameters.
 *
 * Do not call this function if @target_agino is the head of the list.
 */
STATIC int
xfs_iunlink_map_prev(
	struct xfs_trans	*tp,
	xfs_agnumber_t		agno,
	xfs_agino_t		head_agino,
	xfs_agino_t		target_agino,
	xfs_agino_t		*agino,
	struct xfs_imap		*imap,
	struct xfs_dinode	**dipp,
	struct xfs_buf		**bpp,
	struct xfs_perag	*pag)
{
	struct xfs_mount	*mp = tp->t_mountp;
	xfs_agino_t		next_agino;
	int			error;

	ASSERT(head_agino != target_agino);
	*bpp = NULL;

	/* See if our backref cache can find it faster. */
	*agino = xfs_iunlink_lookup_backref(pag, target_agino);
	if (*agino != NULLAGINO) {
		error = xfs_iunlink_map_ino(tp, agno, *agino, imap, dipp, bpp);
		if (error)
			return error;

		if (be32_to_cpu((*dipp)->di_next_unlinked) == target_agino)
			return 0;

		/*
		 * If we get here the cache contents were corrupt, so drop the
		 * buffer and fall back to walking the bucket list.
		 */
		xfs_trans_brelse(tp, *bpp);
		*bpp = NULL;
		WARN_ON_ONCE(1);
	}

	trace_xfs_iunlink_map_prev_fallback(mp, agno);

	/* Otherwise, walk the entire bucket until we find it. */
	next_agino = head_agino;
	while (next_agino != target_agino) {
		xfs_agino_t	unlinked_agino;

		if (*bpp)
			xfs_trans_brelse(tp, *bpp);

		*agino = next_agino;
		error = xfs_iunlink_map_ino(tp, agno, next_agino, imap, dipp,
				bpp);
		if (error)
			return error;

		unlinked_agino = be32_to_cpu((*dipp)->di_next_unlinked);
		/*
		 * Make sure this pointer is valid and isn't an obvious
		 * infinite loop.
		 */
		if (!xfs_verify_agino(mp, agno, unlinked_agino) ||
		    next_agino == unlinked_agino) {
			XFS_CORRUPTION_ERROR(__func__,
					XFS_ERRLEVEL_LOW, mp,
					*dipp, sizeof(**dipp));
			xfs_ag_mark_sick(pag, XFS_SICK_AG_AGI);
			error = -EFSCORRUPTED;
			return error;
		}
		next_agino = unlinked_agino;
	}

	return 0;
}

/*
 * Pull the on-disk inode from the AGI unlinked list.
 */
int
xfs_iunlink_remove(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip)
{
	struct xfs_mount	*mp = tp->t_mountp;
	struct xfs_agi		*agi;
	struct xfs_buf		*agibp;
	struct xfs_buf		*last_ibp;
	struct xfs_dinode	*last_dip = NULL;
	xfs_agnumber_t		agno = XFS_INO_TO_AGNO(mp, ip->i_ino);
	xfs_agino_t		agino = XFS_INO_TO_AGINO(mp, ip->i_ino);
	xfs_agino_t		next_agino;
	xfs_agino_t		head_agino;
	short			bucket_index = agino % XFS_AGI_UNLINKED_BUCKETS;
	int			error;

	trace_xfs_iunlink_remove(ip);

	/* Get the agi buffer first.  It ensures lock ordering on the list. */
	error = xfs_read_agi(mp, tp, agno, &agibp);
	if (error)
		return error;
	agi = agibp->b_addr;

	/*
	 * Get the index into the agi hash table for the list this inode will
	 * go on.  Make sure the head pointer isn't garbage.
	 */
	head_agino = be32_to_cpu(agi->agi_unlinked[bucket_index]);
	if (!xfs_verify_agino(mp, agno, head_agino)) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp,
				agi, sizeof(*agi));
		xfs_agno_mark_sick(mp, agno, XFS_SICK_AG_AGI);
		return -EFSCORRUPTED;
	}

	/*
	 * Set our inode's next_unlinked pointer to NULL and then return
	 * the old pointer value so that we can update whatever was previous
	 * to us in the list to point to whatever was next in the list.
	 */
	error = xfs_iunlink_update_inode(tp, ip, agno, NULLAGINO, &next_agino);
	if (error)
		return error;

	/*
	 * If there was a backref pointing from the next inode back to this
	 * one, remove it because we've removed this inode from the list.
	 *
	 * Later, if this inode was in the middle of the list we'll update
	 * this inode's backref to point from the next inode.
	 */
	if (next_agino != NULLAGINO) {
		error = xfs_iunlink_change_backref(agibp->b_pag, next_agino,
				NULLAGINO);
		if (error)
			return error;
	}

	if (head_agino != agino) {
		struct xfs_imap	imap;
		xfs_agino_t	prev_agino;

		/* We need to search the list for the inode being freed. */
		error = xfs_iunlink_map_prev(tp, agno, head_agino, agino,
				&prev_agino, &imap, &last_dip, &last_ibp,
				agibp->b_pag);
		if (error)
			return error;

		/* Point the previous inode on the list to the next inode. */
		xfs_iunlink_update_dinode(tp, agno, prev_agino, last_ibp,
				last_dip, &imap, next_agino);

		/*
		 * Now we deal with the backref for this inode.  If this inode
		 * pointed at a real inode, change the backref that pointed to
		 * us to point to our old next.  If this inode was the end of
		 * the list, delete the backref that pointed to us.  Note that
		 * change_backref takes care of deleting the backref if
		 * next_agino is NULLAGINO.
		 */
		return xfs_iunlink_change_backref(agibp->b_pag, agino,
				next_agino);
	}

	/* Point the head of the list to the next unlinked inode. */
	return xfs_iunlink_update_bucket(tp, agno, agibp, bucket_index,
			next_agino);
}
