// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 *
 * The xfs_swap_extent_* functions are:
 * Copyright (c) 2000-2006 Silicon Graphics, Inc.
 * Copyright (c) 2012 Red Hat, Inc.
 * All Rights Reserved.
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_quota.h"
#include "xfs_bmap_util.h"
#include "xfs_bmap_btree.h"
#include "xfs_reflink.h"
#include "xfs_trace.h"
#include "xfs_swapext.h"
#include "xfs_xchgrange.h"
#include "xfs_sb.h"
#include "xfs_icache.h"
#include "xfs_log.h"
#include "xfs_rtalloc.h"

/* Lock (and optionally join) two inodes for a file range exchange. */
void
xfs_xchg_range_ilock(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	if (ip1 != ip2)
		xfs_lock_two_inodes(ip1, XFS_ILOCK_EXCL,
				    ip2, XFS_ILOCK_EXCL);
	else
		xfs_ilock(ip1, XFS_ILOCK_EXCL);
	if (tp) {
		xfs_trans_ijoin(tp, ip1, 0);
		if (ip2 != ip1)
			xfs_trans_ijoin(tp, ip2, 0);
	}

}

/* Unlock two inodes after a file range exchange operation. */
void
xfs_xchg_range_iunlock(
	struct xfs_inode	*ip1,
	struct xfs_inode	*ip2)
{
	if (ip2 != ip1)
		xfs_iunlock(ip2, XFS_ILOCK_EXCL);
	xfs_iunlock(ip1, XFS_ILOCK_EXCL);
}

/*
 * Estimate the resource requirements to exchange file contents between the two
 * files.  The caller is required to hold the IOLOCK and the MMAPLOCK and to
 * have flushed both inodes' pagecache and active direct-ios.
 */
int
xfs_xchg_range_estimate(
	const struct xfs_swapext_req	*req,
	struct xfs_swapext_res		*res)
{
	int				error;

	xfs_xchg_range_ilock(NULL, req->ip1, req->ip2);
	error = xfs_swapext_estimate(req, res);
	xfs_xchg_range_iunlock(req->ip1, req->ip2);
	return error;
}

/*
 * We need to check that the format of the data fork in the temporary inode is
 * valid for the target inode before doing the swap. This is not a problem with
 * attr1 because of the fixed fork offset, but attr2 has a dynamically sized
 * data fork depending on the space the attribute fork is taking so we can get
 * invalid formats on the target inode.
 *
 * E.g. target has space for 7 extents in extent format, temp inode only has
 * space for 6.  If we defragment down to 7 extents, then the tmp format is a
 * btree, but when swapped it needs to be in extent format. Hence we can't just
 * blindly swap data forks on attr2 filesystems.
 *
 * Note that we check the swap in both directions so that we don't end up with
 * a corrupt temporary inode, either.
 *
 * Note that fixing the way xfs_fsr sets up the attribute fork in the source
 * inode will prevent this situation from occurring, so all we do here is
 * reject and log the attempt. basically we are putting the responsibility on
 * userspace to get this right.
 */
STATIC int
xfs_swap_extents_check_format(
	struct xfs_inode	*ip,	/* target inode */
	struct xfs_inode	*tip)	/* tmp inode */
{
	struct xfs_ifork	*ifp = &ip->i_df;
	struct xfs_ifork	*tifp = &tip->i_df;

	/* User/group/project quota ids must match if quotas are enforced. */
	if (XFS_IS_QUOTA_ON(ip->i_mount) &&
	    (!uid_eq(VFS_I(ip)->i_uid, VFS_I(tip)->i_uid) ||
	     !gid_eq(VFS_I(ip)->i_gid, VFS_I(tip)->i_gid) ||
	     ip->i_projid != tip->i_projid))
		return -EINVAL;

	/* Should never get a local format */
	if (ifp->if_format == XFS_DINODE_FMT_LOCAL ||
	    tifp->if_format == XFS_DINODE_FMT_LOCAL)
		return -EINVAL;

	/*
	 * if the target inode has less extents that then temporary inode then
	 * why did userspace call us?
	 */
	if (ifp->if_nextents < tifp->if_nextents)
		return -EINVAL;

	/*
	 * If we have to use the (expensive) rmap swap method, we can
	 * handle any number of extents and any format.
	 */
	if (xfs_sb_version_hasrmapbt(&ip->i_mount->m_sb))
		return 0;

	/*
	 * if the target inode is in extent form and the temp inode is in btree
	 * form then we will end up with the target inode in the wrong format
	 * as we already know there are less extents in the temp inode.
	 */
	if (ifp->if_format == XFS_DINODE_FMT_EXTENTS &&
	    tifp->if_format == XFS_DINODE_FMT_BTREE)
		return -EINVAL;

	/* Check temp in extent form to max in target */
	if (tifp->if_format == XFS_DINODE_FMT_EXTENTS &&
	    tifp->if_nextents > XFS_IFORK_MAXEXT(ip, XFS_DATA_FORK))
		return -EINVAL;

	/* Check target in extent form to max in temp */
	if (ifp->if_format == XFS_DINODE_FMT_EXTENTS &&
	    ifp->if_nextents > XFS_IFORK_MAXEXT(tip, XFS_DATA_FORK))
		return -EINVAL;

	/*
	 * If we are in a btree format, check that the temp root block will fit
	 * in the target and that it has enough extents to be in btree format
	 * in the target.
	 *
	 * Note that we have to be careful to allow btree->extent conversions
	 * (a common defrag case) which will occur when the temp inode is in
	 * extent format...
	 */
	if (tifp->if_format == XFS_DINODE_FMT_BTREE) {
		if (XFS_IFORK_Q(ip) &&
		    XFS_BMAP_BMDR_SPACE(tifp->if_broot) > XFS_IFORK_BOFF(ip))
			return -EINVAL;
		if (tifp->if_nextents <= XFS_IFORK_MAXEXT(ip, XFS_DATA_FORK))
			return -EINVAL;
	}

	/* Reciprocal target->temp btree format checks */
	if (ifp->if_format == XFS_DINODE_FMT_BTREE) {
		if (XFS_IFORK_Q(tip) &&
		    XFS_BMAP_BMDR_SPACE(ip->i_df.if_broot) > XFS_IFORK_BOFF(tip))
			return -EINVAL;
		if (ifp->if_nextents <= XFS_IFORK_MAXEXT(tip, XFS_DATA_FORK))
			return -EINVAL;
	}

	return 0;
}

/*
 * Fix up the owners of the bmbt blocks to refer to the current inode. The
 * change owner scan attempts to order all modified buffers in the current
 * transaction. In the event of ordered buffer failure, the offending buffer is
 * physically logged as a fallback and the scan returns -EAGAIN. We must roll
 * the transaction in this case to replenish the fallback log reservation and
 * restart the scan. This process repeats until the scan completes.
 */
static int
xfs_swap_change_owner(
	struct xfs_trans	**tpp,
	struct xfs_inode	*ip,
	struct xfs_inode	*tmpip)
{
	int			error;
	struct xfs_trans	*tp = *tpp;

	do {
		error = xfs_bmbt_change_owner(tp, ip, XFS_DATA_FORK, ip->i_ino,
					      NULL);
		/* success or fatal error */
		if (error != -EAGAIN)
			break;

		error = xfs_trans_roll(tpp);
		if (error)
			break;
		tp = *tpp;

		/*
		 * Redirty both inodes so they can relog and keep the log tail
		 * moving forward.
		 */
		xfs_trans_ijoin(tp, ip, 0);
		xfs_trans_ijoin(tp, tmpip, 0);
		xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
		xfs_trans_log_inode(tp, tmpip, XFS_ILOG_CORE);
	} while (true);

	return error;
}

/* Swap the extents of two files by swapping data forks. */
STATIC int
xfs_swap_extent_forks(
	struct xfs_trans	**tpp,
	struct xfs_swapext_req	*req)
{
	struct xfs_inode	*ip = req->ip1;
	struct xfs_inode	*tip = req->ip2;
	xfs_filblks_t		aforkblks = 0;
	xfs_filblks_t		taforkblks = 0;
	xfs_extnum_t		junk;
	uint64_t		tmp;
	unsigned int		reflink_state;
	int			src_log_flags = XFS_ILOG_CORE;
	int			target_log_flags = XFS_ILOG_CORE;
	int			error;

	reflink_state = xfs_swapext_reflink_prep(req);

	/*
	 * Count the number of extended attribute blocks
	 */
	if (XFS_IFORK_Q(ip) && ip->i_afp->if_nextents > 0 &&
	    ip->i_afp->if_format != XFS_DINODE_FMT_LOCAL) {
		error = xfs_bmap_count_blocks(*tpp, ip, XFS_ATTR_FORK, &junk,
				&aforkblks);
		if (error)
			return error;
	}
	if (XFS_IFORK_Q(tip) && tip->i_afp->if_nextents > 0 &&
	    tip->i_afp->if_format != XFS_DINODE_FMT_LOCAL) {
		error = xfs_bmap_count_blocks(*tpp, tip, XFS_ATTR_FORK, &junk,
				&taforkblks);
		if (error)
			return error;
	}

	/*
	 * Btree format (v3) inodes have the inode number stamped in the bmbt
	 * block headers. We can't start changing the bmbt blocks until the
	 * inode owner change is logged so recovery does the right thing in the
	 * event of a crash. Set the owner change log flags now and leave the
	 * bmbt scan as the last step.
	 */
	if (xfs_sb_version_has_v3inode(&ip->i_mount->m_sb)) {
		if (ip->i_df.if_format == XFS_DINODE_FMT_BTREE)
			target_log_flags |= XFS_ILOG_DOWNER;
		if (tip->i_df.if_format == XFS_DINODE_FMT_BTREE)
			src_log_flags |= XFS_ILOG_DOWNER;
	}

	/*
	 * Swap the data forks of the inodes
	 */
	swap(ip->i_df, tip->i_df);

	/*
	 * Fix the on-disk inode values
	 */
	tmp = (uint64_t)ip->i_nblocks;
	ip->i_nblocks = tip->i_nblocks - taforkblks + aforkblks;
	tip->i_nblocks = tmp + taforkblks - aforkblks;

	/*
	 * The extents in the source inode could still contain speculative
	 * preallocation beyond EOF (e.g. the file is open but not modified
	 * while defrag is in progress). In that case, we need to copy over the
	 * number of delalloc blocks the data fork in the source inode is
	 * tracking beyond EOF so that when the fork is truncated away when the
	 * temporary inode is unlinked we don't underrun the i_delayed_blks
	 * counter on that inode.
	 */
	ASSERT(tip->i_delayed_blks == 0);
	tip->i_delayed_blks = ip->i_delayed_blks;
	ip->i_delayed_blks = 0;

	switch (ip->i_df.if_format) {
	case XFS_DINODE_FMT_EXTENTS:
		src_log_flags |= XFS_ILOG_DEXT;
		break;
	case XFS_DINODE_FMT_BTREE:
		ASSERT(!xfs_sb_version_has_v3inode(&ip->i_mount->m_sb) ||
		       (src_log_flags & XFS_ILOG_DOWNER));
		src_log_flags |= XFS_ILOG_DBROOT;
		break;
	}

	switch (tip->i_df.if_format) {
	case XFS_DINODE_FMT_EXTENTS:
		target_log_flags |= XFS_ILOG_DEXT;
		break;
	case XFS_DINODE_FMT_BTREE:
		target_log_flags |= XFS_ILOG_DBROOT;
		ASSERT(!xfs_sb_version_has_v3inode(&ip->i_mount->m_sb) ||
		       (target_log_flags & XFS_ILOG_DOWNER));
		break;
	}

	xfs_swapext_reflink_finish(*tpp, req, reflink_state);

	xfs_trans_log_inode(*tpp, ip,  src_log_flags);
	xfs_trans_log_inode(*tpp, tip, target_log_flags);

	/*
	 * The extent forks have been swapped, but crc=1,rmapbt=0 filesystems
	 * have inode number owner values in the bmbt blocks that still refer to
	 * the old inode. Scan each bmbt to fix up the owner values with the
	 * inode number of the current inode.
	 */
	if (src_log_flags & XFS_ILOG_DOWNER) {
		error = xfs_swap_change_owner(tpp, ip, tip);
		if (error)
			return error;
	}
	if (target_log_flags & XFS_ILOG_DOWNER) {
		error = xfs_swap_change_owner(tpp, tip, ip);
		if (error)
			return error;
	}

	return 0;
}

/* Prepare two files to have their data exchanged. */
int
xfs_xchg_range_prep(
	struct file		*file1,
	struct file		*file2,
	struct file_xchg_range	*fxr)
{
	struct xfs_inode	*ip1 = XFS_I(file_inode(file1));
	struct xfs_inode	*ip2 = XFS_I(file_inode(file2));
	int			error;

	trace_xfs_xchg_range_prep(ip1, fxr, ip2, 0);

	/* Verify both files are either real-time or non-realtime */
	if (XFS_IS_REALTIME_INODE(ip1) != XFS_IS_REALTIME_INODE(ip2))
		return -EINVAL;

	/*
	 * The alignment checks in the VFS helpers cannot deal with allocation
	 * units that are not powers of 2.  This can happen with the realtime
	 * volume if the extent size is set.  Note that alignment checks are
	 * skipped if FULL_FILES is set.
	 */
	if (!(fxr->flags & FILE_XCHG_RANGE_FULL_FILES) &&
	    !is_power_of_2(xfs_inode_alloc_unitsize(ip2)))
		return -EOPNOTSUPP;

	error = generic_xchg_file_range_prep(file1, file2, fxr,
			xfs_inode_alloc_unitsize(ip2));
	if (error || fxr->length == 0)
		return error;

	/* Attach dquots to both inodes before changing block maps. */
	error = xfs_qm_dqattach(ip2);
	if (error)
		return error;
	error = xfs_qm_dqattach(ip1);
	if (error)
		return error;

	trace_xfs_xchg_range_flush(ip1, fxr, ip2, 0);

	/* Flush the relevant ranges of both files. */
	error = xfs_flush_unmap_range(ip2, fxr->file2_offset, fxr->length);
	if (error)
		return error;
	error = xfs_flush_unmap_range(ip1, fxr->file1_offset, fxr->length);
	if (error)
		return error;

	/*
	 * Cancel CoW fork preallocations for the ranges of both files.  The
	 * prep function should have flushed all the dirty data, so the only
	 * extents remaining should be speculative.
	 */
	if (xfs_inode_has_cow_data(ip1)) {
		error = xfs_reflink_cancel_cow_range(ip1, fxr->file1_offset,
				fxr->length, true);
		if (error)
			return error;
	}

	if (xfs_inode_has_cow_data(ip2)) {
		error = xfs_reflink_cancel_cow_range(ip2, fxr->file2_offset,
				fxr->length, true);
		if (error)
			return error;
	}

	/* Convert unwritten sub-extent mappings if required. */
	if (xfs_swapext_need_rt_conversion(ip2)) {
		error = xfs_rtfile_convert_unwritten(ip2, fxr->file2_offset,
				fxr->length);
		if (error)
			return error;

		error = xfs_rtfile_convert_unwritten(ip1, fxr->file1_offset,
				fxr->length);
		if (error)
			return error;
	}

	return 0;
}

#define QRETRY_IP1	(0x1)
#define QRETRY_IP2	(0x2)

/*
 * Obtain a quota reservation to make sure we don't hit EDQUOT.  We can skip
 * this if quota enforcement is disabled or if both inodes' dquots are the
 * same.  The qretry structure must be initialized to zeroes before the first
 * call to this function.
 */
STATIC int
xfs_xchg_range_reserve_quota(
	struct xfs_trans		*tp,
	const struct xfs_swapext_req	*req,
	const struct xfs_swapext_res	*res,
	unsigned int			*qretry)
{
	int64_t				ddelta, rdelta;
	int				ip1_error = 0;
	int				error;

	/*
	 * Don't bother with a quota reservation if we're not enforcing them
	 * or the two inodes have the same dquots.
	 */
	if (!XFS_IS_QUOTA_ON(tp->t_mountp) || req->ip1 == req->ip2 ||
	    (req->ip1->i_udquot == req->ip2->i_udquot &&
	     req->ip1->i_gdquot == req->ip2->i_gdquot &&
	     req->ip1->i_pdquot == req->ip2->i_pdquot))
		return 0;

	*qretry = 0;

	/*
	 * For each file, compute the net gain in the number of regular blocks
	 * that will be mapped into that file and reserve that much quota.  The
	 * quota counts must be able to absorb at least that much space.
	 */
	ddelta = res->ip2_bcount - res->ip1_bcount;
	rdelta = res->ip2_rtbcount - res->ip1_rtbcount;
	if (ddelta > 0 || rdelta > 0) {
		error = xfs_trans_reserve_quota_nblks(tp, req->ip1,
				ddelta > 0 ? ddelta : 0,
				rdelta > 0 ? rdelta : 0,
				false);
		if (error == -EDQUOT || error == -ENOSPC) {
			/*
			 * Save this error and see what happens if we try to
			 * reserve quota for ip2.  Then report both.
			 */
			*qretry |= QRETRY_IP1;
			ip1_error = error;
			error = 0;
		}
		if (error)
			return error;
	}
	if (ddelta < 0 || rdelta < 0) {
		error = xfs_trans_reserve_quota_nblks(tp, req->ip2,
				ddelta < 0 ? -ddelta : 0,
				rdelta < 0 ? -rdelta : 0,
				false);
		if (error == -EDQUOT || error == -ENOSPC)
			*qretry |= QRETRY_IP2;
		if (error)
			return error;
	}
	if (ip1_error)
		return ip1_error;

	/*
	 * For each file, forcibly reserve the gross gain in mapped blocks so
	 * that we don't trip over any quota block reservation assertions.
	 * We must reserve the gross gain because the quota code subtracts from
	 * bcount the number of blocks that we unmap; it does not add that
	 * quantity back to the quota block reservation.
	 */
	error = xfs_trans_reserve_quota_nblks(tp, req->ip1, res->ip1_bcount,
			res->ip1_rtbcount, true);
	if (error)
		return error;

	return xfs_trans_reserve_quota_nblks(tp, req->ip2, res->ip2_bcount,
			res->ip2_rtbcount, true);
}

/*
 * Get permission to use log-assisted atomic exchange of file extents.
 *
 * Callers must not be running any transactions or hold any inode locks, and
 * they must release the permission by calling xfs_xchg_range_rele_log_assist
 * when they're done.
 */
int
xfs_xchg_range_grab_log_assist(
	struct xfs_mount	*mp,
	bool			force,
	bool			*enabled)
{
	int			error = 0;

	/*
	 * Protect ourselves from an idle log clearing the atomic swapext
	 * log incompat feature bit.
	 */
	xlog_use_incompat_feat(mp->m_log);
	*enabled = true;

	/*
	 * If log-assisted swapping is already enabled, the caller can use the
	 * log assisted swap functions with the log-incompat reference we got.
	 */
	if (xfs_sb_version_hasatomicswap(&mp->m_sb))
		return 0;

	/*
	 * If the caller doesn't /require/ log-assisted swapping, drop the
	 * log-incompat feature protection and exit.  The caller cannot use
	 * log assisted swapping.
	 */
	if (!force)
		goto err;

	/*
	 * Caller requires log-assisted swapping but the fs feature set isn't
	 * rich enough to support it.  Bail out.
	 */
	if (!xfs_sb_version_canatomicswap(&mp->m_sb)) {
		error = -EOPNOTSUPP;
		goto err;
	}

	/* Enable log-assisted extent swapping. */
	xfs_warn(mp,
 "EXPERIMENTAL atomic file range swap feature added. Use at your own risk!");
	error = xfs_add_incompat_log_feature(mp,
			XFS_SB_FEAT_INCOMPAT_LOG_ATOMIC_SWAP);
	if (error)
		goto err;
	return 0;
err:
	xlog_drop_incompat_feat(mp->m_log);
	*enabled = false;
	return error;
}

/* Release permission to use log-assisted extent swapping. */
void
xfs_xchg_range_rele_log_assist(
	struct xfs_mount	*mp)
{
	xlog_drop_incompat_feat(mp->m_log);
}

/* Decide if we can use the old data fork exchange code. */
static inline bool
xfs_xchg_use_forkswap(
	const struct file_xchg_range	*fxr,
	struct xfs_inode		*ip1,
	struct xfs_inode		*ip2)
{
	return	(fxr->flags & FILE_XCHG_RANGE_NONATOMIC) &&
		(fxr->flags & FILE_XCHG_RANGE_FULL_FILES) &&
		!(fxr->flags & FILE_XCHG_RANGE_TO_EOF) &&
		fxr->file1_offset == 0 && fxr->file2_offset == 0 &&
		fxr->length == ip1->i_disk_size &&
		fxr->length == ip2->i_disk_size;
}

enum xchg_strategy {
	SWAPEXT		= 1,	/* xfs_swapext() */
	FORKSWAP	= 2,	/* exchange forks */
};

/* Exchange the contents of two files. */
int
xfs_xchg_range(
	struct xfs_inode		*ip1,
	struct xfs_inode		*ip2,
	const struct file_xchg_range	*fxr,
	unsigned int			xchg_flags)
{
	struct xfs_mount		*mp = ip1->i_mount;
	struct xfs_swapext_req		req = {
		.ip1			= ip1,
		.ip2			= ip2,
		.whichfork		= XFS_DATA_FORK,
		.startoff1		= XFS_B_TO_FSBT(mp, fxr->file1_offset),
		.startoff2		= XFS_B_TO_FSBT(mp, fxr->file2_offset),
		.blockcount		= XFS_B_TO_FSB(mp, fxr->length),
	};
	struct xfs_swapext_res		res;
	struct xfs_trans		*tp;
	unsigned int			qretry;
	unsigned int			flags = 0;
	bool				retried = false;
	enum xchg_strategy		strategy;
	int				error;

	trace_xfs_xchg_range(ip1, fxr, ip2, xchg_flags);

	if (fxr->flags & FILE_XCHG_RANGE_TO_EOF)
		req.flags |= XFS_SWAPEXT_SET_SIZES;
	if (fxr->flags & FILE_XCHG_RANGE_SKIP_FILE1_HOLES)
		req.flags |= XFS_SWAPEXT_SKIP_FILE1_HOLES;

	/*
	 * Round the request length up to the nearest fundamental unit of
	 * allocation.  The prep function already checked that the request
	 * offsets and length in @fxr are safe to round up.
	 */
	if (XFS_IS_REALTIME_INODE(ip2))
		req.blockcount = roundup_64(req.blockcount,
					    mp->m_sb.sb_rextsize);

	error = xfs_xchg_range_estimate(&req, &res);
	if (error)
		return error;

	/*
	 * We haven't decided which exchange strategy we want to use yet, but
	 * here we must choose if we want freed blocks during the swap to be
	 * added to the transaction block reservation (RES_FDBLKS) or freed
	 * into the global fdblocks.  The legacy fork swap mechanism doesn't
	 * free any blocks, so it doesn't require it.  It is also the only
	 * option that works for older filesystems.
	 *
	 * The bmap log intent items that were added with rmap and reflink can
	 * change the bmbt shape, so the intent-based swap strategies require
	 * us to set RES_FDBLKS.
	 */
	if (xfs_sb_version_haslazysbcount(&mp->m_sb))
		flags |= XFS_TRANS_RES_FDBLKS;

retry:
	/* Allocate the transaction, lock the inodes, and join them. */
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_write, res.resblks, 0,
			flags, &tp);
	if (error)
		return error;

	xfs_xchg_range_ilock(tp, ip1, ip2);

	trace_xfs_swap_extent_before(ip2, 0);
	trace_xfs_swap_extent_before(ip1, 1);

	if (fxr->flags & FILE_XCHG_RANGE_FILE2_FRESH)
		trace_xfs_xchg_range_freshness(ip2, fxr);

	/*
	 * Now that we've excluded all other inode metadata changes by taking
	 * the ILOCK, repeat the freshness check.
	 */
	error = generic_xchg_file_range_check_fresh(VFS_I(ip2), fxr);
	if (error)
		goto out_trans_cancel;

	error = xfs_swapext_check_extents(mp, &req);
	if (error)
		goto out_trans_cancel;

	/*
	 * Reserve ourselves some quota if any of them are in enforcing mode.
	 * In theory we only need enough to satisfy the change in the number
	 * of blocks between the two ranges being remapped.
	 */
	error = xfs_xchg_range_reserve_quota(tp, &req, &res, &qretry);
	if ((error == -EDQUOT || error == -ENOSPC) && !retried) {
		xfs_trans_cancel(tp);
		xfs_xchg_range_iunlock(ip1, ip2);
		if (qretry & QRETRY_IP1)
			xfs_blockgc_free_quota(ip1, 0);
		if (qretry & QRETRY_IP2)
			xfs_blockgc_free_quota(ip2, 0);
		retried = true;
		goto retry;
	}
	if (error)
		goto out_trans_cancel;

	if (xfs_sb_version_hasatomicswap(&mp->m_sb) ||
	    xfs_sb_version_canatomicswap(&mp->m_sb)) {
		/*
		 * xfs_swapext() uses deferred bmap log intent items to swap
		 * extents between file forks.  If the atomic log swap feature
		 * is enabled, it will also use swapext log intent items to
		 * restart the operation in case of failure.
		 *
		 * This means that we can use it if we previously obtained
		 * permission from the log to use log-assisted atomic extent
		 * swapping; or if the fs supports rmap or reflink and the
		 * user said NONATOMIC.
		 */
		strategy = SWAPEXT;
	} else if (xfs_xchg_use_forkswap(fxr, ip1, ip2)) {
		/*
		 * Exchange the file contents by using the old bmap fork
		 * exchange code, if we're a defrag tool doing a full file
		 * swap.
		 */
		strategy = FORKSWAP;

		error = xfs_swap_extents_check_format(ip2, ip1);
		if (error) {
			xfs_notice(mp,
		"%s: inode 0x%llx format is incompatible for exchanging.",
					__func__, ip2->i_ino);
			goto out_trans_cancel;
		}
	} else {
		/* We cannot exchange the file contents. */
		error = -EOPNOTSUPP;
		goto out_trans_cancel;
	}

	/* If we got this far on a dry run, all parameters are ok. */
	if (fxr->flags & FILE_XCHG_RANGE_DRY_RUN)
		goto out_trans_cancel;

	/* Update the mtime and ctime of both files. */
	if (xchg_flags & XFS_XCHG_RANGE_UPD_CMTIME1)
		xfs_trans_ichgtime(tp, ip1,
				XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);
	if (xchg_flags & XFS_XCHG_RANGE_UPD_CMTIME2)
		xfs_trans_ichgtime(tp, ip2,
				XFS_ICHGTIME_MOD | XFS_ICHGTIME_CHG);

	if (strategy == SWAPEXT)
		error = xfs_swapext(&tp, &req);
	else
		error = xfs_swap_extent_forks(&tp, &req);
	if (error)
		goto out_trans_cancel;

	/*
	 * If the caller wanted us to exchange the contents of two complete
	 * files of unequal length, exchange the incore sizes now.  This should
	 * be safe because we flushed both files' page caches and moved all the
	 * post-eof extents, so there should not be anything to zero.
	 */
	if (fxr->flags & FILE_XCHG_RANGE_TO_EOF) {
		loff_t	temp;

		temp = i_size_read(VFS_I(ip2));
		i_size_write(VFS_I(ip2), i_size_read(VFS_I(ip1)));
		i_size_write(VFS_I(ip1), temp);
	}

	/* Relog the inodes to keep transactions moving forward. */
	xfs_trans_log_inode(tp, ip1, XFS_ILOG_CORE);
	xfs_trans_log_inode(tp, ip2, XFS_ILOG_CORE);

	/*
	 * Force the log to persist metadata updates if the caller or the
	 * administrator requires this.  The VFS prep function already flushed
	 * the relevant parts of the page cache.
	 */
	if ((mp->m_flags & XFS_MOUNT_WSYNC) ||
	    (fxr->flags & FILE_XCHG_RANGE_FSYNC))
		xfs_trans_set_sync(tp);

	error = xfs_trans_commit(tp);

	trace_xfs_swap_extent_after(ip2, 0);
	trace_xfs_swap_extent_after(ip1, 1);

out_unlock:
	xfs_xchg_range_iunlock(ip1, ip2);
	return error;

out_trans_cancel:
	xfs_trans_cancel(tp);
	goto out_unlock;
}
