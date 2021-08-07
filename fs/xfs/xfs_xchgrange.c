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
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_quota.h"
#include "xfs_bmap_util.h"
#include "xfs_reflink.h"
#include "xfs_trace.h"
#include "xfs_swapext.h"
#include "xfs_xchgrange.h"
#include "xfs_sb.h"
#include "xfs_icache.h"
#include "xfs_log.h"

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
		goto drop_incompat;

	/*
	 * Caller requires log-assisted swapping but the fs feature set isn't
	 * rich enough to support it.  Bail out.
	 */
	if (!xfs_sb_version_canatomicswap(&mp->m_sb)) {
		error = -EOPNOTSUPP;
		goto drop_incompat;
	}

	/* Enable log-assisted extent swapping. */
	error = xfs_add_incompat_log_feature(mp,
			XFS_SB_FEAT_INCOMPAT_LOG_ATOMIC_SWAP);
	if (error)
		goto drop_incompat;

	xfs_warn(mp,
 "EXPERIMENTAL atomic file range swap feature added. Use at your own risk!");

	return 0;
drop_incompat:
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
	bool				retried = false;
	int				error;

	trace_xfs_xchg_range(ip1, fxr, ip2, xchg_flags);

	/*
	 * This function only supports using log intent items (SXI items if
	 * atomic exchange is required, or BUI items if not) to exchange file
	 * data.  The legacy whole-fork swap will be ported in a later patch.
	 */
	if (!xfs_sb_version_hasatomicswap(&mp->m_sb) &&
	    !xfs_sb_version_canatomicswap(&mp->m_sb))
		return -EOPNOTSUPP;

	if (fxr->flags & FILE_XCHG_RANGE_TO_EOF)
		req.req_flags |= XFS_SWAP_REQ_SET_SIZES;
	if (fxr->flags & FILE_XCHG_RANGE_SKIP_FILE1_HOLES)
		req.req_flags |= XFS_SWAP_REQ_SKIP_FILE1_HOLES;

	error = xfs_xchg_range_estimate(&req, &res);
	if (error)
		return error;

retry:
	/* Allocate the transaction, lock the inodes, and join them. */
	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_write, res.resblks, 0,
			XFS_TRANS_RES_FDBLKS, &tp);
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

	/* Exchange the file contents by swapping the block mappings. */
	error = xfs_swapext(&tp, &req);
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
