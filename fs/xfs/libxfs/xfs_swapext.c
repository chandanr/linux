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
#include "xfs_bmap.h"
#include "xfs_icache.h"
#include "xfs_quota.h"
#include "xfs_swapext.h"
#include "xfs_trace.h"
#include "xfs_bmap_btree.h"
#include "xfs_trans_space.h"
#include "xfs_errortag.h"
#include "xfs_error.h"
#include "xfs_da_format.h"
#include "xfs_da_btree.h"
#include "xfs_attr_leaf.h"
#include "xfs_attr.h"
#include "xfs_dir2_priv.h"
#include "xfs_dir2.h"

/* Information to help us reset reflink flag / CoW fork state after a swap. */

/* Are we swapping the data fork? */
#define XFS_SX_REFLINK_DATAFORK		(1U << 0)

/* Can we swap the flags? */
#define XFS_SX_REFLINK_SWAPFLAGS	(1U << 1)

/* Previous state of the two inodes' reflink flags. */
#define XFS_SX_REFLINK_IP1_REFLINK	(1U << 2)
#define XFS_SX_REFLINK_IP2_REFLINK	(1U << 3)


/*
 * Prepare both inodes' reflink state for an extent swap, and return our
 * findings so that xfs_swapext_reflink_finish can deal with the aftermath.
 */
unsigned int
xfs_swapext_reflink_prep(
	const struct xfs_swapext_req	*req)
{
	struct xfs_mount		*mp = req->ip1->i_mount;
	unsigned int			rs = 0;

	if (req->whichfork != XFS_DATA_FORK)
		return 0;

	/*
	 * If either file has shared blocks and we're swapping data forks, we
	 * must flag the other file as having shared blocks so that we get the
	 * shared-block rmap functions if we need to fix up the rmaps.  The
	 * flags will be switched for real by xfs_swapext_reflink_finish.
	 */
	if (xfs_is_reflink_inode(req->ip1))
		rs |= XFS_SX_REFLINK_IP1_REFLINK;
	if (xfs_is_reflink_inode(req->ip2))
		rs |= XFS_SX_REFLINK_IP2_REFLINK;

	if (rs & XFS_SX_REFLINK_IP1_REFLINK)
		req->ip2->i_diflags2 |= XFS_DIFLAG2_REFLINK;
	if (rs & XFS_SX_REFLINK_IP2_REFLINK)
		req->ip1->i_diflags2 |= XFS_DIFLAG2_REFLINK;

	/*
	 * If either file had the reflink flag set before; and the two files'
	 * reflink state was different; and we're swapping the entirety of both
	 * files, then we can exchange the reflink flags at the end.
	 * Otherwise, we propagate the reflink flag from either file to the
	 * other file.
	 *
	 * Note that we've only set the _REFLINK flags of the reflink state, so
	 * we can cheat and use hweight32 for the reflink flag test.
	 *
	 */
	if (hweight32(rs) == 1 && req->startoff1 == 0 && req->startoff2 == 0 &&
	    req->blockcount == XFS_B_TO_FSB(mp, req->ip1->i_disk_size) &&
	    req->blockcount == XFS_B_TO_FSB(mp, req->ip2->i_disk_size))
		rs |= XFS_SX_REFLINK_SWAPFLAGS;

	rs |= XFS_SX_REFLINK_DATAFORK;
	return rs;
}

/*
 * If the reflink flag is set on either inode, make sure it has an incore CoW
 * fork, since all reflink inodes must have them.  If there's a CoW fork and it
 * has extents in it, make sure the inodes are tagged appropriately so that
 * speculative preallocations can be GC'd if we run low of space.
 */
static inline void
xfs_swapext_ensure_cowfork(
	struct xfs_inode	*ip)
{
	struct xfs_ifork	*cfork;

	if (xfs_is_reflink_inode(ip))
		xfs_ifork_init_cow(ip);

	cfork = XFS_IFORK_PTR(ip, XFS_COW_FORK);
	if (!cfork)
		return;
	if (cfork->if_bytes > 0)
		xfs_inode_set_cowblocks_tag(ip);
	else
		xfs_inode_clear_cowblocks_tag(ip);
}

/*
 * Set both inodes' ondisk reflink flags to their final state and ensure that
 * the incore state is ready to go.
 */
void
xfs_swapext_reflink_finish(
	struct xfs_trans		*tp,
	const struct xfs_swapext_req	*req,
	unsigned int			rs)
{
	if (!(rs & XFS_SX_REFLINK_DATAFORK))
		return;

	if (rs & XFS_SX_REFLINK_SWAPFLAGS) {
		/* Exchange the reflink inode flags and log them. */
		req->ip1->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;
		if (rs & XFS_SX_REFLINK_IP2_REFLINK)
			req->ip1->i_diflags2 |= XFS_DIFLAG2_REFLINK;

		req->ip2->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;
		if (rs & XFS_SX_REFLINK_IP1_REFLINK)
			req->ip2->i_diflags2 |= XFS_DIFLAG2_REFLINK;

		xfs_trans_log_inode(tp, req->ip1, XFS_ILOG_CORE);
		xfs_trans_log_inode(tp, req->ip2, XFS_ILOG_CORE);
	}

	xfs_swapext_ensure_cowfork(req->ip1);
	xfs_swapext_ensure_cowfork(req->ip2);
}

/* Schedule an atomic extent swap. */
static inline void
xfs_swapext_schedule(
	struct xfs_trans		*tp,
	struct xfs_swapext_intent	*sxi)
{
	trace_xfs_swapext_defer(tp->t_mountp, sxi);
	xfs_defer_add(tp, XFS_DEFER_OPS_TYPE_SWAPEXT, &sxi->sxi_list);
}

/* Reschedule an atomic extent swap on behalf of log recovery. */
void
xfs_swapext_reschedule(
	struct xfs_trans		*tp,
	const struct xfs_swapext_intent	*sxi)
{
	struct xfs_swapext_intent	*new_sxi;

	new_sxi = kmem_alloc(sizeof(struct xfs_swapext_intent), KM_NOFS);
	memcpy(new_sxi, sxi, sizeof(*new_sxi));
	INIT_LIST_HEAD(&new_sxi->sxi_list);

	xfs_swapext_schedule(tp, new_sxi);
}

/*
 * Adjust the on-disk inode size upwards if needed so that we never map extents
 * into the file past EOF.  This is crucial so that log recovery won't get
 * confused by the sudden appearance of post-eof extents.
 */
STATIC void
xfs_swapext_update_size(
	struct xfs_trans	*tp,
	struct xfs_inode	*ip,
	struct xfs_bmbt_irec	*imap,
	xfs_fsize_t		new_isize)
{
	struct xfs_mount	*mp = tp->t_mountp;
	xfs_fsize_t		len;

	if (new_isize < 0)
		return;

	len = min(XFS_FSB_TO_B(mp, imap->br_startoff + imap->br_blockcount),
		  new_isize);

	if (len <= ip->i_disk_size)
		return;

	trace_xfs_swapext_update_inode_size(ip, len);

	ip->i_disk_size = len;
	xfs_trans_log_inode(tp, ip, XFS_ILOG_CORE);
}

/* Convert inode2's leaf attr fork back to shortform, if possible.. */
STATIC int
xfs_swapext_attr_to_shortform2(
	struct xfs_trans		*tp,
	struct xfs_swapext_intent	*sxi)
{
	struct xfs_da_args	args = {
		.dp		= sxi->sxi_ip2,
		.geo		= tp->t_mountp->m_attr_geo,
		.whichfork	= XFS_ATTR_FORK,
		.trans		= tp,
	};
	struct xfs_buf		*bp;
	int			forkoff;
	int			error;

	if (!xfs_attr_is_leaf(sxi->sxi_ip2))
		return 0;

	error = xfs_attr3_leaf_read(tp, sxi->sxi_ip2, 0, &bp);
	if (error)
		return error;

	forkoff = xfs_attr_shortform_allfit(bp, sxi->sxi_ip2);
	if (forkoff == 0)
		return 0;

	return xfs_attr3_leaf_to_shortform(bp, &args, forkoff);
}

/* Mask of all flags that require post-processing of file2. */
#define XFS_SWAP_EXTENT_POST_PROCESSING (XFS_SWAP_EXTENT_INO2_SHORTFORM)

/* Convert inode2's block dir fork back to shortform, if possible.. */
STATIC int
xfs_swapext_dir_to_shortform2(
	struct xfs_trans		*tp,
	struct xfs_swapext_intent	*sxi)
{
	struct xfs_da_args	args = {
		.dp		= sxi->sxi_ip2,
		.geo		= tp->t_mountp->m_dir_geo,
		.whichfork	= XFS_DATA_FORK,
		.trans		= tp,
	};
	struct xfs_dir2_sf_hdr	sfh;
	struct xfs_buf		*bp;
	int			isblock;
	int			size;
	int			error;

	error = xfs_dir2_isblock(&args, &isblock);
	if (error)
		return error;

	if (!isblock)
		return 0;

	error = xfs_dir3_block_read(tp, sxi->sxi_ip2, &bp);
	if (error)
		return error;

	size = xfs_dir2_block_sfsize(sxi->sxi_ip2, bp->b_addr, &sfh);
	if (size > XFS_IFORK_DSIZE(sxi->sxi_ip2))
		return 0;

	return xfs_dir2_block_to_sf(&args, bp, size, &sfh);
}

/* Do we have more work to do to finish this operation? */
bool
xfs_swapext_has_more_work(
	struct xfs_swapext_intent	*sxi)
{
	return sxi->sxi_blockcount > 0 ||
		(sxi->sxi_flags & XFS_SWAP_EXTENT_POST_PROCESSING);
}

/*
 * There may be partially written rt extents lurking in the ranges to be
 * swapped.  According to the rules for realtime files with big rt extents, we
 * must guarantee that an outside observer (an IO thread, realistically) never
 * can see multiple physical rt extents mapped to the same logical file rt
 * extent.  The deferred bmap log intent items that we use under the hood
 * operate on single block mappings and not rt extents, which means we must
 * have a strategy to ensure that log recovery after a failure won't stop in
 * the middle of an rt extent.
 *
 * The preferred strategy is to use deferred extent swap log intent items to
 * track the status of the overall swap operation so that we can complete the
 * work during crash recovery.  If that isn't possible, we fall back to
 * requiring the selected mappings in both forks to be aligned to rt extent
 * boundaries.  As an aside, the old fork swap routine didn't have this
 * requirement, but at an extreme cost in flexibilty (full files only, no attr
 * forks, and no support if rmapbt is enabled).
 */
bool
xfs_swapext_need_rt_conversion(
	struct xfs_inode		*ip)
{
	struct xfs_mount		*mp = ip->i_mount;

	/* We're using the extent swap intent items */
	if (xfs_sb_version_hasatomicswap(&mp->m_sb))
		return false;

	/* The only supported operation is full fork swaps */
	if (!xfs_sb_version_canatomicswap(&mp->m_sb))
		return false;

	/* Conversion is only needed for realtime files with big rt extents */
	return xfs_inode_has_bigrtextents(ip);
}

#ifdef DEBUG
static inline int
xfs_swapext_check_rt_extents(
	struct xfs_mount		*mp,
	const struct xfs_swapext_req	*req)
{
	struct xfs_bmbt_irec		irec1, irec2;
	xfs_fileoff_t			startoff1 = req->startoff1;
	xfs_fileoff_t			startoff2 = req->startoff2;
	xfs_filblks_t			blockcount = req->blockcount;
	uint32_t			mod;
	int				nimaps;
	int				error;

	if (req->whichfork == XFS_ATTR_FORK ||
	    !xfs_swapext_need_rt_conversion(req->ip2))
		return 0;

	while (blockcount > 0) {
		/* Read extent from the first file */
		nimaps = 1;
		error = xfs_bmapi_read(req->ip1, startoff1, blockcount,
				&irec1, &nimaps, 0);
		if (error)
			return error;
		ASSERT(nimaps == 1);

		/* Read extent from the second file */
		nimaps = 1;
		error = xfs_bmapi_read(req->ip2, startoff2,
				irec1.br_blockcount, &irec2, &nimaps,
				0);
		if (error)
			return error;
		ASSERT(nimaps == 1);

		/*
		 * We can only swap as many blocks as the smaller of the two
		 * extent maps.
		 */
		irec1.br_blockcount = min(irec1.br_blockcount,
					  irec2.br_blockcount);

		/* Both mappings must be aligned to the realtime extent size. */
		div_u64_rem(irec1.br_startoff, mp->m_sb.sb_rextsize, &mod);
		if (mod) {
			ASSERT(mod == 0);
			return -EINVAL;
		}

		div_u64_rem(irec2.br_startoff, mp->m_sb.sb_rextsize, &mod);
		if (mod) {
			ASSERT(mod == 0);
			return -EINVAL;
		}

		div_u64_rem(irec1.br_blockcount, mp->m_sb.sb_rextsize, &mod);
		if (mod) {
			ASSERT(mod == 0);
			return -EINVAL;
		}

		startoff1 += irec1.br_blockcount;
		startoff2 += irec1.br_blockcount;
		blockcount -= irec1.br_blockcount;
	}

	return 0;
}
#else
# define xfs_swapext_check_rt_extents(mp, req)		(0)
#endif

/* Check all extents to make sure we can actually swap them. */
int
xfs_swapext_check_extents(
	struct xfs_mount		*mp,
	const struct xfs_swapext_req	*req)
{
	struct xfs_ifork		*ifp1, *ifp2;

	/* No fork? */
	ifp1 = XFS_IFORK_PTR(req->ip1, req->whichfork);
	ifp2 = XFS_IFORK_PTR(req->ip2, req->whichfork);
	if (!ifp1 || !ifp2)
		return -EINVAL;

	/* We don't know how to swap local format forks. */
	if (ifp1->if_format == XFS_DINODE_FMT_LOCAL ||
	    ifp2->if_format == XFS_DINODE_FMT_LOCAL)
		return -EINVAL;

	return xfs_swapext_check_rt_extents(mp, req);
}

#ifdef CONFIG_XFS_QUOTA
/* Log the actual updates to the quota accounting. */
static inline void
xfs_swapext_update_quota(
	struct xfs_trans		*tp,
	struct xfs_swapext_intent	*sxi,
	struct xfs_bmbt_irec		*irec1,
	struct xfs_bmbt_irec		*irec2)
{
	int64_t				ip1_delta = 0, ip2_delta = 0;
	unsigned int			qflag;

	qflag = XFS_IS_REALTIME_INODE(sxi->sxi_ip1) ? XFS_TRANS_DQ_RTBCOUNT :
						      XFS_TRANS_DQ_BCOUNT;

	if (xfs_bmap_is_real_extent(irec1)) {
		ip1_delta -= irec1->br_blockcount;
		ip2_delta += irec1->br_blockcount;
	}

	if (xfs_bmap_is_real_extent(irec2)) {
		ip1_delta += irec2->br_blockcount;
		ip2_delta -= irec2->br_blockcount;
	}

	xfs_trans_mod_dquot_byino(tp, sxi->sxi_ip1, qflag, ip1_delta);
	xfs_trans_mod_dquot_byino(tp, sxi->sxi_ip2, qflag, ip2_delta);
}
#else
# define xfs_swapext_update_quota(tp, sxi, irec1, irec2)	((void)0)
#endif

/* Finish one extent swap, possibly log more. */
int
xfs_swapext_finish_one(
	struct xfs_trans		*tp,
	struct xfs_swapext_intent	*sxi)
{
	struct xfs_bmbt_irec		irec1, irec2;
	int				whichfork;
	int				nimaps;
	int				bmap_flags;
	int				error = 0;

	whichfork = (sxi->sxi_flags & XFS_SWAP_EXTENT_ATTR_FORK) ?
			XFS_ATTR_FORK : XFS_DATA_FORK;
	bmap_flags = xfs_bmapi_aflag(whichfork);

	/* Do any post-processing work that we requires a transaction roll. */
	if (sxi->sxi_blockcount == 0) {
		if (sxi->sxi_flags & XFS_SWAP_EXTENT_INO2_SHORTFORM) {
			if (sxi->sxi_flags & XFS_SWAP_EXTENT_ATTR_FORK)
				error = xfs_swapext_attr_to_shortform2(tp, sxi);
			else if (S_ISDIR(VFS_I(sxi->sxi_ip2)->i_mode))
				error = xfs_swapext_dir_to_shortform2(tp, sxi);
			sxi->sxi_flags &= ~XFS_SWAP_EXTENT_INO2_SHORTFORM;
			return error;
		}
		return 0;
	}

	while (sxi->sxi_blockcount > 0) {
		/* Read extent from the first file */
		nimaps = 1;
		error = xfs_bmapi_read(sxi->sxi_ip1, sxi->sxi_startoff1,
				sxi->sxi_blockcount, &irec1, &nimaps,
				bmap_flags);
		if (error)
			return error;
		if (nimaps != 1 ||
		    irec1.br_startblock == DELAYSTARTBLOCK ||
		    irec1.br_startoff != sxi->sxi_startoff1) {
			/*
			 * We should never get no mapping or a delalloc extent
			 * or something that doesn't match what we asked for,
			 * since the caller flushed both inodes and we hold the
			 * ILOCKs for both inodes.
			 */
			ASSERT(0);
			return -EINVAL;
		}

		/*
		 * If the caller told us to ignore sparse areas of file1, jump
		 * ahead to the next region.
		 */
		if ((sxi->sxi_flags & XFS_SWAP_EXTENT_SKIP_FILE1_HOLES) &&
		    irec1.br_startblock == HOLESTARTBLOCK) {
			trace_xfs_swapext_extent1(sxi->sxi_ip1, &irec1);

			sxi->sxi_startoff1 += irec1.br_blockcount;
			sxi->sxi_startoff2 += irec1.br_blockcount;
			sxi->sxi_blockcount -= irec1.br_blockcount;
			continue;
		}

		/* Read extent from the second file */
		nimaps = 1;
		error = xfs_bmapi_read(sxi->sxi_ip2, sxi->sxi_startoff2,
				irec1.br_blockcount, &irec2, &nimaps,
				bmap_flags);
		if (error)
			return error;
		if (nimaps != 1 ||
		    irec2.br_startblock == DELAYSTARTBLOCK ||
		    irec2.br_startoff != sxi->sxi_startoff2) {
			/*
			 * We should never get no mapping or a delalloc extent
			 * or something that doesn't match what we asked for,
			 * since the caller flushed both inodes and we hold the
			 * ILOCKs for both inodes.
			 */
			ASSERT(0);
			return -EINVAL;
		}

		/*
		 * We can only swap as many blocks as the smaller of the two
		 * extent maps.
		 */
		irec1.br_blockcount = min(irec1.br_blockcount,
					  irec2.br_blockcount);

		trace_xfs_swapext_extent1(sxi->sxi_ip1, &irec1);
		trace_xfs_swapext_extent2(sxi->sxi_ip2, &irec2);

		/*
		 * Two extents mapped to the same physical block must not have
		 * different states; that's filesystem corruption.  Move on to
		 * the next extent if they're both holes or both the same
		 * physical extent.
		 */
		if (irec1.br_startblock == irec2.br_startblock) {
			if (irec1.br_state != irec2.br_state)
				return -EFSCORRUPTED;

			sxi->sxi_startoff1 += irec1.br_blockcount;
			sxi->sxi_startoff2 += irec1.br_blockcount;
			sxi->sxi_blockcount -= irec1.br_blockcount;
			continue;
		}

		xfs_swapext_update_quota(tp, sxi, &irec1, &irec2);

		/* Remove both mappings. */
		xfs_bmap_unmap_extent(tp, sxi->sxi_ip1, whichfork, &irec1);
		xfs_bmap_unmap_extent(tp, sxi->sxi_ip2, whichfork, &irec2);

		/*
		 * Re-add both mappings.  We swap the file offsets between the
		 * two maps and add the opposite map, which has the effect of
		 * filling the logical offsets we just unmapped, but with with
		 * the physical mapping information swapped.
		 */
		swap(irec1.br_startoff, irec2.br_startoff);
		xfs_bmap_map_extent(tp, sxi->sxi_ip1, whichfork, &irec2);
		xfs_bmap_map_extent(tp, sxi->sxi_ip2, whichfork, &irec1);

		/* Make sure we're not mapping extents past EOF. */
		if (whichfork == XFS_DATA_FORK) {
			xfs_swapext_update_size(tp, sxi->sxi_ip1, &irec2,
					sxi->sxi_isize1);
			xfs_swapext_update_size(tp, sxi->sxi_ip2, &irec1,
					sxi->sxi_isize2);
		}

		/*
		 * Advance our cursor and exit.   The caller (either defer ops
		 * or log recovery) will log the SXD item, and if *blockcount
		 * is nonzero, it will log a new SXI item for the remainder
		 * and call us back.
		 */
		sxi->sxi_startoff1 += irec1.br_blockcount;
		sxi->sxi_startoff2 += irec1.br_blockcount;
		sxi->sxi_blockcount -= irec1.br_blockcount;
		break;
	}

	/*
	 * If the caller asked us to exchange the file sizes and we're done
	 * moving extents, update the ondisk file sizes now.
	 */
	if (sxi->sxi_blockcount == 0 &&
	    (sxi->sxi_flags & XFS_SWAP_EXTENT_SET_SIZES)) {
		sxi->sxi_ip1->i_disk_size = sxi->sxi_isize1;
		sxi->sxi_ip2->i_disk_size = sxi->sxi_isize2;

		xfs_trans_log_inode(tp, sxi->sxi_ip1, XFS_ILOG_CORE);
		xfs_trans_log_inode(tp, sxi->sxi_ip2, XFS_ILOG_CORE);
	}

	if (XFS_TEST_ERROR(false, tp->t_mountp, XFS_ERRTAG_SWAPEXT_FINISH_ONE))
		return -EIO;

	if (xfs_swapext_has_more_work(sxi))
		trace_xfs_swapext_defer(tp->t_mountp, sxi);

	return 0;
}

/* Estimate the bmbt and rmapbt overhead required to exchange extents. */
int
xfs_swapext_estimate_overhead(
	const struct xfs_swapext_req	*req,
	struct xfs_swapext_res		*res)
{
	struct xfs_mount		*mp = req->ip1->i_mount;
	unsigned int			bmbt_overhead;

	/*
	 * Compute the amount of bmbt blocks we should reserve for each file.
	 *
	 * Conceptually this shouldn't affect the shape of either bmbt, but
	 * since we atomically move extents one by one, we reserve enough space
	 * to handle a bmbt split for each remap operation (t1).
	 *
	 * However, we must be careful to handle a corner case where the
	 * repeated unmap and map activities could result in ping-ponging of
	 * the btree shape.  This behavior can come from one of two sources:
	 *
	 * An inode's extent list could have just enough records to straddle
	 * the btree format boundary. If so, the inode could bounce between
	 * btree <-> extent format on unmap -> remap cycles, freeing and
	 * allocating a bmapbt block each time.
	 *
	 * The same thing can happen if we have just enough records in a block
	 * to bounce between one and two leaf blocks. If there aren't enough
	 * sibling blocks to absorb or donate some records, we end up reshaping
	 * the tree with every remap operation.  This doesn't seem to happen if
	 * we have more than four bmbt leaf blocks, so we'll make that the
	 * lower bound on the pingponging (t2).
	 *
	 * Therefore, we use XFS_TRANS_RES_FDBLKS so that freed bmbt blocks
	 * are accounted back to the transaction block reservation.
	 */
	bmbt_overhead = XFS_NEXTENTADD_SPACE_RES(mp, res->nr_exchanges,
						 req->whichfork);
	res->ip1_bcount += bmbt_overhead;
	res->ip2_bcount += bmbt_overhead;
	res->resblks += 2 * bmbt_overhead;

	/* Apply similar logic to rmapbt reservations. */
	if (xfs_sb_version_hasrmapbt(&mp->m_sb)) {
		unsigned int	rmapbt_overhead;

		if (!XFS_IS_REALTIME_INODE(req->ip1))
			rmapbt_overhead = XFS_NRMAPADD_SPACE_RES(mp,
							res->nr_exchanges);
		else
			rmapbt_overhead = 0;
		res->resblks += 2 * rmapbt_overhead;
	}

	trace_xfs_swapext_estimate(req, res);

	if (res->resblks > UINT_MAX)
		return -ENOSPC;
	return 0;
}

/* Decide if we can merge two real extents. */
static inline bool
can_merge(
	const struct xfs_bmbt_irec	*b1,
	const struct xfs_bmbt_irec	*b2)
{
	/* Zero length means uninitialized. */
	if (b1->br_blockcount == 0 || b2->br_blockcount == 0)
		return false;

	/* We don't merge holes. */
	if (!xfs_bmap_is_real_extent(b1) || !xfs_bmap_is_real_extent(b2))
		return false;

	if (b1->br_startoff   + b1->br_blockcount == b2->br_startoff &&
	    b1->br_startblock + b1->br_blockcount == b2->br_startblock &&
	    b1->br_state			  == b2->br_state &&
	    b1->br_blockcount + b2->br_blockcount <= MAXEXTLEN)
		return true;

	return false;
}

#define CLEFT_CONTIG	0x01
#define CRIGHT_CONTIG	0x02
#define CHOLE		0x04
#define CBOTH_CONTIG	(CLEFT_CONTIG | CRIGHT_CONTIG)

#define NLEFT_CONTIG	0x10
#define NRIGHT_CONTIG	0x20
#define NHOLE		0x40
#define NBOTH_CONTIG	(NLEFT_CONTIG | NRIGHT_CONTIG)

/* Estimate the effect of a single swap on extent count. */
static inline int
delta_nextents_step(
	struct xfs_mount		*mp,
	const struct xfs_bmbt_irec	*left,
	const struct xfs_bmbt_irec	*curr,
	const struct xfs_bmbt_irec	*new,
	const struct xfs_bmbt_irec	*right)
{
	bool				lhole, rhole, chole, nhole;
	unsigned int			state = 0;
	int				ret = 0;

	lhole = left->br_blockcount == 0 ||
		left->br_startblock == HOLESTARTBLOCK;
	rhole = right->br_blockcount == 0 ||
		right->br_startblock == HOLESTARTBLOCK;
	chole = curr->br_startblock == HOLESTARTBLOCK;
	nhole = new->br_startblock == HOLESTARTBLOCK;

	if (chole)
		state |= CHOLE;
	if (!lhole && !chole && can_merge(left, curr))
		state |= CLEFT_CONTIG;
	if (!rhole && !chole && can_merge(curr, right))
		state |= CRIGHT_CONTIG;
	if ((state & CBOTH_CONTIG) == CBOTH_CONTIG &&
	    left->br_startblock + curr->br_startblock +
					right->br_startblock > MAXEXTLEN)
		state &= ~CRIGHT_CONTIG;

	if (nhole)
		state |= NHOLE;
	if (!lhole && !nhole && can_merge(left, new))
		state |= NLEFT_CONTIG;
	if (!rhole && !nhole && can_merge(new, right))
		state |= NRIGHT_CONTIG;
	if ((state & NBOTH_CONTIG) == NBOTH_CONTIG &&
	    left->br_startblock + new->br_startblock +
					right->br_startblock > MAXEXTLEN)
		state &= ~NRIGHT_CONTIG;

	switch (state & (CLEFT_CONTIG | CRIGHT_CONTIG | CHOLE)) {
	case CLEFT_CONTIG | CRIGHT_CONTIG:
		/*
		 * left/curr/right are the same extent, so deleting curr causes
		 * 2 new extents to be created.
		 */
		ret += 2;
		break;
	case 0:
		/*
		 * curr is not contiguous with any extent, so we remove curr
		 * completely
		 */
		ret--;
		break;
	case CHOLE:
		/* hole, do nothing */
		break;
	case CLEFT_CONTIG:
	case CRIGHT_CONTIG:
		/* trim either left or right, no change */
		break;
	}

	switch (state & (NLEFT_CONTIG | NRIGHT_CONTIG | NHOLE)) {
	case NLEFT_CONTIG | NRIGHT_CONTIG:
		/*
		 * left/curr/right will become the same extent, so adding
		 * curr causes the deletion of right.
		 */
		ret--;
		break;
		break;
	case 0:
		/* new is not contiguous with any extent */
		ret++;
		break;
	case NHOLE:
		/* hole, do nothing. */
		break;
	case NLEFT_CONTIG:
	case NRIGHT_CONTIG:
		/* new is absorbed into left or right, no change */
		break;
	}

	trace_xfs_swapext_delta_nextents_step(mp, left, curr, new, right, ret,
			state);
	return ret;
}

/* Make sure we don't overflow the extent counters. */
static inline int
check_delta_nextents(
	const struct xfs_swapext_req	*req,
	struct xfs_inode		*ip,
	int64_t				delta)
{
	ASSERT(delta < INT_MAX);
	ASSERT(delta > INT_MIN);

	if (delta < 0)
		return 0;

	return xfs_iext_count_may_overflow(ip, req->whichfork, delta);
}

/* Find the next extent after irec. */
static inline int
get_next_ext(
	struct xfs_inode		*ip,
	unsigned int			bmap_flags,
	const struct xfs_bmbt_irec	*irec,
	struct xfs_bmbt_irec		*nrec)
{
	xfs_fileoff_t			off;
	xfs_filblks_t			blockcount;
	int				nimaps = 1;
	int				error;

	off = irec->br_startoff + irec->br_blockcount;
	blockcount = XFS_MAX_FILEOFF - off;
	error = xfs_bmapi_read(ip, off, blockcount, nrec, &nimaps, bmap_flags);
	if (error)
		return error;
	if (nrec->br_startblock == DELAYSTARTBLOCK ||
	    nrec->br_startoff != off) {
		/*
		 * If we don't get the extent we want, return a zero-length
		 * mapping, which our estimator function will pretend is a hole.
		 */
		nrec->br_blockcount = 0;
	}

	return 0;
}

/*
 * Estimate the number of exchange operations and the number of file blocks
 * in each file that will be affected by the exchange operation.
 */
int
xfs_swapext_estimate(
	const struct xfs_swapext_req	*req,
	struct xfs_swapext_res		*res)
{
	struct xfs_bmbt_irec		irec1, irec2;
	struct xfs_bmbt_irec		lrec1 = { }, lrec2 = { };
	struct xfs_bmbt_irec		rrec1, rrec2;
	xfs_fileoff_t			startoff1 = req->startoff1;
	xfs_fileoff_t			startoff2 = req->startoff2;
	xfs_filblks_t			blockcount = req->blockcount;
	xfs_filblks_t			ip1_blocks = 0, ip2_blocks = 0;
	int64_t				d_nexts1, d_nexts2;
	int				bmap_flags;
	int				nimaps;
	int				error;

	bmap_flags = xfs_bmapi_aflag(req->whichfork);
	memset(res, 0, sizeof(struct xfs_swapext_res));

	/*
	 * To guard against the possibility of overflowing the extent counters,
	 * we have to estimate an upper bound on the potential increase in that
	 * counter.  We can split the extent at each end of the range, and for
	 * each step of the swap we can split the extent that we're working on
	 * if the extents do not align.
	 */
	d_nexts1 = d_nexts2 = 3;

	while (blockcount > 0) {
		/* Read extent from the first file */
		nimaps = 1;
		error = xfs_bmapi_read(req->ip1, startoff1, blockcount,
				&irec1, &nimaps, bmap_flags);
		if (error)
			return error;
		if (irec1.br_startblock == DELAYSTARTBLOCK ||
		    irec1.br_startoff != startoff1) {
			/*
			 * We should never get no mapping or a delalloc extent
			 * or something that doesn't match what we asked for,
			 * since the caller flushed both inodes and we hold the
			 * ILOCKs for both inodes.
			 */
			ASSERT(0);
			return -EINVAL;
		}

		/*
		 * If the caller told us to ignore sparse areas of file1, jump
		 * ahead to the next region.
		 */
		if ((req->flags & XFS_SWAPEXT_SKIP_FILE1_HOLES) &&
		    irec1.br_startblock == HOLESTARTBLOCK) {
			memcpy(&lrec1, &irec1, sizeof(struct xfs_bmbt_irec));
			lrec1.br_blockcount = 0;
			goto advance;
		}

		/* Read extent from the second file */
		nimaps = 1;
		error = xfs_bmapi_read(req->ip2, startoff2,
				irec1.br_blockcount, &irec2, &nimaps,
				bmap_flags);
		if (error)
			return error;
		if (irec2.br_startblock == DELAYSTARTBLOCK ||
		    irec2.br_startoff != startoff2) {
			/*
			 * We should never get no mapping or a delalloc extent
			 * or something that doesn't match what we asked for,
			 * since the caller flushed both inodes and we hold the
			 * ILOCKs for both inodes.
			 */
			ASSERT(0);
			return -EINVAL;
		}

		/*
		 * We can only swap as many blocks as the smaller of the two
		 * extent maps.
		 */
		irec1.br_blockcount = min(irec1.br_blockcount,
					  irec2.br_blockcount);

		/*
		 * Two extents mapped to the same physical block must not have
		 * different states; that's filesystem corruption.  Move on to
		 * the next extent if they're both holes or both the same
		 * physical extent.
		 */
		if (irec1.br_startblock == irec2.br_startblock) {
			if (irec1.br_state != irec2.br_state)
				return -EFSCORRUPTED;
			memcpy(&lrec1, &irec1, sizeof(struct xfs_bmbt_irec));
			memcpy(&lrec2, &irec2, sizeof(struct xfs_bmbt_irec));
			goto advance;
		}

		/* Update accounting. */
		if (xfs_bmap_is_real_extent(&irec1))
			ip1_blocks += irec1.br_blockcount;
		if (xfs_bmap_is_real_extent(&irec2))
			ip2_blocks += irec2.br_blockcount;
		res->nr_exchanges++;

		/* Read next extent from the first file */
		error = get_next_ext(req->ip1, bmap_flags, &irec1, &rrec1);
		if (error)
			return error;
		error = get_next_ext(req->ip2, bmap_flags, &irec2, &rrec2);
		if (error)
			return error;

		d_nexts1 += delta_nextents_step(req->ip1->i_mount,
				&lrec1, &irec1, &irec2, &rrec1);
		d_nexts2 += delta_nextents_step(req->ip1->i_mount,
				&lrec2, &irec2, &irec1, &rrec2);

		/* Now pretend we swapped the extents. */
		if (can_merge(&lrec2, &irec1))
			lrec2.br_blockcount += irec1.br_blockcount;
		else
			memcpy(&lrec2, &irec1, sizeof(struct xfs_bmbt_irec));
		if (can_merge(&lrec1, &irec2))
			lrec1.br_blockcount += irec2.br_blockcount;
		else
			memcpy(&lrec1, &irec2, sizeof(struct xfs_bmbt_irec));

advance:
		/* Advance our cursor and move on. */
		startoff1 += irec1.br_blockcount;
		startoff2 += irec1.br_blockcount;
		blockcount -= irec1.br_blockcount;
	}

	/* Account for the blocks that are being exchanged. */
	if (XFS_IS_REALTIME_INODE(req->ip1) &&
	    req->whichfork == XFS_DATA_FORK) {
		res->ip1_rtbcount = ip1_blocks;
		res->ip2_rtbcount = ip2_blocks;
	} else {
		res->ip1_bcount = ip1_blocks;
		res->ip2_bcount = ip2_blocks;
	}

	/*
	 * Make sure that both forks have enough slack left in their extent
	 * counters that the swap operation will not overflow.
	 */
	trace_xfs_swapext_delta_nextents(req, d_nexts1, d_nexts2);
	if (req->ip1 == req->ip2) {
		error = check_delta_nextents(req, req->ip1,
				d_nexts1 + d_nexts2);
	} else {
		error = check_delta_nextents(req, req->ip1, d_nexts1);
		if (error)
			return error;
		error = check_delta_nextents(req, req->ip2, d_nexts2);
	}
	if (error)
		return error;

	return xfs_swapext_estimate_overhead(req, res);
}

static void
xfs_swapext_init_intent(
	struct xfs_swapext_intent	*sxi,
	const struct xfs_swapext_req	*req)
{
	INIT_LIST_HEAD(&sxi->sxi_list);
	sxi->sxi_flags = 0;
	if (req->whichfork == XFS_ATTR_FORK)
		sxi->sxi_flags |= XFS_SWAP_EXTENT_ATTR_FORK;
	sxi->sxi_isize1 = sxi->sxi_isize2 = -1;
	if (req->whichfork == XFS_DATA_FORK &&
	    (req->flags & XFS_SWAPEXT_SET_SIZES)) {
		sxi->sxi_flags |= XFS_SWAP_EXTENT_SET_SIZES;
		sxi->sxi_isize1 = req->ip2->i_disk_size;
		sxi->sxi_isize2 = req->ip1->i_disk_size;
	}
	if (req->flags & XFS_SWAPEXT_SKIP_FILE1_HOLES)
		sxi->sxi_flags |= XFS_SWAP_EXTENT_SKIP_FILE1_HOLES;
	if (req->flags & XFS_SWAPEXT_INO2_SHORTFORM)
		sxi->sxi_flags |= XFS_SWAP_EXTENT_INO2_SHORTFORM;
	sxi->sxi_ip1 = req->ip1;
	sxi->sxi_ip2 = req->ip2;
	sxi->sxi_startoff1 = req->startoff1;
	sxi->sxi_startoff2 = req->startoff2;
	sxi->sxi_blockcount = req->blockcount;
}

/*
 * Swap a range of extents from one inode to another.  If the atomic swap
 * feature is enabled, then the operation progress can be resumed even if the
 * system goes down.
 *
 * The caller must ensure the inodes must be joined to the transaction and
 * ILOCKd; they will still be joined to the transaction at exit.
 */
int
xfs_swapext(
	struct xfs_trans		**tpp,
	const struct xfs_swapext_req	*req)
{
	struct xfs_swapext_intent	*sxi;
	unsigned int			reflink_state;
	int				error;

	ASSERT(xfs_isilocked(req->ip1, XFS_ILOCK_EXCL));
	ASSERT(xfs_isilocked(req->ip2, XFS_ILOCK_EXCL));
	ASSERT(req->whichfork != XFS_COW_FORK);
	if (req->flags & XFS_SWAPEXT_SET_SIZES)
		ASSERT(req->whichfork == XFS_DATA_FORK);

	if (req->blockcount == 0)
		return 0;

	reflink_state = xfs_swapext_reflink_prep(req);

	sxi = kmem_alloc(sizeof(struct xfs_swapext_intent), KM_NOFS);
	xfs_swapext_init_intent(sxi, req);
	xfs_swapext_schedule(*tpp, sxi);

	error = xfs_defer_finish(tpp);
	if (error)
		return error;

	xfs_swapext_reflink_finish(*tpp, req, reflink_state);
	return 0;
}
