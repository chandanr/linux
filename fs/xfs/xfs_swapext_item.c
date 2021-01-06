// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_format.h"
#include "xfs_log_format.h"
#include "xfs_trans_resv.h"
#include "xfs_bit.h"
#include "xfs_shared.h"
#include "xfs_mount.h"
#include "xfs_defer.h"
#include "xfs_inode.h"
#include "xfs_trans.h"
#include "xfs_trans_priv.h"
#include "xfs_swapext_item.h"
#include "xfs_swapext.h"
#include "xfs_log.h"
#include "xfs_bmap.h"
#include "xfs_icache.h"
#include "xfs_bmap_btree.h"
#include "xfs_trans_space.h"
#include "xfs_error.h"
#include "xfs_log_priv.h"
#include "xfs_log_recover.h"
#include "xfs_xchgrange.h"

kmem_zone_t	*xfs_sxi_zone;
kmem_zone_t	*xfs_sxd_zone;

static const struct xfs_item_ops xfs_sxi_item_ops;

static inline struct xfs_sxi_log_item *SXI_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_sxi_log_item, sxi_item);
}

STATIC void
xfs_sxi_item_free(
	struct xfs_sxi_log_item	*sxi_lip)
{
	kmem_cache_free(xfs_sxi_zone, sxi_lip);
}

/*
 * Freeing the SXI requires that we remove it from the AIL if it has already
 * been placed there. However, the SXI may not yet have been placed in the AIL
 * when called by xfs_sxi_release() from SXD processing due to the ordering of
 * committed vs unpin operations in bulk insert operations. Hence the reference
 * count to ensure only the last caller frees the SXI.
 */
STATIC void
xfs_sxi_release(
	struct xfs_sxi_log_item	*sxi_lip)
{
	ASSERT(atomic_read(&sxi_lip->sxi_refcount) > 0);
	if (atomic_dec_and_test(&sxi_lip->sxi_refcount)) {
		xfs_trans_ail_delete(&sxi_lip->sxi_item, SHUTDOWN_LOG_IO_ERROR);
		xfs_sxi_item_free(sxi_lip);
	}
}


STATIC void
xfs_sxi_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += sizeof(struct xfs_sxi_log_format);
}

/*
 * This is called to fill in the vector of log iovecs for the given sxi log
 * item. We use only 1 iovec, and we point that at the sxi_log_format structure
 * embedded in the sxi item.
 */
STATIC void
xfs_sxi_item_format(
	struct xfs_log_item	*lip,
	struct xfs_log_vec	*lv)
{
	struct xfs_sxi_log_item	*sxi_lip = SXI_ITEM(lip);
	struct xfs_log_iovec	*vecp = NULL;

	sxi_lip->sxi_format.sxi_type = XFS_LI_SXI;
	sxi_lip->sxi_format.sxi_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_SXI_FORMAT,
			&sxi_lip->sxi_format,
			sizeof(struct xfs_sxi_log_format));
}

/*
 * The unpin operation is the last place an SXI is manipulated in the log. It
 * is either inserted in the AIL or aborted in the event of a log I/O error. In
 * either case, the SXI transaction has been successfully committed to make it
 * this far. Therefore, we expect whoever committed the SXI to either construct
 * and commit the SXD or drop the SXD's reference in the event of error. Simply
 * drop the log's SXI reference now that the log is done with it.
 */
STATIC void
xfs_sxi_item_unpin(
	struct xfs_log_item	*lip,
	int			remove)
{
	struct xfs_sxi_log_item	*sxi_lip = SXI_ITEM(lip);

	xfs_sxi_release(sxi_lip);
}

/*
 * The SXI has been either committed or aborted if the transaction has been
 * cancelled. If the transaction was cancelled, an SXD isn't going to be
 * constructed and thus we free the SXI here directly.
 */
STATIC void
xfs_sxi_item_release(
	struct xfs_log_item	*lip)
{
	xfs_sxi_release(SXI_ITEM(lip));
}

/* Allocate and initialize an sxi item with the given number of extents. */
STATIC struct xfs_sxi_log_item *
xfs_sxi_init(
	struct xfs_mount		*mp)

{
	struct xfs_sxi_log_item		*sxi_lip;

	sxi_lip = kmem_cache_zalloc(xfs_sxi_zone, GFP_KERNEL | __GFP_NOFAIL);

	xfs_log_item_init(mp, &sxi_lip->sxi_item, XFS_LI_SXI, &xfs_sxi_item_ops);
	sxi_lip->sxi_format.sxi_id = (uintptr_t)(void *)sxi_lip;
	atomic_set(&sxi_lip->sxi_refcount, 2);

	return sxi_lip;
}

static inline struct xfs_sxd_log_item *SXD_ITEM(struct xfs_log_item *lip)
{
	return container_of(lip, struct xfs_sxd_log_item, sxd_item);
}

STATIC void
xfs_sxd_item_size(
	struct xfs_log_item	*lip,
	int			*nvecs,
	int			*nbytes)
{
	*nvecs += 1;
	*nbytes += sizeof(struct xfs_sxd_log_format);
}

/*
 * This is called to fill in the vector of log iovecs for the given sxd log
 * item. We use only 1 iovec, and we point that at the sxd_log_format structure
 * embedded in the sxd item.
 */
STATIC void
xfs_sxd_item_format(
	struct xfs_log_item	*lip,
	struct xfs_log_vec	*lv)
{
	struct xfs_sxd_log_item	*sxd_lip = SXD_ITEM(lip);
	struct xfs_log_iovec	*vecp = NULL;

	sxd_lip->sxd_format.sxd_type = XFS_LI_SXD;
	sxd_lip->sxd_format.sxd_size = 1;

	xlog_copy_iovec(lv, &vecp, XLOG_REG_TYPE_SXD_FORMAT, &sxd_lip->sxd_format,
			sizeof(struct xfs_sxd_log_format));
}

/*
 * The SXD is either committed or aborted if the transaction is cancelled. If
 * the transaction is cancelled, drop our reference to the SXI and free the
 * SXD.
 */
STATIC void
xfs_sxd_item_release(
	struct xfs_log_item	*lip)
{
	struct xfs_sxd_log_item	*sxd_lip = SXD_ITEM(lip);

	xfs_sxi_release(sxd_lip->sxd_intent_log_item);
	kmem_cache_free(xfs_sxd_zone, sxd_lip);
}

static const struct xfs_item_ops xfs_sxd_item_ops = {
	.flags		= XFS_ITEM_RELEASE_WHEN_COMMITTED,
	.iop_size	= xfs_sxd_item_size,
	.iop_format	= xfs_sxd_item_format,
	.iop_release	= xfs_sxd_item_release,
};

static struct xfs_sxd_log_item *
xfs_trans_get_sxd(
	struct xfs_trans		*tp,
	struct xfs_sxi_log_item		*sxi_lip)
{
	struct xfs_sxd_log_item		*sxd_lip;

	sxd_lip = kmem_cache_zalloc(xfs_sxd_zone, GFP_KERNEL | __GFP_NOFAIL);
	xfs_log_item_init(tp->t_mountp, &sxd_lip->sxd_item, XFS_LI_SXD,
			  &xfs_sxd_item_ops);
	sxd_lip->sxd_intent_log_item = sxi_lip;
	sxd_lip->sxd_format.sxd_sxi_id = sxi_lip->sxi_format.sxi_id;

	xfs_trans_add_item(tp, &sxd_lip->sxd_item);
	return sxd_lip;
}

/*
 * Finish an swapext update and log it to the SXD. Note that the transaction is
 * marked dirty regardless of whether the swapext update succeeds or fails to
 * support the SXI/SXD lifecycle rules.
 */
static int
xfs_swapext_finish_update(
	struct xfs_trans		*tp,
	struct xfs_log_item		*done,
	struct xfs_swapext_intent	*sxi)
{
	int				error;

	error = xfs_swapext_finish_one(tp, sxi);

	/*
	 * Mark the transaction dirty, even on error. This ensures the
	 * transaction is aborted, which:
	 *
	 * 1.) releases the SXI and frees the SXD
	 * 2.) shuts down the filesystem
	 */
	tp->t_flags |= XFS_TRANS_DIRTY;
	if (done)
		set_bit(XFS_LI_DIRTY, &done->li_flags);

	return error;
}

/* Log swapext updates in the intent item. */
STATIC void
xfs_swapext_log_item(
	struct xfs_trans		*tp,
	struct xfs_sxi_log_item		*sxi_lip,
	struct xfs_swapext_intent	*sxi)
{
	struct xfs_swap_extent		*sx;

	tp->t_flags |= XFS_TRANS_DIRTY;
	set_bit(XFS_LI_DIRTY, &sxi_lip->sxi_item.li_flags);

	sx = &sxi_lip->sxi_format.sxi_extent;
	sx->sx_inode1 = sxi->sxi_ip1->i_ino;
	sx->sx_inode2 = sxi->sxi_ip2->i_ino;
	sx->sx_startoff1 = sxi->sxi_startoff1;
	sx->sx_startoff2 = sxi->sxi_startoff2;
	sx->sx_blockcount = sxi->sxi_blockcount;
	sx->sx_isize1 = sxi->sxi_isize1;
	sx->sx_isize2 = sxi->sxi_isize2;
	sx->sx_flags = sxi->sxi_flags;
}

STATIC struct xfs_log_item *
xfs_swapext_create_intent(
	struct xfs_trans		*tp,
	struct list_head		*items,
	unsigned int			count,
	bool				sort)
{
	struct xfs_sxi_log_item		*sxi_lip = xfs_sxi_init(tp->t_mountp);
	struct xfs_swapext_intent	*sxi;

	ASSERT(count == XFS_SXI_MAX_FAST_EXTENTS);

	/*
	 * We use the same defer ops control machinery to perform extent swaps
	 * even if we lack the machinery to track the operation status through
	 * log items.
	 */
	if (!xfs_sb_version_hasatomicswap(&tp->t_mountp->m_sb))
		return NULL;

	xfs_trans_add_item(tp, &sxi_lip->sxi_item);
	list_for_each_entry(sxi, items, sxi_list)
		xfs_swapext_log_item(tp, sxi_lip, sxi);
	return &sxi_lip->sxi_item;
}

STATIC struct xfs_log_item *
xfs_swapext_create_done(
	struct xfs_trans		*tp,
	struct xfs_log_item		*intent,
	unsigned int			count)
{
	if (intent == NULL)
		return NULL;
	return &xfs_trans_get_sxd(tp, SXI_ITEM(intent))->sxd_item;
}

/* Process a deferred swapext update. */
STATIC int
xfs_swapext_finish_item(
	struct xfs_trans		*tp,
	struct xfs_log_item		*done,
	struct list_head		*item,
	struct xfs_btree_cur		**state)
{
	struct xfs_swapext_intent	*sxi;
	int				error;

	sxi = container_of(item, struct xfs_swapext_intent, sxi_list);

	/*
	 * Swap one more extent between the two files.  If there's still more
	 * work to do, we want to requeue ourselves after all other pending
	 * deferred operations have finished.  This includes all of the dfops
	 * that we queued directly as well as any new ones created in the
	 * process of finishing the others.  Doing so prevents us from queuing
	 * a large number of SXI log items in kernel memory, which in turn
	 * prevents us from pinning the tail of the log (while logging those
	 * new SXI items) until the first SXI items can be processed.
	 */
	error = xfs_swapext_finish_update(tp, done, sxi);
	if (!error && xfs_swapext_has_more_work(sxi))
		return -EAGAIN;

	kmem_free(sxi);
	return error;
}

/* Abort all pending SXIs. */
STATIC void
xfs_swapext_abort_intent(
	struct xfs_log_item		*intent)
{
	xfs_sxi_release(SXI_ITEM(intent));
}

/* Cancel a deferred swapext update. */
STATIC void
xfs_swapext_cancel_item(
	struct list_head		*item)
{
	struct xfs_swapext_intent	*sxi;

	sxi = container_of(item, struct xfs_swapext_intent, sxi_list);
	kmem_free(sxi);
}

const struct xfs_defer_op_type xfs_swapext_defer_type = {
	.max_items	= XFS_SXI_MAX_FAST_EXTENTS,
	.create_intent	= xfs_swapext_create_intent,
	.abort_intent	= xfs_swapext_abort_intent,
	.create_done	= xfs_swapext_create_done,
	.finish_item	= xfs_swapext_finish_item,
	.cancel_item	= xfs_swapext_cancel_item,
};

static int
xfs_sxi_item_recover_estimate(
	struct xfs_swapext_intent	*sxi,
	struct xfs_swapext_res		*res)
{
	struct xfs_swapext_req		req = {
		.ip1			= sxi->sxi_ip1,
		.ip2			= sxi->sxi_ip2,
		.startoff1		= sxi->sxi_startoff1,
		.startoff2		= sxi->sxi_startoff2,
		.blockcount		= sxi->sxi_blockcount,
		.whichfork		= XFS_DATA_FORK,
	};

	if (sxi->sxi_flags & XFS_SWAP_EXTENT_ATTR_FORK)
		req.whichfork = XFS_ATTR_FORK;
	if (sxi->sxi_flags & XFS_SWAP_EXTENT_SET_SIZES)
		req.flags |= XFS_SWAPEXT_SET_SIZES;
	if (sxi->sxi_flags & XFS_SWAP_EXTENT_SKIP_FILE1_HOLES)
		req.flags |= XFS_SWAPEXT_SKIP_FILE1_HOLES;

	return xfs_xchg_range_estimate(&req, res);
}

/* Is this recovered SXI ok? */
static inline bool
xfs_sxi_validate(
	struct xfs_mount		*mp,
	struct xfs_sxi_log_item		*sxi_lip)
{
	struct xfs_swap_extent		*sx = &sxi_lip->sxi_format.sxi_extent;

	if (!xfs_sb_version_hasatomicswap(&mp->m_sb))
		return false;

	if (sxi_lip->sxi_format.__pad != 0)
		return false;

	if (sx->sx_flags & ~XFS_SWAP_EXTENT_FLAGS)
		return false;

	if (!xfs_verify_ino(mp, sx->sx_inode1) ||
	    !xfs_verify_ino(mp, sx->sx_inode2))
		return false;

	if ((sx->sx_flags & XFS_SWAP_EXTENT_SET_SIZES) &&
	     (sx->sx_isize1 < 0 || sx->sx_isize2 < 0))
		return false;

	if (!xfs_verify_fileext(mp, sx->sx_startoff1, sx->sx_blockcount))
		return false;

	return xfs_verify_fileext(mp, sx->sx_startoff2, sx->sx_blockcount);
}

/* Process a swapext update intent item that was recovered from the log. */
STATIC int
xfs_sxi_item_recover(
	struct xfs_log_item		*lip,
	struct list_head		*capture_list)
{
	struct xfs_swapext_intent	sxi;
	struct xfs_swapext_res		res;
	struct xfs_sxi_log_item		*sxi_lip = SXI_ITEM(lip);
	struct xfs_mount		*mp = lip->li_mountp;
	struct xfs_swap_extent		*sx = &sxi_lip->sxi_format.sxi_extent;
	struct xfs_sxd_log_item		*sxd_lip = NULL;
	struct xfs_trans		*tp;
	bool				more_work;
	int				error = 0;

	if (!xfs_sxi_validate(mp, sxi_lip)) {
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp,
				&sxi_lip->sxi_format,
				sizeof(sxi_lip->sxi_format));
		return -EFSCORRUPTED;
	}

	memset(&sxi, 0, sizeof(sxi));
	INIT_LIST_HEAD(&sxi.sxi_list);

	/*
	 * Grab both inodes and set IRECOVERY to prevent trimming of post-eof
	 * extents and freeing of unlinked inodes until we're totally done
	 * processing files.
	 */
	error = xlog_recover_iget(mp, sx->sx_inode1, &sxi.sxi_ip1);
	if (error)
		return error;
	error = xlog_recover_iget(mp, sx->sx_inode2, &sxi.sxi_ip2);
	if (error)
		goto err_rele1;

	/*
	 * Construct the rest of our in-core swapext intent state so that we
	 * can allocate all the resources we need to continue the swap work.
	 */
	sxi.sxi_flags = sx->sx_flags;
	sxi.sxi_startoff1 = sx->sx_startoff1;
	sxi.sxi_startoff2 = sx->sx_startoff2;
	sxi.sxi_blockcount = sx->sx_blockcount;
	sxi.sxi_isize1 = sx->sx_isize1;
	sxi.sxi_isize2 = sx->sx_isize2;
	error = xfs_sxi_item_recover_estimate(&sxi, &res);
	if (error)
		goto err_rele2;

	error = xfs_trans_alloc(mp, &M_RES(mp)->tr_write, res.resblks, 0,
			0, &tp);
	if (error)
		goto err_rele2;

	sxd_lip = xfs_trans_get_sxd(tp, sxi_lip);

	xfs_xchg_range_ilock(tp, sxi.sxi_ip1, sxi.sxi_ip2);

	error = xfs_swapext_finish_update(tp, &sxd_lip->sxd_item, &sxi);
	if (error == -EFSCORRUPTED)
		XFS_CORRUPTION_ERROR(__func__, XFS_ERRLEVEL_LOW, mp, sx,
				sizeof(*sx));
	if (error)
		goto err_cancel;

	/*
	 * If there's more extent swapping to be done, we have to schedule that
	 * as a separate deferred operation to be run after we've finished
	 * replaying all of the intents we recovered from the log.
	 */
	more_work = xfs_swapext_has_more_work(&sxi);
	if (more_work)
		xfs_swapext_reschedule(tp, &sxi);

	/*
	 * Commit transaction, which frees the transaction and saves the inodes
	 * for later replay activities.
	 */
	error = xfs_defer_ops_capture_and_commit(tp, sxi.sxi_ip1, sxi.sxi_ip2,
			capture_list);
	goto err_unlock;

err_cancel:
	xfs_trans_cancel(tp);
err_unlock:
	xfs_xchg_range_iunlock(sxi.sxi_ip1, sxi.sxi_ip2);
err_rele2:
	if (sxi.sxi_ip2 != sxi.sxi_ip1)
		xfs_irele(sxi.sxi_ip2);
err_rele1:
	xfs_irele(sxi.sxi_ip1);
	return error;
}

STATIC bool
xfs_sxi_item_match(
	struct xfs_log_item	*lip,
	uint64_t		intent_id)
{
	return SXI_ITEM(lip)->sxi_format.sxi_id == intent_id;
}

/* Relog an intent item to push the log tail forward. */
static struct xfs_log_item *
xfs_sxi_item_relog(
	struct xfs_log_item		*intent,
	struct xfs_trans		*tp)
{
	struct xfs_sxd_log_item		*sxd_lip;
	struct xfs_sxi_log_item		*sxi_lip;
	struct xfs_swap_extent		*sx;

	sx = &SXI_ITEM(intent)->sxi_format.sxi_extent;

	tp->t_flags |= XFS_TRANS_DIRTY;
	sxd_lip = xfs_trans_get_sxd(tp, SXI_ITEM(intent));
	set_bit(XFS_LI_DIRTY, &sxd_lip->sxd_item.li_flags);

	sxi_lip = xfs_sxi_init(tp->t_mountp);
	memcpy(&sxi_lip->sxi_format.sxi_extent, sx, sizeof(*sx));
	xfs_trans_add_item(tp, &sxi_lip->sxi_item);
	set_bit(XFS_LI_DIRTY, &sxi_lip->sxi_item.li_flags);
	return &sxi_lip->sxi_item;
}

static const struct xfs_item_ops xfs_sxi_item_ops = {
	.iop_size	= xfs_sxi_item_size,
	.iop_format	= xfs_sxi_item_format,
	.iop_unpin	= xfs_sxi_item_unpin,
	.iop_release	= xfs_sxi_item_release,
	.iop_recover	= xfs_sxi_item_recover,
	.iop_match	= xfs_sxi_item_match,
	.iop_relog	= xfs_sxi_item_relog,
};

/*
 * Copy an SXI format buffer from the given buf, and into the destination SXI
 * format structure.  The SXI/SXD items were designed not to need any special
 * alignment handling.
 */
static int
xfs_sxi_copy_format(
	struct xfs_log_iovec		*buf,
	struct xfs_sxi_log_format	*dst_sxi_fmt)
{
	struct xfs_sxi_log_format	*src_sxi_fmt;
	size_t				len;

	src_sxi_fmt = buf->i_addr;
	len = sizeof(struct xfs_sxi_log_format);

	if (buf->i_len == len) {
		memcpy(dst_sxi_fmt, src_sxi_fmt, len);
		return 0;
	}
	XFS_ERROR_REPORT(__func__, XFS_ERRLEVEL_LOW, NULL);
	return -EFSCORRUPTED;
}

/*
 * This routine is called to create an in-core extent swapext update item from
 * the sxi format structure which was logged on disk.  It allocates an in-core
 * sxi, copies the extents from the format structure into it, and adds the sxi
 * to the AIL with the given LSN.
 */
STATIC int
xlog_recover_sxi_commit_pass2(
	struct xlog			*log,
	struct list_head		*buffer_list,
	struct xlog_recover_item	*item,
	xfs_lsn_t			lsn)
{
	int				error;
	struct xfs_mount		*mp = log->l_mp;
	struct xfs_sxi_log_item		*sxi_lip;
	struct xfs_sxi_log_format	*sxi_formatp;

	sxi_formatp = item->ri_buf[0].i_addr;

	if (sxi_formatp->__pad != 0) {
		XFS_ERROR_REPORT(__func__, XFS_ERRLEVEL_LOW, log->l_mp);
		return -EFSCORRUPTED;
	}
	sxi_lip = xfs_sxi_init(mp);
	error = xfs_sxi_copy_format(&item->ri_buf[0], &sxi_lip->sxi_format);
	if (error) {
		xfs_sxi_item_free(sxi_lip);
		return error;
	}
	xfs_trans_ail_insert(log->l_ailp, &sxi_lip->sxi_item, lsn);
	xfs_sxi_release(sxi_lip);
	return 0;
}

const struct xlog_recover_item_ops xlog_sxi_item_ops = {
	.item_type		= XFS_LI_SXI,
	.commit_pass2		= xlog_recover_sxi_commit_pass2,
};

/*
 * This routine is called when an SXD format structure is found in a committed
 * transaction in the log. Its purpose is to cancel the corresponding SXI if it
 * was still in the log. To do this it searches the AIL for the SXI with an id
 * equal to that in the SXD format structure. If we find it we drop the SXD
 * reference, which removes the SXI from the AIL and frees it.
 */
STATIC int
xlog_recover_sxd_commit_pass2(
	struct xlog			*log,
	struct list_head		*buffer_list,
	struct xlog_recover_item	*item,
	xfs_lsn_t			lsn)
{
	struct xfs_sxd_log_format	*sxd_formatp;

	sxd_formatp = item->ri_buf[0].i_addr;
	if (item->ri_buf[0].i_len != sizeof(struct xfs_sxd_log_format)) {
		XFS_ERROR_REPORT(__func__, XFS_ERRLEVEL_LOW, log->l_mp);
		return -EFSCORRUPTED;
	}

	xlog_recover_release_intent(log, XFS_LI_SXI, sxd_formatp->sxd_sxi_id);
	return 0;
}

const struct xlog_recover_item_ops xlog_sxd_item_ops = {
	.item_type		= XFS_LI_SXD,
	.commit_pass2		= xlog_recover_sxd_commit_pass2,
};
