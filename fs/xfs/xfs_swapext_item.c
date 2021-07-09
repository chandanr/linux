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
#include "xfs_log.h"
#include "xfs_bmap.h"
#include "xfs_icache.h"
#include "xfs_trans_space.h"
#include "xfs_error.h"
#include "xfs_log_priv.h"
#include "xfs_log_recover.h"

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

/* Process a swapext update intent item that was recovered from the log. */
STATIC int
xfs_sxi_item_recover(
	struct xfs_log_item		*lip,
	struct list_head		*capture_list)
{
	return -EFSCORRUPTED;
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
	ASSERT(0);
	return NULL;
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
