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
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_inode.h"
#include "xfs_quota.h"
#include "xfs_qm.h"
#include "xfs_icache.h"
#include "xfs_bmap_util.h"
#include "xfs_iwalk.h"
#include "xfs_ialloc.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/repair.h"
#include "scrub/array.h"
#include "scrub/quotacheck.h"

/*
 * Live Quotacheck
 * ===============
 *
 * Quota counters are "summary" metadata, in the sense that they are computed
 * as the summation of the block usage counts for every file on the filesystem.
 * Therefore, we compute the correct icount, bcount, and rtbcount values by
 * creating a shadow quota counter structure and walking every inode.
 */

/* Set us up to scrub quota counters. */
int
xchk_setup_quotacheck(
	struct xfs_scrub	*sc)
{
	/* Not ready for general consumption yet. */
	return -EOPNOTSUPP;

	if (!XFS_IS_QUOTA_RUNNING(sc->mp) || !XFS_IS_QUOTA_ON(sc->mp))
		return -ENOENT;

	sc->buf = kmem_zalloc(sizeof(struct xqcheck), KM_NOFS | KM_MAYFAIL);
	if (!sc->buf)
		return -ENOMEM;

	sc->flags |= XCHK_HAS_QUOTAOFFLOCK;
	mutex_lock(&sc->mp->m_quotainfo->qi_quotaofflock);

	/* Re-check the quota flags once we're protected against quotaoff. */
	if (!XFS_IS_QUOTA_RUNNING(sc->mp) || !XFS_IS_QUOTA_ON(sc->mp))
		return -ENOENT;

	return xchk_setup_fs(sc);
}

/* Retrieve the shadow dquot for the given id. */
int
xqcheck_get_shadow_dquot(
	struct xfbma		*counts,
	xfs_dqid_t		id,
	struct xqcheck_dquot	*xcdq)
{
	int			error;

	error = xfbma_get(counts, id, xcdq);
	if (error == -ENODATA) {
		/*
		 * ENODATA means we tried to read beyond the end of the sparse
		 * array.  This isn't a big deal, just zero the incore record
		 * and return that.
		 */
		memset(xcdq, 0, sizeof(struct xqcheck_dquot));
		return 0;
	}
	return error;
}

/* Update an incore dquot information. */
static int
xqcheck_update_incore(
	struct xqcheck		*xqc,
	struct xfbma		*counts,
	xfs_dqid_t		id,
	int64_t			inodes,
	int64_t			nblks,
	int64_t			rtblks)
{
	struct xqcheck_dquot	xcdq;
	int			error;

	if (!counts)
		return 0;

	error = xqcheck_get_shadow_dquot(counts, id, &xcdq);
	if (error)
		return error;

	xcdq.icount += inodes;
	xcdq.bcount += nblks;
	xcdq.rtbcount += rtblks;

	error = xfbma_set(counts, id, &xcdq);
	if (error == -EFBIG) {
		/*
		 * EFBIG means we tried to store data at too high a byte offset
		 * in the sparse array.  IOWs, we cannot complete the check and
		 * must notify userspace that the check was incomplete.
		 */
		xchk_set_incomplete(xqc->sc);
		error = -ECANCELED;
	}
	return error;
}

/* Record this inode's quota usage in our shadow quota counter data. */
STATIC int
xqcheck_inode(
	struct xqcheck		*xqc,
	struct xfs_inode	*ip)
{
	struct xfs_trans	*tp = xqc->sc->tp;
	xfs_filblks_t		nblks, rtblks;
	uint			ilock_flags = 0;
	xfs_dqid_t		id;
	int			error;

	/* Figure out the data / rt device block counts. */
	ilock_flags = xfs_ilock_data_map_shared(ip);
	if (XFS_IS_REALTIME_INODE(ip)) {
		error = xfs_iread_extents(tp, ip, XFS_DATA_FORK);
		if (error)
			goto out_ilock;
	}
	xfs_inode_count_blocks(tp, ip, &nblks, &rtblks);

	/* Update the shadow dquot counters. */
	id = xfs_qm_id_for_quotatype(ip, XFS_DQTYPE_USER);
	error = xqcheck_update_incore(xqc, xqc->ucounts, id, 1, nblks, rtblks);
	if (error)
		goto out_ilock;

	id = xfs_qm_id_for_quotatype(ip, XFS_DQTYPE_GROUP);
	error = xqcheck_update_incore(xqc, xqc->gcounts, id, 1, nblks, rtblks);
	if (error)
		goto out_ilock;

	id = xfs_qm_id_for_quotatype(ip, XFS_DQTYPE_PROJ);
	error = xqcheck_update_incore(xqc, xqc->pcounts, id, 1, nblks, rtblks);

out_ilock:
	xfs_iunlock(ip, ilock_flags);
	return error;
}

/*
 * Advance ino to the next inode that the inobt thinks is allocated, being
 * careful to jump to the next AG and to skip quota inodes.  Advancing ino
 * effectively means that we've pushed the quotacheck scan forward, so set the
 * quotacheck cursor to (ino - 1) so that our shadow dquot tracking will track
 * inode allocations in that range once we release the AGI buffer.
 */
STATIC int
xqcheck_advance(
	struct xqcheck		*xqc,
	xfs_ino_t		*ino)
{
	struct xfs_scrub	*sc = xqc->sc;
	struct xfs_buf		*agi_bp;
	xfs_agnumber_t		agno;
	int			error;

next_ag:
	agno = XFS_INO_TO_AGNO(sc->mp, *ino);
	if (agno >= sc->mp->m_sb.sb_agcount) {
		*ino = NULLFSINO;
		return 0;
	}
	error = xfs_ialloc_read_agi(sc->mp, sc->tp, agno, &agi_bp);
	if (error)
		return error;

next_ino:
	error = xfs_iwalk_find_next(sc->mp, sc->tp, agi_bp, ino);
	if (error || *ino == NULLFSINO) {
		xfs_trans_brelse(sc->tp, agi_bp);
		if (error == -EAGAIN)
			goto next_ag;
		return error;
	}

	if (xfs_is_quota_inode(&sc->mp->m_sb, *ino))
		goto next_ino;

	xfs_trans_brelse(sc->tp, agi_bp);
	return error;
}

/* Walk all the allocated inodes and run a quota scan on them. */
STATIC int
xqcheck_collect_counts(
	struct xqcheck		*xqc)
{
	struct xfs_scrub	*sc = xqc->sc;
	struct xfs_inode	*ip;
	xfs_ino_t		ino = 0;
	int			flags = XFS_IGET_UNTRUSTED | XFS_IGET_DONTCACHE;
	unsigned int		retries = 20;
	int			error;

	while (!(error = xqcheck_advance(xqc, &ino)) && ino != NULLFSINO) {
		if (xchk_should_terminate(sc, &error))
			break;

		error = xfs_iget(sc->mp, sc->tp, ino, flags, 0, &ip);
		switch (error) {
		case 0:
			error = xqcheck_inode(xqc, ip);
			xfs_irele(ip);
			if (error)
				return error;
			retries = 20;
			break;
		case -ENOENT:
			/*¬
			 * It's possible that this inode has lost all of its
			 * links but hasn't yet been inactivated.  Try to push
			 * it towards inactivation.
			 */
			xfs_inodegc_flush_ino(xqc->sc->mp, ino);
			/* fall through */
		case -EINVAL:
			/*
			 * We thought the inode was allocated, but iget failed
			 * to find it.  This could be because the inobt lookup
			 * failed, or because there's an incore inode that
			 * thinks it's marked free.  Either way, we back up
			 * one inode and try to advance the cursor.
			 */
			ino--;
			if (--retries == 0) {
				xchk_set_incomplete(sc);
				return -ECANCELED;
			}
			delay(HZ / 10);
			break;
		default:
			return error;
		}
	}
	return error;
}

/*
 * Check the dquot data against what we observed.  Caller must hold the dquot
 * lock.
 */
STATIC int
xqcheck_compare_dquot(
	struct xfs_dquot	*dqp,
	xfs_dqtype_t		dqtype,
	void			*priv)
{
	struct xqcheck_dquot	xcdq;
	struct xqcheck		*xqc = priv;
	struct xfbma		*counts = xqcheck_counters_for(xqc, dqtype);
	int			error;

	error = xqcheck_get_shadow_dquot(counts, dqp->q_id, &xcdq);
	if (error)
		goto out_unlock;

	if (xcdq.icount != dqp->q_ino.count)
		xchk_qcheck_set_corrupt(xqc->sc, dqtype, dqp->q_id);

	if (xcdq.bcount != dqp->q_blk.count)
		xchk_qcheck_set_corrupt(xqc->sc, dqtype, dqp->q_id);

	if (xcdq.rtbcount != dqp->q_rtb.count)
		xchk_qcheck_set_corrupt(xqc->sc, dqtype, dqp->q_id);

	if (xqc->sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT) {
		error = -ECANCELED;
		goto out_unlock;
	}

out_unlock:
	return error;
}

/*
 * Walk all the observed dquots, and make sure there's a matching incore
 * dquot and that its counts match ours.
 */
STATIC int
xqcheck_walk_observations(
	struct xqcheck		*xqc,
	xfs_dqtype_t		dqtype)
{
	struct xqcheck_dquot	xcdq;
	struct xfs_dquot	*dqp;
	struct xfbma		*counts = xqcheck_counters_for(xqc, dqtype);
	uint64_t		nr = 0;
	int			error;

	if (!counts)
		return 0;

	while (!(error = xfbma_iter_get(counts, &nr, &xcdq))) {
		xfs_dqid_t	id = nr - 1;

		if (xchk_should_terminate(xqc->sc, &error))
			return error;

		error = xfs_qm_dqget(xqc->sc->mp, id, dqtype, false, &dqp);
		if (error == -ENOENT) {
			xchk_qcheck_set_corrupt(xqc->sc, dqtype, id);
			return 0;
		}
		if (error)
			return error;

		error = xqcheck_compare_dquot(dqp, dqtype, xqc);
		xfs_qm_dqput(dqp);
		if (error)
			return error;
	}

	/* ENODATA means we hit the end of the array. */
	if (error == -ENODATA)
		return 0;

	return error;
}

/* Compare the quota counters we observed against the live dquots. */
STATIC int
xqcheck_compare_dqtype(
	struct xqcheck		*xqc,
	xfs_dqtype_t		dqtype)
{
	struct xfs_scrub	*sc = xqc->sc;
	int			error;

	if (sc->sm->sm_flags & XFS_SCRUB_OFLAG_CORRUPT)
		return 0;

	/* If the quota CHKD flag is cleared, we need to repair this quota. */
	if (!(xfs_quota_chkd_flag(dqtype) & sc->mp->m_qflags)) {
		xchk_qcheck_set_corrupt(xqc->sc, dqtype, 0);
		return 0;
	}

	/* Compare what we observed against the actual dquots. */
	error = xfs_qm_dqiterate(sc->mp, dqtype, xqcheck_compare_dquot, xqc);
	if (error)
		return error;

	/* Walk all the observed dquots and compare to the incore ones. */
	return xqcheck_walk_observations(xqc, dqtype);
}

/* Tear down everything associated with a quotacheck. */
static void
xqcheck_teardown_scan(
	struct xqcheck		*xqc)
{
	if (xqc->pcounts) {
		xfbma_destroy(xqc->pcounts);
		xqc->pcounts = NULL;
	}

	if (xqc->gcounts) {
		xfbma_destroy(xqc->gcounts);
		xqc->gcounts = NULL;
	}

	if (xqc->ucounts) {
		xfbma_destroy(xqc->ucounts);
		xqc->ucounts = NULL;
	}

	xqc->sc = NULL;
}

/*
 * Scan all inodes in the entire filesystem to generate quota counter data.
 * If the scan is successful, the quota data will be left alive for a repair.
 * If any error occurs, we'll tear everything down.
 */
STATIC int
xqcheck_setup_scan(
	struct xfs_scrub	*sc,
	struct xqcheck		*xqc)
{
	int			error;

	ASSERT(xqc->sc == NULL);
	xqc->sc = sc;

	error = -ENOMEM;
	if (xfs_this_quota_on(sc->mp, XFS_DQTYPE_USER)) {
		xqc->ucounts = xfbma_init("user dquots",
				sizeof(struct xqcheck_dquot));
		if (!xqc->ucounts)
			goto out_teardown;
	}

	if (xfs_this_quota_on(sc->mp, XFS_DQTYPE_GROUP)) {
		xqc->gcounts = xfbma_init("group dquots",
				sizeof(struct xqcheck_dquot));
		if (!xqc->gcounts)
			goto out_teardown;
	}

	if (xfs_this_quota_on(sc->mp, XFS_DQTYPE_PROJ)) {
		xqc->pcounts = xfbma_init("proj dquots",
				sizeof(struct xqcheck_dquot));
		if (!xqc->pcounts)
			goto out_teardown;
	}

	/* Use deferred cleanup to pass the quota count data to repair. */
	sc->buf_cleanup = (void (*)(void *))xqcheck_teardown_scan;
	return 0;

out_teardown:
	xqcheck_teardown_scan(xqc);
	return error;
}

/* Scrub all counters for a given quota type. */
int
xchk_quotacheck(
	struct xfs_scrub	*sc)
{
	struct xqcheck		*xqc = sc->buf;
	int			error = 0;

	/* Check quota counters on the live filesystem. */
	error = xqcheck_setup_scan(sc, xqc);
	if (error)
		return error;

	/* Walk all inodes, picking up quota information. */
	error = xqcheck_collect_counts(xqc);
	if (!xchk_xref_process_error(sc, 0, 0, &error))
		return error;

	/* Compare quota counters. */
	if (xqc->ucounts) {
		error = xqcheck_compare_dqtype(xqc, XFS_DQTYPE_USER);
		if (!xchk_xref_process_error(sc, 0, 0, &error))
			return error;
	}
	if (xqc->gcounts) {
		error = xqcheck_compare_dqtype(xqc, XFS_DQTYPE_GROUP);
		if (!xchk_xref_process_error(sc, 0, 0, &error))
			return error;
	}
	if (xqc->pcounts) {
		error = xqcheck_compare_dqtype(xqc, XFS_DQTYPE_PROJ);
		if (!xchk_xref_process_error(sc, 0, 0, &error))
			return error;
	}

	return 0;
}
