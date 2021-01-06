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
#include "xfs_sb.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/repair.h"
#include "scrub/array.h"
#include "scrub/quotacheck.h"
#include "scrub/trace.h"

/*
 * Live Quotacheck Repair
 * ======================
 *
 * Use the live quota counter information that we collected to replace the
 * counter values in the incore dquots.  A scrub->repair cycle should have left
 * the live data and hooks active, so this is safe so long as we make sure the
 * dquot is locked.
 */

/* Commit new counters to a dquot. */
static int
xqcheck_commit_dquot(
	struct xfs_dquot	*dqp,
	xfs_dqtype_t		dqtype,
	void			*priv)
{
	struct xqcheck_dquot	xcdq;
	struct xqcheck		*xqc = priv;
	struct xfbma		*counts = xqcheck_counters_for(xqc, dqtype);
	int64_t			delta;
	bool			dirty = false;
	int			error = 0;

	/* Unlock the dquot just long enough to allocate a transaction. */
	xfs_dqunlock(dqp);
	error = xchk_trans_alloc(xqc->sc, 0);
	xfs_dqlock(dqp);
	if (error)
		return error;
	xfs_trans_dqjoin(xqc->sc->tp, dqp);

	mutex_lock(&xqc->lock);
	if (xqc->hook_dead) {
		mutex_unlock(&xqc->lock);
		xfs_trans_cancel(xqc->sc->tp);
		error = -ECANCELED;
		goto out;
	}
	error = xqcheck_get_shadow_dquot(counts, dqp->q_id, &xcdq);
	if (error) {
		mutex_unlock(&xqc->lock);
		xfs_trans_cancel(xqc->sc->tp);
		goto out;
	}

	/* Adjust counters as needed. */
	delta = (int64_t)xcdq.icount - dqp->q_ino.count;
	if (delta) {
		dqp->q_ino.reserved += delta;
		dqp->q_ino.count += delta;
		dirty = true;
	}

	delta = (int64_t)xcdq.bcount - dqp->q_blk.count;
	if (delta) {
		dqp->q_blk.reserved += delta;
		dqp->q_blk.count += delta;
		dirty = true;
	}

	delta = (int64_t)xcdq.rtbcount - dqp->q_rtb.count;
	if (delta) {
		dqp->q_rtb.reserved += delta;
		dqp->q_rtb.count += delta;
		dirty = true;
	}
	mutex_unlock(&xqc->lock);

	if (!dirty) {
		xfs_trans_cancel(xqc->sc->tp);
		goto out;
	}

	trace_xrep_quotacheck_dquot(xqc->sc->mp, dqp->q_type, dqp->q_id);

	/* Commit the dirty dquot to disk. */
	dqp->q_flags |= XFS_DQFLAG_DIRTY;
	if (dqp->q_id)
		xfs_qm_adjust_dqtimers(dqp);
	xfs_trans_log_dquot(xqc->sc->tp, dqp);

	error = xfs_trans_commit(xqc->sc->tp);
out:
	xqc->sc->tp = NULL;
	/*
	 * Transaction commit unlocks the dquot, so we must re-lock it so that
	 * the caller can put the reference (which apparently requires a locked
	 * dq...)
	 */
	xfs_dqlock(dqp);
	return error;
}

/* Commit new quota counters for a particular quota type. */
STATIC int
xqcheck_commit_dqtype(
	struct xqcheck		*xqc,
	unsigned int		dqtype)
{
	struct xqcheck_dquot	xcdq;
	struct xfs_scrub	*sc = xqc->sc;
	struct xfs_mount	*mp = sc->mp;
	struct xfbma		*counts = xqcheck_counters_for(xqc, dqtype);
	struct xfs_dquot	*dqp;
	uint64_t		nr = 0;
	int			error;

	/*
	 * Update the counters of every dquot that the quota file knows about.
	 */
	error = xfs_qm_dqiterate(mp, dqtype, xqcheck_commit_dquot, xqc);
	if (error)
		return error;

	/*
	 * Make a second pass to deal with the dquots that we know about but
	 * the quota file previously did not know about.
	 */
	mutex_lock(&xqc->lock);
	while (!(error = xfbma_iter_get(counts, &nr, &xcdq))) {
		xfs_dqid_t	id = nr - 1;

		mutex_unlock(&xqc->lock);

		/*
		 * Grab the dquot, allowing for dquot block allocation in a
		 * separate transaction.  We committed the scrub transaction
		 * in a previous step, so we will not be creating nested
		 * transactions here.
		 */
		error = xfs_qm_dqget(mp, id, dqtype, true, &dqp);
		if (error)
			return error;

		error = xqcheck_commit_dquot(dqp, dqtype, xqc);
		xfs_qm_dqput(dqp);
		if (error)
			return error;

		mutex_lock(&xqc->lock);
	}
	mutex_unlock(&xqc->lock);

	/* ENODATA means we hit the end of the array. */
	if (error == -ENODATA)
		return 0;

	return error;
}

/* Figure out quota CHKD flags for the running quota types. */
static inline unsigned int
xqcheck_chkd_flags(
	struct xfs_mount	*mp)
{
	unsigned int		ret = 0;

	if (XFS_IS_UQUOTA_ON(mp))
		ret |= XFS_UQUOTA_CHKD;
	if (XFS_IS_GQUOTA_ON(mp))
		ret |= XFS_GQUOTA_CHKD;
	if (XFS_IS_PQUOTA_ON(mp))
		ret |= XFS_PQUOTA_CHKD;
	return ret;
}

/* Commit the new dquot counters. */
int
xrep_quotacheck(
	struct xfs_scrub	*sc)
{
	struct xqcheck		*xqc = sc->buf;
	unsigned int		qflags = xqcheck_chkd_flags(sc->mp);
	int			error;

	/*
	 * Clear the CHKD flag for this quota type and commit the scrub
	 * transaction so that we can allocate new quota block mappings if we
	 * have to.  If we crash after this point, the sb still has the CHKD
	 * flags cleared, so mount quotacheck will fix all of this up.
	 */
	spin_lock(&sc->mp->m_sb_lock);
	sc->mp->m_qflags &= ~qflags;
	sc->mp->m_sb.sb_qflags &= ~qflags;
	spin_unlock(&sc->mp->m_sb_lock);
	xfs_log_sb(sc->tp);

	error = xfs_trans_commit(sc->tp);
	sc->tp = NULL;
	if (error)
		return error;

	/* Commit the new counters to the dquots. */
	if (xqc->ucounts) {
		error = xqcheck_commit_dqtype(xqc, XFS_DQTYPE_USER);
		if (error)
			return error;
	}
	if (xqc->gcounts) {
		error = xqcheck_commit_dqtype(xqc, XFS_DQTYPE_GROUP);
		if (error)
			return error;
	}
	if (xqc->pcounts) {
		error = xqcheck_commit_dqtype(xqc, XFS_DQTYPE_PROJ);
		if (error)
			return error;
	}

	/* Reinstate CHKD flags. */
	error = xchk_trans_alloc(sc, 0);
	if (error)
		return error;

	spin_lock(&sc->mp->m_sb_lock);
	sc->mp->m_qflags |= qflags;
	sc->mp->m_sb.sb_qflags |= qflags;
	spin_unlock(&sc->mp->m_sb_lock);
	xfs_log_sb(sc->tp);

	return 0;
}
