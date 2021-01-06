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
#include "xfs_btree.h"
#include "xfs_bit.h"
#include "xfs_log_format.h"
#include "xfs_trans.h"
#include "xfs_sb.h"
#include "xfs_inode.h"
#include "xfs_inode_fork.h"
#include "xfs_alloc.h"
#include "xfs_bmap.h"
#include "xfs_quota.h"
#include "xfs_qm.h"
#include "xfs_dquot.h"
#include "xfs_dquot_item.h"
#include "xfs_reflink.h"
#include "scrub/xfs_scrub.h"
#include "scrub/scrub.h"
#include "scrub/common.h"
#include "scrub/quota.h"
#include "scrub/trace.h"
#include "scrub/repair.h"

/*
 * Quota Repair
 * ============
 *
 * Quota repairs are fairly simplistic; we fix everything that the dquot
 * verifiers complain about, cap any counters or limits that make no sense,
 * and schedule a quotacheck if we had to fix anything.  We also repair any
 * data fork extent records that don't apply to metadata files.
 */

struct xrep_quota_info {
	struct xfs_scrub	*sc;
	bool			need_quotacheck;
};

/* Scrub the fields in an individual quota item. */
STATIC int
xrep_quota_item(
	struct xfs_dquot	*dqp,
	xfs_dqtype_t		dqtype,
	void			*priv)
{
	struct xrep_quota_info	*rqi = priv;
	struct xfs_scrub	*sc = rqi->sc;
	struct xfs_mount	*mp = sc->mp;
	xfs_ino_t		fs_icount;
	bool			dirty = false;
	int			error;

	/* Check the limits. */
	if (dqp->q_blk.softlimit > dqp->q_blk.hardlimit) {
		dqp->q_blk.softlimit = dqp->q_blk.hardlimit;
		dirty = true;
	}

	if (dqp->q_ino.softlimit > dqp->q_ino.hardlimit) {
		dqp->q_ino.softlimit = dqp->q_ino.hardlimit;
		dirty = true;
	}

	if (dqp->q_rtb.softlimit > dqp->q_rtb.hardlimit) {
		dqp->q_rtb.softlimit = dqp->q_rtb.hardlimit;
		dirty = true;
	}

	/*
	 * Check that usage doesn't exceed physical limits.  However, on
	 * a reflink filesystem we're allowed to exceed physical space
	 * if there are no quota limits.  We don't know what the real number
	 * is, but we can make quotacheck find out for us.
	 */
	if (!xfs_sb_version_hasreflink(&mp->m_sb) &&
	    dqp->q_blk.count > mp->m_sb.sb_dblocks) {
		dqp->q_blk.reserved -= dqp->q_blk.count;
		dqp->q_blk.reserved += mp->m_sb.sb_dblocks;
		dqp->q_blk.count = mp->m_sb.sb_dblocks;
		rqi->need_quotacheck = true;
		dirty = true;
	}
	fs_icount = percpu_counter_sum(&mp->m_icount);
	if (dqp->q_ino.count > fs_icount) {
		dqp->q_ino.reserved -= dqp->q_ino.count;
		dqp->q_ino.reserved += fs_icount;
		dqp->q_ino.count = fs_icount;
		rqi->need_quotacheck = true;
		dirty = true;
	}
	if (dqp->q_rtb.count > mp->m_sb.sb_rblocks) {
		dqp->q_rtb.reserved -= dqp->q_rtb.count;
		dqp->q_rtb.reserved += mp->m_sb.sb_rblocks;
		dqp->q_rtb.count = mp->m_sb.sb_rblocks;
		rqi->need_quotacheck = true;
		dirty = true;
	}

	if (!dirty)
		return 0;

	trace_xrep_dquot_item(sc->mp, dqp->q_type, dqp->q_id);

	dqp->q_flags |= XFS_DQFLAG_DIRTY;
	xfs_trans_dqjoin(sc->tp, dqp);
	if (dqp->q_id) {
		xfs_qm_adjust_dqlimits(dqp);
		xfs_qm_adjust_dqtimers(dqp);
	}
	xfs_trans_log_dquot(sc->tp, dqp);
	error = xfs_trans_roll(&sc->tp);
	xfs_dqlock(dqp);
	return error;
}

/* Fix a quota timer so that we can pass the verifier. */
STATIC void
xrep_quota_fix_timer(
	struct xfs_mount	*mp,
	__be64			softlimit,
	__be64			countnow,
	__be32			*timer,
	time64_t		timelimit)
{
	uint64_t		soft = be64_to_cpu(softlimit);
	uint64_t		count = be64_to_cpu(countnow);
	time64_t		new_timer;

	if (!soft || count <= soft || *timer != 0)
		return;

	new_timer = xfs_dquot_set_timeout(mp,
				ktime_get_real_seconds() + timelimit);
	*timer = cpu_to_be32(new_timer);
}

/* Fix anything the verifiers complain about. */
STATIC int
xrep_quota_block(
	struct xfs_scrub	*sc,
	xfs_daddr_t		daddr,
	xfs_dqtype_t		dqtype,
	xfs_dqid_t		id)
{
	struct xfs_dqblk	*dqblk;
	struct xfs_disk_dquot	*ddq;
	struct xfs_quotainfo	*qi = sc->mp->m_quotainfo;
	struct xfs_def_quota	*defq = xfs_get_defquota(qi, dqtype);
	struct xfs_buf		*bp = NULL;
	enum xfs_blft		buftype = 0;
	int			i;
	int			error;

	error = xfs_trans_read_buf(sc->mp, sc->tp, sc->mp->m_ddev_targp, daddr,
			qi->qi_dqchunklen, 0, &bp, &xfs_dquot_buf_ops);
	switch (error) {
	case -EFSBADCRC:
	case -EFSCORRUPTED:
		/* Failed verifier, retry read with no ops. */
		error = xfs_trans_read_buf(sc->mp, sc->tp,
				sc->mp->m_ddev_targp, daddr, qi->qi_dqchunklen,
				0, &bp, NULL);
		if (error)
			return error;
		break;
	case 0:
		dqblk = bp->b_addr;
		ddq = &dqblk[0].dd_diskdq;

		/*
		 * If there's nothing that would impede a dqiterate, we're
		 * done.
		 */
		if ((ddq->d_type & XFS_DQTYPE_REC_MASK) != dqtype ||
		    id == be32_to_cpu(ddq->d_id)) {
			xfs_trans_brelse(sc->tp, bp);
			return 0;
		}
		break;
	default:
		return error;
	}

	/* Something's wrong with the block, fix the whole thing. */
	dqblk = bp->b_addr;
	bp->b_ops = &xfs_dquot_buf_ops;
	for (i = 0; i < qi->qi_dqperchunk; i++, dqblk++) {
		ddq = &dqblk->dd_diskdq;

		trace_xrep_disk_dquot(sc->mp, dqtype, id + i);

		ddq->d_magic = cpu_to_be16(XFS_DQUOT_MAGIC);
		ddq->d_version = XFS_DQUOT_VERSION;
		ddq->d_type = dqtype;
		ddq->d_id = cpu_to_be32(id + i);

		xrep_quota_fix_timer(sc->mp, ddq->d_blk_softlimit,
				ddq->d_bcount, &ddq->d_btimer,
				defq->blk.time);

		xrep_quota_fix_timer(sc->mp, ddq->d_ino_softlimit,
				ddq->d_icount, &ddq->d_itimer,
				defq->ino.time);

		xrep_quota_fix_timer(sc->mp, ddq->d_rtb_softlimit,
				ddq->d_rtbcount, &ddq->d_rtbtimer,
				defq->rtb.time);

		/* We only support v5 filesystems so always set these. */
		uuid_copy(&dqblk->dd_uuid, &sc->mp->m_sb.sb_meta_uuid);
		xfs_update_cksum((char *)dqblk, sizeof(struct xfs_dqblk),
				 XFS_DQUOT_CRC_OFF);
		dqblk->dd_lsn = 0;
	}
	switch (dqtype) {
	case XFS_DQTYPE_USER:
		buftype = XFS_BLFT_UDQUOT_BUF;
		break;
	case XFS_DQTYPE_GROUP:
		buftype = XFS_BLFT_GDQUOT_BUF;
		break;
	case XFS_DQTYPE_PROJ:
		buftype = XFS_BLFT_PDQUOT_BUF;
		break;
	}
	xfs_trans_buf_set_type(sc->tp, bp, buftype);
	xfs_trans_log_buf(sc->tp, bp, 0, BBTOB(bp->b_length) - 1);
	return xrep_roll_trans(sc);
}

/*
 * Repair a quota file's data fork.  The function returns with the inode
 * joined.
 */
STATIC int
xrep_quota_data_fork(
	struct xfs_scrub	*sc,
	xfs_dqtype_t		dqtype)
{
	struct xfs_bmbt_irec	irec = { 0 };
	struct xfs_iext_cursor	icur;
	struct xfs_quotainfo	*qi = sc->mp->m_quotainfo;
	struct xfs_ifork	*ifp;
	xfs_fileoff_t		max_dqid_off;
	xfs_fileoff_t		off;
	xfs_fsblock_t		fsbno;
	bool			truncate = false;
	int			error = 0;

	error = xrep_metadata_inode_forks(sc);
	if (error)
		goto out;

	/* Check for data fork problems that apply only to quota files. */
	max_dqid_off = ((xfs_dqid_t)-1) / qi->qi_dqperchunk;
	ifp = XFS_IFORK_PTR(sc->ip, XFS_DATA_FORK);
	for_each_xfs_iext(ifp, &icur, &irec) {
		if (isnullstartblock(irec.br_startblock)) {
			error = -EFSCORRUPTED;
			goto out;
		}

		if (irec.br_startoff > max_dqid_off ||
		    irec.br_startoff + irec.br_blockcount - 1 > max_dqid_off) {
			truncate = true;
			break;
		}

		/* Convert unwritten extents to real ones. */
		if (irec.br_state == XFS_EXT_UNWRITTEN) {
			struct xfs_bmbt_irec	nrec;
			int			nmap = 1;

			xfs_trans_ijoin(sc->tp, sc->ip, 0);

			error = xfs_bmapi_write(sc->tp, sc->ip,
					irec.br_startoff, irec.br_blockcount,
					XFS_BMAPI_CONVERT, 0, &nrec, &nmap);
			if (error)
				goto out;
			ASSERT(nmap == 1);
			ASSERT(nrec.br_startoff == irec.br_startoff);
			ASSERT(nrec.br_blockcount == irec.br_blockcount);

			error = xrep_roll_trans(sc);
			if (error)
				goto out;
		}
	}

	xfs_trans_ijoin(sc->tp, sc->ip, 0);

	if (truncate) {
		/* Erase everything after the block containing the max dquot */
		error = xfs_bunmapi_range(&sc->tp, sc->ip, 0,
				max_dqid_off * sc->mp->m_sb.sb_blocksize,
				XFS_MAX_FILEOFF);
		if (error)
			goto out;

		/* Remove all CoW reservations. */
		error = xfs_reflink_cancel_cow_blocks(sc->ip, &sc->tp, 0,
				XFS_MAX_FILEOFF, true);
		if (error)
			goto out;
		sc->ip->i_diflags2 &= ~XFS_DIFLAG2_REFLINK;

		/*
		 * Always re-log the inode so that our permanent transaction
		 * can keep on rolling it forward in the log.
		 */
		xfs_trans_log_inode(sc->tp, sc->ip, XFS_ILOG_CORE);
	}

	/* Now go fix anything that fails the verifiers. */
	for_each_xfs_iext(ifp, &icur, &irec) {
		for (fsbno = irec.br_startblock, off = irec.br_startoff;
		     fsbno < irec.br_startblock + irec.br_blockcount;
		     fsbno += XFS_DQUOT_CLUSTER_SIZE_FSB,
				off += XFS_DQUOT_CLUSTER_SIZE_FSB) {
			error = xrep_quota_block(sc,
					XFS_FSB_TO_DADDR(sc->mp, fsbno),
					dqtype, off * qi->qi_dqperchunk);
			if (error)
				goto out;
		}
	}

out:
	return error;
}

/*
 * Go fix anything in the quota items that we could have been mad about.  Now
 * that we've checked the quota inode data fork we have to drop ILOCK_EXCL to
 * use the regular dquot functions.
 */
STATIC int
xrep_quota_problems(
	struct xfs_scrub	*sc,
	xfs_dqtype_t		dqtype)
{
	struct xrep_quota_info	rqi;
	int			error;

	rqi.sc = sc;
	rqi.need_quotacheck = false;
	error = xfs_qm_dqiterate(sc->mp, dqtype, xrep_quota_item, &rqi);
	if (error)
		return error;

	/* Make a quotacheck happen. */
	if (rqi.need_quotacheck)
		xrep_force_quotacheck(sc, dqtype);
	return 0;
}

/* Repair all of a quota type's items. */
int
xrep_quota(
	struct xfs_scrub	*sc)
{
	xfs_dqtype_t		dqtype;
	int			error;

	dqtype = xchk_quota_to_dqtype(sc);

	/*
	 * Re-take the ILOCK so that we can fix any problems that we found
	 * with the data fork mappings, or with the dquot bufs themselves.
	 */
	if (sc->ilock_flags == 0) {
		sc->ilock_flags = XFS_ILOCK_EXCL;
		xfs_ilock(sc->ip, sc->ilock_flags);
	}
	error = xrep_quota_data_fork(sc, dqtype);
	if (error)
		goto out;

	/*
	 * Roll the transaction to unjoin the quota inode from transaction so
	 * that we can unlock the quota inode; we play only with dquots from
	 * now on.
	 */
	error = xfs_trans_roll(&sc->tp);
	if (error)
		goto out;
	xfs_iunlock(sc->ip, sc->ilock_flags);
	sc->ilock_flags = 0;

	/* Fix anything the dquot verifiers don't complain about. */
	error = xrep_quota_problems(sc, dqtype);
out:
	return error;
}
