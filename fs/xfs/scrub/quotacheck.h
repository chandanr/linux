/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_SCRUB_QUOTACHECK_H__
#define __XFS_SCRUB_QUOTACHECK_H__

/*
 * Quota counters for live quotacheck.  Pad the structure to 32 bytes to avoid
 * a weird interaction between sparse xfbma arrays and shmem files, and so that
 * we never mistake a zero-count xchk_dquot for a null record.
 */
struct xqcheck_dquot {
	/* block usage count */
	int64_t			bcount;

	/* inode usage count */
	int64_t			icount;

	/* realtime block usage count */
	int64_t			rtbcount;
};

/* Live quotacheck control structure. */
struct xqcheck {
	struct xfs_scrub	*sc;

	/* Shadow dquot counter data. */
	struct xfbma		*ucounts;
	struct xfbma		*gcounts;
	struct xfbma		*pcounts;
};

/* Return the incore counter array for a given quota type. */
static inline struct xfbma *
xqcheck_counters_for(
	struct xqcheck		*xqc,
	xfs_dqtype_t		dqtype)
{
	switch (dqtype) {
	case XFS_DQTYPE_USER:
		return xqc->ucounts;
	case XFS_DQTYPE_GROUP:
		return xqc->gcounts;
	case XFS_DQTYPE_PROJ:
		return xqc->pcounts;
	}

	ASSERT(0);
	return NULL;
}

int xqcheck_get_shadow_dquot(struct xfbma *counts, xfs_dqid_t id,
		struct xqcheck_dquot *xcdq);

#endif /* __XFS_SCRUB_QUOTACHECK_H__ */
