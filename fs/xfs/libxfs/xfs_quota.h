// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_QUOTA_H__
#define __XFS_QUOTA_H__

#include "xfs_quota_defs.h"

/*
 * Kernel only quota definitions and functions
 */

struct xfs_trans;
struct xfs_buf;

/*
 * This check is done typically without holding the inode lock;
 * that may seem racy, but it is harmless in the context that it is used.
 * The inode cannot go inactive as long a reference is kept, and
 * therefore if dquot(s) were attached, they'll stay consistent.
 * If, for example, the ownership of the inode changes while
 * we didn't have the inode locked, the appropriate dquot(s) will be
 * attached atomically.
 */
#define XFS_NOT_DQATTACHED(mp, ip) \
	((XFS_IS_UQUOTA_ON(mp) && (ip)->i_udquot == NULL) || \
	 (XFS_IS_GQUOTA_ON(mp) && (ip)->i_gdquot == NULL) || \
	 (XFS_IS_PQUOTA_ON(mp) && (ip)->i_pdquot == NULL))

#define XFS_QM_NEED_QUOTACHECK(mp) \
	((XFS_IS_UQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & XFS_UQUOTA_CHKD) == 0) || \
	 (XFS_IS_GQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & XFS_GQUOTA_CHKD) == 0) || \
	 (XFS_IS_PQUOTA_ON(mp) && \
		(mp->m_sb.sb_qflags & XFS_PQUOTA_CHKD) == 0))

static inline uint
xfs_quota_chkd_flag(
	xfs_dqtype_t		type)
{
	switch (type) {
	case XFS_DQTYPE_USER:
		return XFS_UQUOTA_CHKD;
	case XFS_DQTYPE_GROUP:
		return XFS_GQUOTA_CHKD;
	case XFS_DQTYPE_PROJ:
		return XFS_PQUOTA_CHKD;
	default:
		return 0;
	}
}

#ifdef CONFIG_XFS_QUOTA
extern int xfs_qm_vop_dqalloc(struct xfs_inode *, kuid_t, kgid_t,
		prid_t, uint, struct xfs_dquot **, struct xfs_dquot **,
		struct xfs_dquot **);
extern void xfs_qm_vop_create_dqattach(struct xfs_trans *, struct xfs_inode *,
		struct xfs_dquot *, struct xfs_dquot *, struct xfs_dquot *);
extern int xfs_qm_vop_rename_dqattach(struct xfs_inode **);
extern struct xfs_dquot *xfs_qm_vop_chown(struct xfs_trans *,
		struct xfs_inode *, struct xfs_dquot **, struct xfs_dquot *);
extern int xfs_qm_dqattach(struct xfs_inode *);
extern int xfs_qm_dqattach_locked(struct xfs_inode *ip, bool doalloc);
extern void xfs_qm_dqdetach(struct xfs_inode *);
extern void xfs_qm_dqrele(struct xfs_dquot *);
extern void xfs_qm_statvfs(struct xfs_inode *, struct kstatfs *);
extern int xfs_qm_newmount(struct xfs_mount *, uint *, uint *);
extern void xfs_qm_mount_quotas(struct xfs_mount *);
extern void xfs_qm_unmount(struct xfs_mount *);
extern void xfs_qm_unmount_quotas(struct xfs_mount *);
bool xfs_inode_near_dquot_enforcement(struct xfs_inode *ip, xfs_dqtype_t type);
#else
static inline int
xfs_qm_vop_dqalloc(struct xfs_inode *ip, kuid_t kuid, kgid_t kgid,
		prid_t prid, uint flags, struct xfs_dquot **udqp,
		struct xfs_dquot **gdqp, struct xfs_dquot **pdqp)
{
	*udqp = NULL;
	*gdqp = NULL;
	*pdqp = NULL;
	return 0;
}

#define xfs_qm_vop_create_dqattach(tp, ip, u, g, p)
#define xfs_qm_vop_rename_dqattach(it)					(0)
#define xfs_qm_vop_chown(tp, ip, old, new)				(NULL)
#define xfs_qm_dqattach(ip)						(0)
#define xfs_qm_dqattach_locked(ip, fl)					(0)
#define xfs_qm_dqdetach(ip)
#define xfs_qm_dqrele(d)			do { (d) = (d); } while(0)
#define xfs_qm_statvfs(ip, s)			do { } while(0)
#define xfs_qm_newmount(mp, a, b)					(0)
#define xfs_qm_mount_quotas(mp)
#define xfs_qm_unmount(mp)
#define xfs_qm_unmount_quotas(mp)
#define xfs_inode_near_dquot_enforcement(ip, type)			(false)
#endif /* CONFIG_XFS_QUOTA */

extern int xfs_mount_reset_sbqflags(struct xfs_mount *);

#endif	/* __XFS_QUOTA_H__ */
