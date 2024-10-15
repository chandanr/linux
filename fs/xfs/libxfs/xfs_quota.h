// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2000-2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef __XFS_QUOTA_H__
#define __XFS_QUOTA_H__

/*
 * Even though users may not have quota limits occupying all 64-bits,
 * they may need 64-bit accounting. Hence, 64-bit quota-counters,
 * and quota-limits. This is a waste in the common case, but hey ...
 */
typedef uint64_t	xfs_qcnt_t;

typedef uint8_t		xfs_dqtype_t;

#define XFS_DQTYPE_STRINGS \
	{ XFS_DQTYPE_USER,	"USER" }, \
	{ XFS_DQTYPE_PROJ,	"PROJ" }, \
	{ XFS_DQTYPE_GROUP,	"GROUP" }, \
	{ XFS_DQTYPE_BIGTIME,	"BIGTIME" }

/*
 * flags for q_flags field in the dquot.
 */
#define XFS_DQFLAG_DIRTY	(1u << 0)	/* dquot is dirty */
#define XFS_DQFLAG_FREEING	(1u << 1)	/* dquot is being torn down */

#define XFS_DQFLAG_STRINGS \
	{ XFS_DQFLAG_DIRTY,	"DIRTY" }, \
	{ XFS_DQFLAG_FREEING,	"FREEING" }

#define XFS_IS_QUOTA_ON(mp)		((mp)->m_qflags & XFS_ALL_QUOTA_ACCT)
#define XFS_IS_UQUOTA_ON(mp)		((mp)->m_qflags & XFS_UQUOTA_ACCT)
#define XFS_IS_PQUOTA_ON(mp)		((mp)->m_qflags & XFS_PQUOTA_ACCT)
#define XFS_IS_GQUOTA_ON(mp)		((mp)->m_qflags & XFS_GQUOTA_ACCT)
#define XFS_IS_UQUOTA_ENFORCED(mp)	((mp)->m_qflags & XFS_UQUOTA_ENFD)
#define XFS_IS_GQUOTA_ENFORCED(mp)	((mp)->m_qflags & XFS_GQUOTA_ENFD)
#define XFS_IS_PQUOTA_ENFORCED(mp)	((mp)->m_qflags & XFS_PQUOTA_ENFD)


/*
 * Flags to tell various functions what to do. Not all of these are meaningful
 * to a single function. None of these XFS_QMOPT_* flags are meant to have
 * persistent values (ie. their values can and will change between versions)
 */
#define XFS_QMOPT_UQUOTA	(1u << 0) /* user dquot requested */
#define XFS_QMOPT_GQUOTA	(1u << 1) /* group dquot requested */
#define XFS_QMOPT_PQUOTA	(1u << 2) /* project dquot requested */
#define XFS_QMOPT_FORCE_RES	(1u << 3) /* ignore quota limits */
#define XFS_QMOPT_SBVERSION	(1u << 4) /* change superblock version num */

/*
 * flags to xfs_trans_mod_dquot to indicate which field needs to be
 * modified.
 */
#define XFS_QMOPT_RES_REGBLKS	(1u << 7)
#define XFS_QMOPT_RES_RTBLKS	(1u << 8)
#define XFS_QMOPT_BCOUNT	(1u << 9)
#define XFS_QMOPT_ICOUNT	(1u << 10)
#define XFS_QMOPT_RTBCOUNT	(1u << 11)
#define XFS_QMOPT_DELBCOUNT	(1u << 12)
#define XFS_QMOPT_DELRTBCOUNT	(1u << 13)
#define XFS_QMOPT_RES_INOS	(1u << 14)

/*
 * flags for dqalloc.
 */
#define XFS_QMOPT_INHERIT	(1u << 31)

#define XFS_QMOPT_FLAGS \
	{ XFS_QMOPT_UQUOTA,		"UQUOTA" }, \
	{ XFS_QMOPT_PQUOTA,		"PQUOTA" }, \
	{ XFS_QMOPT_FORCE_RES,		"FORCE_RES" }, \
	{ XFS_QMOPT_SBVERSION,		"SBVERSION" }, \
	{ XFS_QMOPT_GQUOTA,		"GQUOTA" }, \
	{ XFS_QMOPT_INHERIT,		"INHERIT" }, \
	{ XFS_QMOPT_RES_REGBLKS,	"RES_REGBLKS" }, \
	{ XFS_QMOPT_RES_RTBLKS,		"RES_RTBLKS" }, \
	{ XFS_QMOPT_BCOUNT,		"BCOUNT" }, \
	{ XFS_QMOPT_ICOUNT,		"ICOUNT" }, \
	{ XFS_QMOPT_RTBCOUNT,		"RTBCOUNT" }, \
	{ XFS_QMOPT_DELBCOUNT,		"DELBCOUNT" }, \
	{ XFS_QMOPT_DELRTBCOUNT,	"DELRTBCOUNT" }, \
	{ XFS_QMOPT_RES_INOS,		"RES_INOS" }


#define XFS_QMOPT_QUOTALL	\
		(XFS_QMOPT_UQUOTA | XFS_QMOPT_PQUOTA | XFS_QMOPT_GQUOTA)
#define XFS_QMOPT_RESBLK_MASK	(XFS_QMOPT_RES_REGBLKS | XFS_QMOPT_RES_RTBLKS)

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

struct xfs_dquot;

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
