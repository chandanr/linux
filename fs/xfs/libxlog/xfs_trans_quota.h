#ifndef	__XFS_TRANS_QUOTA_H
#define __XFS_TRANS_QUOTA_H

/*
 * The structure kept inside the xfs_trans_t keep track of dquot changes
 * within a transaction and apply them later.
 */
struct xfs_dqtrx {
	struct xfs_dquot *qt_dquot;	  /* the dquot this refers to */

	uint64_t	qt_blk_res;	  /* blks reserved on a dquot */
	int64_t		qt_bcount_delta;  /* dquot blk count changes */
	int64_t		qt_delbcnt_delta; /* delayed dquot blk count changes */

	uint64_t	qt_rtblk_res;	  /* # blks reserved on a dquot */
	uint64_t	qt_rtblk_res_used;/* # blks used from reservation */
	int64_t		qt_rtbcount_delta;/* dquot realtime blk changes */
	int64_t		qt_delrtb_delta;  /* delayed RT blk count changes */

	uint64_t	qt_ino_res;	  /* inode reserved on a dquot */
	uint64_t	qt_ino_res_used;  /* inodes used from the reservation */
	int64_t		qt_icount_delta;  /* dquot inode count changes */
};

#ifdef CONFIG_XFS_QUOTA
extern void xfs_trans_dup_dqinfo(struct xfs_trans *, struct xfs_trans *);
extern void xfs_trans_free_dqinfo(struct xfs_trans *);
extern void xfs_trans_mod_dquot_byino(struct xfs_trans *, struct xfs_inode *,
		uint, int64_t);
extern void xfs_trans_apply_dquot_deltas(struct xfs_trans *);
extern void xfs_trans_unreserve_and_mod_dquots(struct xfs_trans *);
int xfs_trans_reserve_quota_nblks(struct xfs_trans *tp, struct xfs_inode *ip,
		int64_t dblocks, int64_t rblocks, bool force);
extern int xfs_trans_reserve_quota_bydquots(struct xfs_trans *,
		struct xfs_mount *, struct xfs_dquot *,
		struct xfs_dquot *, struct xfs_dquot *, int64_t, long, uint);
int xfs_trans_reserve_quota_icreate(struct xfs_trans *tp,
		struct xfs_dquot *udqp, struct xfs_dquot *gdqp,
		struct xfs_dquot *pdqp, int64_t dblocks);
static inline int
xfs_quota_reserve_blkres(struct xfs_inode *ip, int64_t blocks)
{
	return xfs_trans_reserve_quota_nblks(NULL, ip, blocks, 0, false);
}

#else

#define xfs_trans_dup_dqinfo(tp, tp2)
#define xfs_trans_free_dqinfo(tp)
#define xfs_trans_mod_dquot_byino(tp, ip, fields, delta) do { } while (0)
#define xfs_trans_apply_dquot_deltas(tp)
#define xfs_trans_unreserve_and_mod_dquots(tp)
static inline int xfs_trans_reserve_quota_nblks(struct xfs_trans *tp,
		struct xfs_inode *ip, int64_t dblocks, int64_t rblocks,
		bool force)
{
	return 0;
}

static inline int xfs_trans_reserve_quota_bydquots(struct xfs_trans *tp,
		struct xfs_mount *mp, struct xfs_dquot *udqp,
		struct xfs_dquot *gdqp, struct xfs_dquot *pdqp,
		int64_t nblks, long nions, uint flags)
{
	return 0;
}

static inline int
xfs_quota_reserve_blkres(struct xfs_inode *ip, int64_t blocks)
{
	return xfs_trans_reserve_quota_nblks(NULL, ip, blocks, 0, false);
}

static inline int
xfs_trans_reserve_quota_icreate(struct xfs_trans *tp, struct xfs_dquot *udqp,
		struct xfs_dquot *gdqp, struct xfs_dquot *pdqp, int64_t dblocks)
{
	return 0;
}

#endif

static inline int
xfs_quota_unreserve_blkres(struct xfs_inode *ip, int64_t blocks)
{
	return xfs_quota_reserve_blkres(ip, -blocks);
}

#endif	/* __XFS_TRANS_QUOTA_H */
