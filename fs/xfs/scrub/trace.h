// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <darrick.wong@oracle.com>
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM xfs_scrub

#if !defined(_TRACE_XFS_SCRUB_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_XFS_SCRUB_TRACE_H

#include <linux/tracepoint.h>
#include "xfs_bit.h"

struct xfile;

/*
 * ftrace's __print_symbolic requires that all enum values be wrapped in the
 * TRACE_DEFINE_ENUM macro so that the enum value can be encoded in the ftrace
 * ring buffer.  Somehow this was only worth mentioning in the ftrace sample
 * code.
 */
TRACE_DEFINE_ENUM(XFS_BTNUM_BNOi);
TRACE_DEFINE_ENUM(XFS_BTNUM_CNTi);
TRACE_DEFINE_ENUM(XFS_BTNUM_BMAPi);
TRACE_DEFINE_ENUM(XFS_BTNUM_INOi);
TRACE_DEFINE_ENUM(XFS_BTNUM_FINOi);
TRACE_DEFINE_ENUM(XFS_BTNUM_RMAPi);
TRACE_DEFINE_ENUM(XFS_BTNUM_REFCi);

TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_PROBE);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_SB);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_AGF);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_AGFL);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_AGI);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_BNOBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_CNTBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_INOBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_FINOBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_RMAPBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_REFCNTBT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_INODE);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_BMBTD);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_BMBTA);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_BMBTC);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_DIR);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_XATTR);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_SYMLINK);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_PARENT);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_RTBITMAP);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_RTSUM);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_UQUOTA);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_GQUOTA);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_PQUOTA);
TRACE_DEFINE_ENUM(XFS_SCRUB_TYPE_FSCOUNTERS);

#define XFS_SCRUB_TYPE_STRINGS \
	{ XFS_SCRUB_TYPE_PROBE,		"probe" }, \
	{ XFS_SCRUB_TYPE_SB,		"sb" }, \
	{ XFS_SCRUB_TYPE_AGF,		"agf" }, \
	{ XFS_SCRUB_TYPE_AGFL,		"agfl" }, \
	{ XFS_SCRUB_TYPE_AGI,		"agi" }, \
	{ XFS_SCRUB_TYPE_BNOBT,		"bnobt" }, \
	{ XFS_SCRUB_TYPE_CNTBT,		"cntbt" }, \
	{ XFS_SCRUB_TYPE_INOBT,		"inobt" }, \
	{ XFS_SCRUB_TYPE_FINOBT,	"finobt" }, \
	{ XFS_SCRUB_TYPE_RMAPBT,	"rmapbt" }, \
	{ XFS_SCRUB_TYPE_REFCNTBT,	"refcountbt" }, \
	{ XFS_SCRUB_TYPE_INODE,		"inode" }, \
	{ XFS_SCRUB_TYPE_BMBTD,		"bmapbtd" }, \
	{ XFS_SCRUB_TYPE_BMBTA,		"bmapbta" }, \
	{ XFS_SCRUB_TYPE_BMBTC,		"bmapbtc" }, \
	{ XFS_SCRUB_TYPE_DIR,		"directory" }, \
	{ XFS_SCRUB_TYPE_XATTR,		"xattr" }, \
	{ XFS_SCRUB_TYPE_SYMLINK,	"symlink" }, \
	{ XFS_SCRUB_TYPE_PARENT,	"parent" }, \
	{ XFS_SCRUB_TYPE_RTBITMAP,	"rtbitmap" }, \
	{ XFS_SCRUB_TYPE_RTSUM,		"rtsummary" }, \
	{ XFS_SCRUB_TYPE_UQUOTA,	"usrquota" }, \
	{ XFS_SCRUB_TYPE_GQUOTA,	"grpquota" }, \
	{ XFS_SCRUB_TYPE_PQUOTA,	"prjquota" }, \
	{ XFS_SCRUB_TYPE_FSCOUNTERS,	"fscounters" }

DECLARE_EVENT_CLASS(xchk_class,
	TP_PROTO(struct xfs_inode *ip, struct xfs_scrub_metadata *sm,
		 int error),
	TP_ARGS(ip, sm, error),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(unsigned int, type)
		__field(xfs_agnumber_t, agno)
		__field(xfs_ino_t, inum)
		__field(unsigned int, gen)
		__field(unsigned int, flags)
		__field(int, error)
	),
	TP_fast_assign(
		__entry->dev = ip->i_mount->m_super->s_dev;
		__entry->ino = ip->i_ino;
		__entry->type = sm->sm_type;
		__entry->agno = sm->sm_agno;
		__entry->inum = sm->sm_ino;
		__entry->gen = sm->sm_gen;
		__entry->flags = sm->sm_flags;
		__entry->error = error;
	),
	TP_printk("dev %d:%d ino 0x%llx type %s agno %u inum %llu gen %u flags 0x%x error %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->agno,
		  __entry->inum,
		  __entry->gen,
		  __entry->flags,
		  __entry->error)
)
#define DEFINE_SCRUB_EVENT(name) \
DEFINE_EVENT(xchk_class, name, \
	TP_PROTO(struct xfs_inode *ip, struct xfs_scrub_metadata *sm, \
		 int error), \
	TP_ARGS(ip, sm, error))

DEFINE_SCRUB_EVENT(xchk_start);
DEFINE_SCRUB_EVENT(xchk_done);
DEFINE_SCRUB_EVENT(xchk_deadlock_retry);
DEFINE_SCRUB_EVENT(xrep_attempt);
DEFINE_SCRUB_EVENT(xrep_done);

TRACE_EVENT(xchk_op_error,
	TP_PROTO(struct xfs_scrub *sc, xfs_agnumber_t agno,
		 xfs_agblock_t bno, int error, void *ret_ip),
	TP_ARGS(sc, agno, bno, error, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(unsigned int, type)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, error)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->agno = agno;
		__entry->bno = bno;
		__entry->error = error;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s agno %u agbno %u error %d ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->agno,
		  __entry->bno,
		  __entry->error,
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_file_op_error,
	TP_PROTO(struct xfs_scrub *sc, int whichfork,
		 xfs_fileoff_t offset, int error, void *ret_ip),
	TP_ARGS(sc, whichfork, offset, error, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(int, whichfork)
		__field(unsigned int, type)
		__field(xfs_fileoff_t, offset)
		__field(int, error)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->ip->i_mount->m_super->s_dev;
		__entry->ino = sc->ip->i_ino;
		__entry->whichfork = whichfork;
		__entry->type = sc->sm->sm_type;
		__entry->offset = offset;
		__entry->error = error;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d ino 0x%llx fork %d type %s offset %llu error %d ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->whichfork,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->offset,
		  __entry->error,
		  __entry->ret_ip)
);

DECLARE_EVENT_CLASS(xchk_block_error_class,
	TP_PROTO(struct xfs_scrub *sc, xfs_daddr_t daddr, void *ret_ip),
	TP_ARGS(sc, daddr, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(unsigned int, type)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		xfs_fsblock_t	fsbno;
		xfs_agnumber_t	agno;
		xfs_agblock_t	bno;

		fsbno = XFS_DADDR_TO_FSB(sc->mp, daddr);
		agno = XFS_FSB_TO_AGNO(sc->mp, fsbno);
		bno = XFS_FSB_TO_AGBNO(sc->mp, fsbno);

		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->agno = agno;
		__entry->bno = bno;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s agno %u agbno %u ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->agno,
		  __entry->bno,
		  __entry->ret_ip)
)

#define DEFINE_SCRUB_BLOCK_ERROR_EVENT(name) \
DEFINE_EVENT(xchk_block_error_class, name, \
	TP_PROTO(struct xfs_scrub *sc, xfs_daddr_t daddr, \
		 void *ret_ip), \
	TP_ARGS(sc, daddr, ret_ip))

DEFINE_SCRUB_BLOCK_ERROR_EVENT(xchk_fs_error);
DEFINE_SCRUB_BLOCK_ERROR_EVENT(xchk_block_error);
DEFINE_SCRUB_BLOCK_ERROR_EVENT(xchk_block_preen);

DECLARE_EVENT_CLASS(xchk_ino_error_class,
	TP_PROTO(struct xfs_scrub *sc, xfs_ino_t ino, void *ret_ip),
	TP_ARGS(sc, ino, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(unsigned int, type)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = ino;
		__entry->type = sc->sm->sm_type;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d ino 0x%llx type %s ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->ret_ip)
)

#define DEFINE_SCRUB_INO_ERROR_EVENT(name) \
DEFINE_EVENT(xchk_ino_error_class, name, \
	TP_PROTO(struct xfs_scrub *sc, xfs_ino_t ino, \
		 void *ret_ip), \
	TP_ARGS(sc, ino, ret_ip))

DEFINE_SCRUB_INO_ERROR_EVENT(xchk_ino_error);
DEFINE_SCRUB_INO_ERROR_EVENT(xchk_ino_preen);
DEFINE_SCRUB_INO_ERROR_EVENT(xchk_ino_warning);

DECLARE_EVENT_CLASS(xchk_fblock_error_class,
	TP_PROTO(struct xfs_scrub *sc, int whichfork,
		 xfs_fileoff_t offset, void *ret_ip),
	TP_ARGS(sc, whichfork, offset, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(int, whichfork)
		__field(unsigned int, type)
		__field(xfs_fileoff_t, offset)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->ip->i_mount->m_super->s_dev;
		__entry->ino = sc->ip->i_ino;
		__entry->whichfork = whichfork;
		__entry->type = sc->sm->sm_type;
		__entry->offset = offset;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d ino 0x%llx fork %d type %s offset %llu ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->whichfork,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->offset,
		  __entry->ret_ip)
);

#define DEFINE_SCRUB_FBLOCK_ERROR_EVENT(name) \
DEFINE_EVENT(xchk_fblock_error_class, name, \
	TP_PROTO(struct xfs_scrub *sc, int whichfork, \
		 xfs_fileoff_t offset, void *ret_ip), \
	TP_ARGS(sc, whichfork, offset, ret_ip))

DEFINE_SCRUB_FBLOCK_ERROR_EVENT(xchk_fblock_error);
DEFINE_SCRUB_FBLOCK_ERROR_EVENT(xchk_fblock_warning);

TRACE_EVENT(xchk_incomplete,
	TP_PROTO(struct xfs_scrub *sc, void *ret_ip),
	TP_ARGS(sc, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(unsigned int, type)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_btree_op_error,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		 int level, int error, void *ret_ip),
	TP_ARGS(sc, cur, level, error, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(unsigned int, type)
		__field(xfs_btnum_t, btnum)
		__field(int, level)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, ptr)
		__field(int, error)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		xfs_fsblock_t fsbno = xchk_btree_cur_fsbno(cur, level);

		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->btnum = cur->bc_btnum;
		__entry->level = level;
		__entry->agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);
		__entry->bno = XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno);
		__entry->ptr = cur->bc_ptrs[level];
		__entry->error = error;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s btree %s level %d ptr %d agno %u agbno %u error %d ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS),
		  __entry->level,
		  __entry->ptr,
		  __entry->agno,
		  __entry->bno,
		  __entry->error,
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_ifork_btree_op_error,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		 int level, int error, void *ret_ip),
	TP_ARGS(sc, cur, level, error, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(int, whichfork)
		__field(unsigned int, type)
		__field(xfs_btnum_t, btnum)
		__field(int, level)
		__field(int, ptr)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, error)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		xfs_fsblock_t fsbno = xchk_btree_cur_fsbno(cur, level);
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = sc->ip->i_ino;
		__entry->whichfork = cur->bc_ino.whichfork;
		__entry->type = sc->sm->sm_type;
		__entry->btnum = cur->bc_btnum;
		__entry->level = level;
		__entry->ptr = cur->bc_ptrs[level];
		__entry->agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);
		__entry->bno = XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno);
		__entry->error = error;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d ino 0x%llx fork %d type %s btree %s level %d ptr %d agno %u agbno %u error %d ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->whichfork,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS),
		  __entry->level,
		  __entry->ptr,
		  __entry->agno,
		  __entry->bno,
		  __entry->error,
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_btree_error,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		 int level, void *ret_ip),
	TP_ARGS(sc, cur, level, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(unsigned int, type)
		__field(xfs_btnum_t, btnum)
		__field(int, level)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, ptr)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		xfs_fsblock_t fsbno = xchk_btree_cur_fsbno(cur, level);
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->btnum = cur->bc_btnum;
		__entry->level = level;
		__entry->agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);
		__entry->bno = XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno);
		__entry->ptr = cur->bc_ptrs[level];
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s btree %s level %d ptr %d agno %u agbno %u ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS),
		  __entry->level,
		  __entry->ptr,
		  __entry->agno,
		  __entry->bno,
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_ifork_btree_error,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		 int level, void *ret_ip),
	TP_ARGS(sc, cur, level, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(int, whichfork)
		__field(unsigned int, type)
		__field(xfs_btnum_t, btnum)
		__field(int, level)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, ptr)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		xfs_fsblock_t fsbno = xchk_btree_cur_fsbno(cur, level);
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = sc->ip->i_ino;
		__entry->whichfork = cur->bc_ino.whichfork;
		__entry->type = sc->sm->sm_type;
		__entry->btnum = cur->bc_btnum;
		__entry->level = level;
		__entry->agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);
		__entry->bno = XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno);
		__entry->ptr = cur->bc_ptrs[level];
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d ino 0x%llx fork %d type %s btree %s level %d ptr %d agno %u agbno %u ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->whichfork,
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS),
		  __entry->level,
		  __entry->ptr,
		  __entry->agno,
		  __entry->bno,
		  __entry->ret_ip)
);

DECLARE_EVENT_CLASS(xchk_sbtree_class,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur,
		 int level),
	TP_ARGS(sc, cur, level),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(int, type)
		__field(xfs_btnum_t, btnum)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bno)
		__field(int, level)
		__field(int, nlevels)
		__field(int, ptr)
	),
	TP_fast_assign(
		xfs_fsblock_t fsbno = xchk_btree_cur_fsbno(cur, level);

		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->btnum = cur->bc_btnum;
		__entry->agno = XFS_FSB_TO_AGNO(cur->bc_mp, fsbno);
		__entry->bno = XFS_FSB_TO_AGBNO(cur->bc_mp, fsbno);
		__entry->level = level;
		__entry->nlevels = cur->bc_nlevels;
		__entry->ptr = cur->bc_ptrs[level];
	),
	TP_printk("dev %d:%d type %s btree %s agno %u agbno %u level %d nlevels %d ptr %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS),
		  __entry->agno,
		  __entry->bno,
		  __entry->level,
		  __entry->nlevels,
		  __entry->ptr)
)
#define DEFINE_SCRUB_SBTREE_EVENT(name) \
DEFINE_EVENT(xchk_sbtree_class, name, \
	TP_PROTO(struct xfs_scrub *sc, struct xfs_btree_cur *cur, \
		 int level), \
	TP_ARGS(sc, cur, level))

DEFINE_SCRUB_SBTREE_EVENT(xchk_btree_rec);
DEFINE_SCRUB_SBTREE_EVENT(xchk_btree_key);

TRACE_EVENT(xchk_xref_error,
	TP_PROTO(struct xfs_scrub *sc, int error, void *ret_ip),
	TP_ARGS(sc, error, ret_ip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(int, type)
		__field(int, error)
		__field(void *, ret_ip)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->type = sc->sm->sm_type;
		__entry->error = error;
		__entry->ret_ip = ret_ip;
	),
	TP_printk("dev %d:%d type %s xref error %d ret_ip %pS",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_symbolic(__entry->type, XFS_SCRUB_TYPE_STRINGS),
		  __entry->error,
		  __entry->ret_ip)
);

TRACE_EVENT(xchk_iallocbt_check_cluster,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agino_t startino, xfs_daddr_t map_daddr,
		 unsigned short map_len, unsigned int chunk_ino,
		 unsigned int nr_inodes, uint16_t cluster_mask,
		 uint16_t holemask, unsigned int cluster_ino),
	TP_ARGS(mp, agno, startino, map_daddr, map_len, chunk_ino, nr_inodes,
		cluster_mask, holemask, cluster_ino),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agino_t, startino)
		__field(xfs_daddr_t, map_daddr)
		__field(unsigned short, map_len)
		__field(unsigned int, chunk_ino)
		__field(unsigned int, nr_inodes)
		__field(unsigned int, cluster_ino)
		__field(uint16_t, cluster_mask)
		__field(uint16_t, holemask)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->startino = startino;
		__entry->map_daddr = map_daddr;
		__entry->map_len = map_len;
		__entry->chunk_ino = chunk_ino;
		__entry->nr_inodes = nr_inodes;
		__entry->cluster_mask = cluster_mask;
		__entry->holemask = holemask;
		__entry->cluster_ino = cluster_ino;
	),
	TP_printk("dev %d:%d agno %d startino %u daddr 0x%llx len %d chunkino %u nr_inodes %u cluster_mask 0x%x holemask 0x%x cluster_ino %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->startino,
		  __entry->map_daddr,
		  __entry->map_len,
		  __entry->chunk_ino,
		  __entry->nr_inodes,
		  __entry->cluster_mask,
		  __entry->holemask,
		  __entry->cluster_ino)
)

TRACE_EVENT(xchk_fscounters_calc,
	TP_PROTO(struct xfs_mount *mp, uint64_t icount, uint64_t ifree,
		 uint64_t fdblocks, uint64_t delalloc),
	TP_ARGS(mp, icount, ifree, fdblocks, delalloc),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(int64_t, icount_sb)
		__field(uint64_t, icount_calculated)
		__field(int64_t, ifree_sb)
		__field(uint64_t, ifree_calculated)
		__field(int64_t, fdblocks_sb)
		__field(uint64_t, fdblocks_calculated)
		__field(uint64_t, delalloc)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->icount_sb = mp->m_sb.sb_icount;
		__entry->icount_calculated = icount;
		__entry->ifree_sb = mp->m_sb.sb_ifree;
		__entry->ifree_calculated = ifree;
		__entry->fdblocks_sb = mp->m_sb.sb_fdblocks;
		__entry->fdblocks_calculated = fdblocks;
		__entry->delalloc = delalloc;
	),
	TP_printk("dev %d:%d icount %lld:%llu ifree %lld::%llu fdblocks %lld::%llu delalloc %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->icount_sb,
		  __entry->icount_calculated,
		  __entry->ifree_sb,
		  __entry->ifree_calculated,
		  __entry->fdblocks_sb,
		  __entry->fdblocks_calculated,
		  __entry->delalloc)
)

TRACE_EVENT(xchk_fscounters_within_range,
	TP_PROTO(struct xfs_mount *mp, uint64_t expected, int64_t curr_value,
		 int64_t old_value),
	TP_ARGS(mp, expected, curr_value, old_value),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(uint64_t, expected)
		__field(int64_t, curr_value)
		__field(int64_t, old_value)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->expected = expected;
		__entry->curr_value = curr_value;
		__entry->old_value = old_value;
	),
	TP_printk("dev %d:%d expected %llu curr_value %lld old_value %lld",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->expected,
		  __entry->curr_value,
		  __entry->old_value)
)

TRACE_EVENT(xchk_fscounters_frextents_within_range,
	TP_PROTO(struct xfs_mount *mp, uint64_t expected, int64_t curr_value),
	TP_ARGS(mp, expected, curr_value),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(uint64_t, expected)
		__field(int64_t, curr_value)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->expected = expected;
		__entry->curr_value = curr_value;
	),
	TP_printk("dev %d:%d expected %llu curr_value %lld",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->expected,
		  __entry->curr_value)
)

TRACE_EVENT(xfile_create,
	TP_PROTO(struct xfile *xf),
	TP_ARGS(xf),
	TP_STRUCT__entry(
		__field(unsigned long, ino)
		__array(char, pathname, 256)
	),
	TP_fast_assign(
		char		pathname[257];
		char		*path;

		__entry->ino = file_inode(xf->file)->i_ino;
		memset(pathname, 0, sizeof(pathname));
		path = file_path(xf->file, pathname, sizeof(pathname) - 1);
		if (IS_ERR(path))
			path = "(unknown)";
		strncpy(__entry->pathname, path, sizeof(__entry->pathname));
	),
	TP_printk("ino %lu path %s",
		  __entry->ino,
		  __entry->pathname)
);

DECLARE_EVENT_CLASS(xfile_class,
	TP_PROTO(struct xfile *xf, loff_t offset, long long count),
	TP_ARGS(xf, offset, count),
	TP_STRUCT__entry(
		__field(unsigned long, ino)
		__field(long long, bytes)
		__field(loff_t, offset)
		__field(long long, count)
	),
	TP_fast_assign(
		struct kstat	statbuf;
		int		ret;

		ret = xfile_statx(xf, &statbuf);
		if (!ret)
			__entry->bytes = statbuf.blocks * 512;
		else
			__entry->bytes = -1;
		__entry->ino = file_inode(xf->file)->i_ino;
		__entry->offset = offset;
		__entry->count = count;
	),
	TP_printk("ino %lu mem_usage %lld offset %lld count %lld",
		  __entry->ino,
		  __entry->bytes,
		  __entry->offset,
		  __entry->count)
);
#define DEFINE_XFILE_EVENT(name) \
DEFINE_EVENT(xfile_class, name, \
	TP_PROTO(struct xfile *xf, loff_t offset, long long count), \
	TP_ARGS(xf, offset, count))
DEFINE_XFILE_EVENT(xfile_destroy);
DEFINE_XFILE_EVENT(xfile_discard);
DEFINE_XFILE_EVENT(xfile_pread);
DEFINE_XFILE_EVENT(xfile_pwrite);
DEFINE_XFILE_EVENT(xfile_seek_data);

TRACE_EVENT(xfbma_sort_stats,
	TP_PROTO(uint64_t nr, unsigned int max_stack_depth,
		 unsigned int max_stack_used, int error),
	TP_ARGS(nr, max_stack_depth, max_stack_used, error),
	TP_STRUCT__entry(
		__field(uint64_t, nr)
		__field(unsigned int, max_stack_depth)
		__field(unsigned int, max_stack_used)
		__field(int, error)
	),
	TP_fast_assign(
		__entry->nr = nr;
		__entry->max_stack_depth = max_stack_depth;
		__entry->max_stack_used = max_stack_used;
		__entry->error = error;
	),
	TP_printk("nr %llu max_depth %u max_used %u error %d",
		  __entry->nr,
		  __entry->max_stack_depth,
		  __entry->max_stack_used,
		  __entry->error)
);

TRACE_EVENT(xchk_rtsum_record_free,
	TP_PROTO(struct xfs_mount *mp, xfs_rtblock_t start,
		 uint64_t len, unsigned int log, loff_t pos, xfs_suminfo_t v),
	TP_ARGS(mp, start, len, log, pos, v),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_rtblock_t, start)
		__field(unsigned long long, len)
		__field(unsigned int, log)
		__field(loff_t, pos)
		__field(xfs_suminfo_t, v)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->start = start;
		__entry->len = len;
		__entry->log = log;
		__entry->pos = pos;
		__entry->v = v;
	),
	TP_printk("dev %d:%d start %llu len %llu log %u pos %lld v %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->start,
		  __entry->len,
		  __entry->log,
		  __entry->pos,
		  __entry->v)
)

/* repair tracepoints */
#if IS_ENABLED(CONFIG_XFS_ONLINE_REPAIR)

DECLARE_EVENT_CLASS(xrep_extent_class,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agblock_t agbno, xfs_extlen_t len),
	TP_ARGS(mp, agno, agbno, len),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, agbno)
		__field(xfs_extlen_t, len)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->agbno = agbno;
		__entry->len = len;
	),
	TP_printk("dev %d:%d agno %u agbno %u len %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->agbno,
		  __entry->len)
);
#define DEFINE_REPAIR_EXTENT_EVENT(name) \
DEFINE_EVENT(xrep_extent_class, name, \
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno, \
		 xfs_agblock_t agbno, xfs_extlen_t len), \
	TP_ARGS(mp, agno, agbno, len))
DEFINE_REPAIR_EXTENT_EVENT(xrep_dispose_btree_extent);
DEFINE_REPAIR_EXTENT_EVENT(xrep_agfl_insert);

DECLARE_EVENT_CLASS(xrep_rmap_class,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agblock_t agbno, xfs_extlen_t len,
		 uint64_t owner, uint64_t offset, unsigned int flags),
	TP_ARGS(mp, agno, agbno, len, owner, offset, flags),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, agbno)
		__field(xfs_extlen_t, len)
		__field(uint64_t, owner)
		__field(uint64_t, offset)
		__field(unsigned int, flags)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->agbno = agbno;
		__entry->len = len;
		__entry->owner = owner;
		__entry->offset = offset;
		__entry->flags = flags;
	),
	TP_printk("dev %d:%d agno %u agbno %u len %u owner %lld offset %llu flags 0x%x",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->agbno,
		  __entry->len,
		  __entry->owner,
		  __entry->offset,
		  __entry->flags)
);
#define DEFINE_REPAIR_RMAP_EVENT(name) \
DEFINE_EVENT(xrep_rmap_class, name, \
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno, \
		 xfs_agblock_t agbno, xfs_extlen_t len, \
		 uint64_t owner, uint64_t offset, unsigned int flags), \
	TP_ARGS(mp, agno, agbno, len, owner, offset, flags))
DEFINE_REPAIR_RMAP_EVENT(xrep_ibt_walk_rmap);
DEFINE_REPAIR_RMAP_EVENT(xrep_rmap_extent_fn);
DEFINE_REPAIR_RMAP_EVENT(xrep_bmap_walk_rmap);

TRACE_EVENT(xrep_abt_found,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 const struct xfs_alloc_rec_incore *rec),
	TP_ARGS(mp, agno, rec),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, startblock)
		__field(xfs_extlen_t, blockcount)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->startblock = rec->ar_startblock;
		__entry->blockcount = rec->ar_blockcount;
	),
	TP_printk("dev %d:%d agno %u agbno %u len %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->startblock,
		  __entry->blockcount)
)

TRACE_EVENT(xrep_ibt_found,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 const struct xfs_inobt_rec_incore *rec),
	TP_ARGS(mp, agno, rec),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agino_t, startino)
		__field(uint16_t, holemask)
		__field(uint8_t, count)
		__field(uint8_t, freecount)
		__field(uint64_t, freemask)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->startino = rec->ir_startino;
		__entry->holemask = rec->ir_holemask;
		__entry->count = rec->ir_count;
		__entry->freecount = rec->ir_freecount;
		__entry->freemask = rec->ir_free;
	),
	TP_printk("dev %d:%d agno %d startino %u holemask 0x%x count %u freecount %u freemask 0x%llx",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->startino,
		  __entry->holemask,
		  __entry->count,
		  __entry->freecount,
		  __entry->freemask)
)

TRACE_EVENT(xrep_refc_found,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 const struct xfs_refcount_irec *rec),
	TP_ARGS(mp, agno, rec),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, startblock)
		__field(xfs_extlen_t, blockcount)
		__field(xfs_nlink_t, refcount)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->startblock = rec->rc_startblock;
		__entry->blockcount = rec->rc_blockcount;
		__entry->refcount = rec->rc_refcount;
	),
	TP_printk("dev %d:%d agno %u agbno %u len %u refcount %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->startblock,
		  __entry->blockcount,
		  __entry->refcount)
)

TRACE_EVENT(xrep_bmap_found,
	TP_PROTO(struct xfs_inode *ip, int whichfork,
		 struct xfs_bmbt_irec *irec),
	TP_ARGS(ip, whichfork, irec),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(int, whichfork)
		__field(xfs_fileoff_t, lblk)
		__field(xfs_extlen_t, len)
		__field(xfs_fsblock_t, pblk)
		__field(int, state)
	),
	TP_fast_assign(
		__entry->dev = VFS_I(ip)->i_sb->s_dev;
		__entry->ino = ip->i_ino;
		__entry->whichfork = whichfork;
		__entry->lblk = irec->br_startoff;
		__entry->len = irec->br_blockcount;
		__entry->pblk = irec->br_startblock;
		__entry->state = irec->br_state;
	),
	TP_printk("dev %d:%d ino 0x%llx whichfork %s lblk 0x%llx len 0x%x pblk %llu st %d",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->whichfork == XFS_ATTR_FORK ? "attr" : "data",
		  __entry->lblk,
		  __entry->len,
		  __entry->pblk,
		  __entry->state)
);

TRACE_EVENT(xrep_init_btblock,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno, xfs_agblock_t agbno,
		 xfs_btnum_t btnum),
	TP_ARGS(mp, agno, agbno, btnum),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, agbno)
		__field(uint32_t, btnum)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->agbno = agbno;
		__entry->btnum = btnum;
	),
	TP_printk("dev %d:%d agno %u agbno %u btree %s",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->agbno,
		  __print_symbolic(__entry->btnum, XFS_BTNUM_STRINGS))
)
TRACE_EVENT(xrep_findroot_block,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno, xfs_agblock_t agbno,
		 uint32_t magic, uint16_t level),
	TP_ARGS(mp, agno, agbno, magic, level),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, agbno)
		__field(uint32_t, magic)
		__field(uint16_t, level)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->agbno = agbno;
		__entry->magic = magic;
		__entry->level = level;
	),
	TP_printk("dev %d:%d agno %u agbno %u magic 0x%x level %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->agbno,
		  __entry->magic,
		  __entry->level)
)
TRACE_EVENT(xrep_calc_ag_resblks,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agino_t icount, xfs_agblock_t aglen, xfs_agblock_t freelen,
		 xfs_agblock_t usedlen),
	TP_ARGS(mp, agno, icount, aglen, freelen, usedlen),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agino_t, icount)
		__field(xfs_agblock_t, aglen)
		__field(xfs_agblock_t, freelen)
		__field(xfs_agblock_t, usedlen)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->icount = icount;
		__entry->aglen = aglen;
		__entry->freelen = freelen;
		__entry->usedlen = usedlen;
	),
	TP_printk("dev %d:%d agno %d icount %u aglen %u freelen %u usedlen %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->icount,
		  __entry->aglen,
		  __entry->freelen,
		  __entry->usedlen)
)
TRACE_EVENT(xrep_calc_ag_resblks_btsize,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agblock_t bnobt_sz, xfs_agblock_t inobt_sz,
		 xfs_agblock_t rmapbt_sz, xfs_agblock_t refcbt_sz),
	TP_ARGS(mp, agno, bnobt_sz, inobt_sz, rmapbt_sz, refcbt_sz),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, bnobt_sz)
		__field(xfs_agblock_t, inobt_sz)
		__field(xfs_agblock_t, rmapbt_sz)
		__field(xfs_agblock_t, refcbt_sz)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->bnobt_sz = bnobt_sz;
		__entry->inobt_sz = inobt_sz;
		__entry->rmapbt_sz = rmapbt_sz;
		__entry->refcbt_sz = refcbt_sz;
	),
	TP_printk("dev %d:%d agno %d bno %u ino %u rmap %u refcount %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->bnobt_sz,
		  __entry->inobt_sz,
		  __entry->rmapbt_sz,
		  __entry->refcbt_sz)
)
TRACE_EVENT(xrep_reset_counters,
	TP_PROTO(struct xfs_mount *mp),
	TP_ARGS(mp),
	TP_STRUCT__entry(
		__field(dev_t, dev)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
	),
	TP_printk("dev %d:%d",
		  MAJOR(__entry->dev), MINOR(__entry->dev))
)

DECLARE_EVENT_CLASS(xrep_newbt_extent_class,
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno,
		 xfs_agblock_t agbno, xfs_extlen_t len,
		 int64_t owner),
	TP_ARGS(mp, agno, agbno, len, owner),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_agnumber_t, agno)
		__field(xfs_agblock_t, agbno)
		__field(xfs_extlen_t, len)
		__field(int64_t, owner)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->agno = agno;
		__entry->agbno = agbno;
		__entry->len = len;
		__entry->owner = owner;
	),
	TP_printk("dev %d:%d agno %u agbno %u len %u owner %lld",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->agno,
		  __entry->agbno,
		  __entry->len,
		  __entry->owner)
);
#define DEFINE_NEWBT_EXTENT_EVENT(name) \
DEFINE_EVENT(xrep_newbt_extent_class, name, \
	TP_PROTO(struct xfs_mount *mp, xfs_agnumber_t agno, \
		 xfs_agblock_t agbno, xfs_extlen_t len, \
		 int64_t owner), \
	TP_ARGS(mp, agno, agbno, len, owner))
DEFINE_NEWBT_EXTENT_EVENT(xrep_newbt_alloc_blocks);
DEFINE_NEWBT_EXTENT_EVENT(xrep_newbt_free_blocks);
DEFINE_NEWBT_EXTENT_EVENT(xrep_newbt_claim_block);

DECLARE_EVENT_CLASS(xrep_dinode_class,
	TP_PROTO(struct xfs_scrub *sc, struct xfs_dinode *dip),
	TP_ARGS(sc, dip),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(uint16_t, mode)
		__field(uint8_t, version)
		__field(uint8_t, format)
		__field(uint32_t, uid)
		__field(uint32_t, gid)
		__field(uint64_t, size)
		__field(uint64_t, nblocks)
		__field(uint32_t, extsize)
		__field(uint32_t, nextents)
		__field(uint16_t, anextents)
		__field(uint8_t, forkoff)
		__field(uint8_t, aformat)
		__field(uint16_t, flags)
		__field(uint32_t, gen)
		__field(uint64_t, flags2)
		__field(uint32_t, cowextsize)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = sc->sm->sm_ino;
		__entry->mode = be16_to_cpu(dip->di_mode);
		__entry->version = dip->di_version;
		__entry->format = dip->di_format;
		__entry->uid = be32_to_cpu(dip->di_uid);
		__entry->gid = be32_to_cpu(dip->di_gid);
		__entry->size = be64_to_cpu(dip->di_size);
		__entry->nblocks = be64_to_cpu(dip->di_nblocks);
		__entry->extsize = be32_to_cpu(dip->di_extsize);
		__entry->nextents = be32_to_cpu(dip->di_nextents);
		__entry->anextents = be16_to_cpu(dip->di_anextents);
		__entry->forkoff = dip->di_forkoff;
		__entry->aformat = dip->di_aformat;
		__entry->flags = be16_to_cpu(dip->di_flags);
		__entry->gen = be32_to_cpu(dip->di_gen);
		__entry->flags2 = be64_to_cpu(dip->di_flags2);
		__entry->cowextsize = be32_to_cpu(dip->di_cowextsize);
	),
	TP_printk("dev %d:%d ino 0x%llx mode 0x%x version %u format %u uid %u gid %u size %llu nblocks %llu extsize %u nextents %u anextents %u forkoff %u aformat %u flags 0x%x gen 0x%x flags2 0x%llx cowextsize %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->mode,
		  __entry->version,
		  __entry->format,
		  __entry->uid,
		  __entry->gid,
		  __entry->size,
		  __entry->nblocks,
		  __entry->extsize,
		  __entry->nextents,
		  __entry->anextents,
		  __entry->forkoff,
		  __entry->aformat,
		  __entry->flags,
		  __entry->gen,
		  __entry->flags2,
		  __entry->cowextsize)
)

#define DEFINE_REPAIR_DINODE_EVENT(name) \
DEFINE_EVENT(xrep_dinode_class, name, \
	TP_PROTO(struct xfs_scrub *sc, struct xfs_dinode *dip), \
	TP_ARGS(sc, dip))
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_header);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_mode);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_flags);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_size);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_extsize_hints);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_zap_symlink);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_zap_dir);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_fixed);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_zap_forks);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_zap_dfork);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_zap_afork);
DEFINE_REPAIR_DINODE_EVENT(xrep_dinode_ensure_forkoff);

DECLARE_EVENT_CLASS(xrep_inode_class,
	TP_PROTO(struct xfs_scrub *sc),
	TP_ARGS(sc),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(xfs_fsize_t, size)
		__field(xfs_rfsblock_t, nblocks)
		__field(uint16_t, flags)
		__field(uint64_t, flags2)
		__field(uint32_t, nextents)
		__field(uint8_t, format)
		__field(uint32_t, anextents)
		__field(uint8_t, aformat)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = sc->sm->sm_ino;
		__entry->size = sc->ip->i_disk_size;
		__entry->nblocks = sc->ip->i_nblocks;
		__entry->flags = sc->ip->i_diflags;
		__entry->flags2 = sc->ip->i_diflags2;
		__entry->nextents = sc->ip->i_df.if_nextents;
		__entry->format = sc->ip->i_df.if_format;

		if (sc->ip->i_afp) {
			__entry->anextents = sc->ip->i_afp->if_nextents;
			__entry->aformat = sc->ip->i_afp->if_format;
		} else {
			__entry->anextents = 0;
			__entry->aformat = XFS_DINODE_FMT_EXTENTS;
		}
	),
	TP_printk("dev %d:%d ino 0x%llx size %llu nblocks %llu flags 0x%x flags2 0x%llx nextents %u format %u anextents %u aformat %u",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->size,
		  __entry->nblocks,
		  __entry->flags,
		  __entry->flags2,
		  __entry->nextents,
		  __entry->format,
		  __entry->anextents,
		  __entry->aformat)
)

#define DEFINE_REPAIR_INODE_EVENT(name) \
DEFINE_EVENT(xrep_inode_class, name, \
	TP_PROTO(struct xfs_scrub *sc), \
	TP_ARGS(sc))
DEFINE_REPAIR_INODE_EVENT(xrep_inode_blockcounts);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_ids);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_flags);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_blockdir_size);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_sfdir_size);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_size);
DEFINE_REPAIR_INODE_EVENT(xrep_inode_fixed);

TRACE_EVENT(xrep_dinode_count_rmaps,
	TP_PROTO(struct xfs_scrub *sc, xfs_rfsblock_t data_blocks,
		xfs_rfsblock_t rt_blocks, xfs_rfsblock_t attr_blocks,
		xfs_extnum_t data_extents, xfs_extnum_t rt_extents,
		xfs_aextnum_t attr_extents, xfs_fsblock_t block0),
	TP_ARGS(sc, data_blocks, rt_blocks, attr_blocks, data_extents,
		rt_extents, attr_extents, block0),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(xfs_ino_t, ino)
		__field(xfs_rfsblock_t, data_blocks)
		__field(xfs_rfsblock_t, rt_blocks)
		__field(xfs_rfsblock_t, attr_blocks)
		__field(xfs_extnum_t, data_extents)
		__field(xfs_extnum_t, rt_extents)
		__field(xfs_aextnum_t, attr_extents)
		__field(xfs_fsblock_t, block0)
	),
	TP_fast_assign(
		__entry->dev = sc->mp->m_super->s_dev;
		__entry->ino = sc->sm->sm_ino;
		__entry->data_blocks = data_blocks;
		__entry->rt_blocks = rt_blocks;
		__entry->attr_blocks = attr_blocks;
		__entry->data_extents = data_extents;
		__entry->rt_extents = rt_extents;
		__entry->attr_extents = attr_extents;
		__entry->block0 = block0;
	),
	TP_printk("dev %d:%d ino 0x%llx dblocks %llu rtblocks %llu ablocks %llu dextents %u rtextents %u aextents %u block0 %llu",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __entry->ino,
		  __entry->data_blocks,
		  __entry->rt_blocks,
		  __entry->attr_blocks,
		  __entry->data_extents,
		  __entry->rt_extents,
		  __entry->attr_extents,
		  __entry->block0)
);

DECLARE_EVENT_CLASS(xrep_dquot_class,
	TP_PROTO(struct xfs_mount *mp, uint8_t type, uint32_t id),
	TP_ARGS(mp, type, id),
	TP_STRUCT__entry(
		__field(dev_t, dev)
		__field(uint8_t, type)
		__field(uint32_t, id)
	),
	TP_fast_assign(
		__entry->dev = mp->m_super->s_dev;
		__entry->id = id;
		__entry->type = type;
	),
	TP_printk("dev %d:%d type %s id 0x%x",
		  MAJOR(__entry->dev), MINOR(__entry->dev),
		  __print_flags(__entry->type, "|", XFS_DQTYPE_STRINGS),
		  __entry->id)
);

#define DEFINE_XREP_DQUOT_EVENT(name) \
DEFINE_EVENT(xrep_dquot_class, name, \
	TP_PROTO(struct xfs_mount *mp, uint8_t type, uint32_t id), \
	TP_ARGS(mp, type, id))
DEFINE_XREP_DQUOT_EVENT(xrep_dquot_item);
DEFINE_XREP_DQUOT_EVENT(xrep_disk_dquot);

#endif /* IS_ENABLED(CONFIG_XFS_ONLINE_REPAIR) */

#endif /* _TRACE_XFS_SCRUB_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scrub/trace
#include <trace/define_trace.h>
