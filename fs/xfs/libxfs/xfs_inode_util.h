/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2000-2003,2005 Silicon Graphics, Inc.
 * All Rights Reserved.
 */
#ifndef	__XFS_INODE_UTIL_H__
#define	__XFS_INODE_UTIL_H__

uint16_t	xfs_flags2diflags(struct xfs_inode *ip, unsigned int xflags);
uint64_t	xfs_flags2diflags2(struct xfs_inode *ip, unsigned int xflags);
uint32_t	xfs_dic2xflags(struct xfs_inode *ip);

prid_t		xfs_get_initial_prid(struct xfs_inode *dp);

/*
 * Initial ids, link count, device number, and mode of a new inode.
 *
 * Due to our only partial reliance on the VFS to propagate uid and gid values
 * according to accepted Unix behaviors, callers must initialize mnt_userns to
 * the appropriate namespace, uid to fsuid_into_mnt(), and gid to
 * fsgid_into_mnt() to get the correct inheritance behaviors when
 * XFS_MOUNT_GRPID is set.  Use the xfs_ialloc_inherit_args() helper.
 *
 * To override the default ids, use the FORCE flags defined below.
 */
struct xfs_icreate_args {
	struct user_namespace	*mnt_userns;
	struct xfs_inode	*pip;	/* parent inode or null */

	kuid_t			uid;
	kgid_t			gid;
	prid_t			prid;

	xfs_nlink_t		nlink;
	dev_t			rdev;

	umode_t			mode;

#define XFS_ICREATE_ARGS_FORCE_UID	(1 << 0)
#define XFS_ICREATE_ARGS_FORCE_GID	(1 << 1)
#define XFS_ICREATE_ARGS_FORCE_MODE	(1 << 2)
#define XFS_ICREATE_ARGS_INIT_XATTRS	(1 << 3)
	uint16_t		flags;
};

#endif /* __XFS_INODE_UTIL_H__ */
