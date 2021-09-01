/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#ifndef __XFS_IMETA_H__
#define __XFS_IMETA_H__

/* How deep can we nest metadata dirs? */
#define XFS_IMETA_MAX_DEPTH	64

/* Form an imeta path from a simple array of strings. */
#define XFS_IMETA_DEFINE_PATH(name, path) \
const struct xfs_imeta_path name = { \
	.im_path = (path), \
	.im_ftype = XFS_DIR3_FT_REG_FILE, \
	.im_depth = ARRAY_SIZE(path), \
}

/* Key for looking up metadata inodes. */
struct xfs_imeta_path {
	/* Array of string pointers. */
	const char	**im_path;

	/* Number of strings in path. */
	unsigned int	im_depth;

	/* Expected file type. */
	unsigned int	im_ftype;
};

/* Cleanup widget for metadata inode creation and deletion. */
struct xfs_imeta_end {
	struct xfs_inode	*dp;
};

/* Lookup keys for static metadata inodes. */
extern const struct xfs_imeta_path XFS_IMETA_RTBITMAP;
extern const struct xfs_imeta_path XFS_IMETA_RTSUMMARY;
extern const struct xfs_imeta_path XFS_IMETA_USRQUOTA;
extern const struct xfs_imeta_path XFS_IMETA_GRPQUOTA;
extern const struct xfs_imeta_path XFS_IMETA_PRJQUOTA;
extern const struct xfs_imeta_path XFS_IMETA_METADIR;

int xfs_imeta_lookup(struct xfs_mount *mp, const struct xfs_imeta_path *path,
		     xfs_ino_t *ino);

void xfs_imeta_set_metaflag(struct xfs_trans *tp, struct xfs_inode *ip);

/* Don't allocate quota for this file. */
#define XFS_IMETA_CREATE_NOQUOTA	(1 << 0)
int xfs_imeta_create(struct xfs_trans **tpp, const struct xfs_imeta_path *path,
		     umode_t mode, unsigned int flags, struct xfs_inode **ipp,
		     struct xfs_imeta_end *cleanup);
int xfs_imeta_unlink(struct xfs_trans **tpp, const struct xfs_imeta_path *path,
		     struct xfs_inode *ip, struct xfs_imeta_end *cleanup);
int xfs_imeta_link(struct xfs_trans *tp, const struct xfs_imeta_path *path,
		   struct xfs_inode *ip, struct xfs_imeta_end *cleanup);
void xfs_imeta_end_update(struct xfs_mount *mp, struct xfs_imeta_end *cleanup,
			  int error);

bool xfs_is_static_meta_ino(struct xfs_mount *mp, xfs_ino_t ino);
int xfs_imeta_mount(struct xfs_mount *mp);
void xfs_imeta_droplink(struct xfs_inode *ip);

unsigned int xfs_imeta_create_space_res(struct xfs_mount *mp);
unsigned int xfs_imeta_unlink_space_res(struct xfs_mount *mp);

/* Must be implemented by the libxfs client */
int xfs_imeta_iget(struct xfs_mount *mp, xfs_ino_t ino, unsigned char ftype,
		struct xfs_inode **ipp);
void xfs_imeta_irele(struct xfs_inode *ip);

#endif /* __XFS_IMETA_H__ */
