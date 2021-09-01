// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 Oracle.  All Rights Reserved.
 * Author: Darrick J. Wong <djwong@kernel.org>
 */
#include "xfs.h"
#include "xfs_fs.h"
#include "xfs_shared.h"
#include "xfs_format.h"
#include "scrub/array.h"
#include "scrub/scrub.h"
#include "scrub/trace.h"
#include "scrub/xfile.h"
#include <linux/shmem_fs.h>

/*
 * Swappable Temporary Memory
 * ==========================
 *
 * Online checking sometimes needs to be able to stage a large amount of data
 * in memory.  This information might not fit in the available memory and it
 * doesn't all need to be accessible at all times.  In other words, we want an
 * indexed data buffer to store data that can be paged out.
 *
 * When CONFIG_TMPFS=y, shmemfs is enough of a filesystem to meet those
 * requirements.  Therefore, the xfile mechanism uses an unlinked shmem file to
 * store our staging data.  This file is not installed in the file descriptor
 * table so that user programs cannot access the data, which means that the
 * xfile must be freed with xfile_destroy.
 *
 * xfiles assume that the caller will handle all required concurrency
 * management; standard vfs locks (freezer and inode) are not taken.  Reads
 * and writes are satisfied directly from the page cache.
 *
 * NOTE: The current shmemfs implementation has a quirk that in-kernel reads
 * of a hole cause a page to be mapped into the file.  If you are going to
 * create a sparse xfile, please be careful about reading from uninitialized
 * parts of the file.
 */

/*
 * xfiles must not be exposed to userspace and require upper layers to
 * coordinate access to the one handle returned by the constructor, so
 * establish a separate lock class for xfiles to avoid confusing lockdep.
 */
static struct lock_class_key xfile_i_mutex_key;

/*
 * Create an xfile of the given size.  The description will be used in the
 * trace output.
 */
struct xfile *
xfile_create(
	const char		*description,
	loff_t			size)
{
	struct xfile		*xf;

	xf = kmem_alloc(sizeof(struct xfile), KM_MAYFAIL);
	if (!xf)
		return ERR_PTR(-ENOMEM);

	xf->file = shmem_file_setup(description, size, 0);
	if (!xf->file) {
		kmem_free(xf);
		return ERR_PTR(-ENOMEM);
	}
	if (IS_ERR(xf->file)) {
		int	ret = PTR_ERR(xf->file);

		kmem_free(xf);
		return ERR_PTR(ret);
	}

	/*
	 * We want a large sparse file that we can pread, pwrite, and seek.
	 * xfile users are responsible for keeping the xfile hidden away from
	 * all other callers, so we skip timestamp updates and security checks.
	 */
	xf->file->f_mode |= FMODE_PREAD | FMODE_PWRITE | FMODE_NOCMTIME |
			    FMODE_LSEEK;
	xf->file->f_flags |= O_RDWR | O_LARGEFILE | O_NOATIME;
	xf->file->f_inode->i_flags |= S_PRIVATE | S_NOCMTIME | S_NOATIME;

	lockdep_set_class(&file_inode(xf->file)->i_rwsem, &xfile_i_mutex_key);

	trace_xfile_create(xf);
	return xf;
}

/* Close the file and release all resources. */
void
xfile_destroy(
	struct xfile		*xf)
{
	struct inode		*inode = file_inode(xf->file);

	trace_xfile_destroy(xf, 0, 0);

	lockdep_set_class(&inode->i_rwsem, &inode->i_sb->s_type->i_mutex_key);
	fput(xf->file);
}

/* Read a buffer directly from the xfile's page cache. */
int
xfile_pread(
	struct xfile		*xf,
	void			*buf,
	size_t			count,
	loff_t			offset)
{
	struct inode		*inode = file_inode(xf->file);
	struct address_space	*mapping = inode->i_mapping;
	struct page		*page = NULL;
	unsigned int		pflags;

	if (count > MAX_RW_COUNT)
		return -ENOMEM;
	if (inode->i_sb->s_maxbytes - offset < count)
		return -ENOMEM;

	trace_xfile_pread(xf, offset, count);

	pflags = memalloc_nofs_save();
	while (count > 0) {
		void		*p, *kaddr;
		unsigned int	len;

		len = min_t(ssize_t, count, PAGE_SIZE - offset_in_page(offset));

		/*
		 * In-kernel reads of a shmem file cause it to allocate a page
		 * if the mapping shows a hole.  Therefore, if we hit ENOMEM
		 * we can continue by zeroing the caller's buffer.
		 */
		page = shmem_read_mapping_page_gfp(mapping,
				offset >> PAGE_SHIFT, __GFP_NOWARN);
		if (IS_ERR(page)) {
			if (PTR_ERR(page) != -ENOMEM)
				break;
			page = NULL;
		}

		if (!page || !PageUptodate(page)) {
			memset(buf, 0, len);
		} else {
			/*
			 * xfile pages must never be mapped into userspace, so
			 * we skip the dcache flush.
			 */
			kaddr = kmap_local_page(page);
			p = kaddr + offset_in_page(offset);
			memcpy(buf, p, len);
			kunmap_local(kaddr);
		}
		if (page)
			put_page(page);

		count -= len;
		offset += len;
		buf += len;
	}
	memalloc_nofs_restore(pflags);

	/*
	 * Since we're treating this file as "memory", any IO error or short
	 * read should be treated as a failure to allocate memory.
	 */
	return count > 0 ? -ENOMEM : 0;
}

/* Write a buffer directly to the xfile's page cache. */
int
xfile_pwrite(
	struct xfile		*xf,
	void			*buf,
	size_t			count,
	loff_t			offset)
{
	struct inode		*inode = file_inode(xf->file);
	struct address_space	*mapping = inode->i_mapping;
	struct page		*page = NULL;
	unsigned int		pflags;
	int			error;

	if (count > MAX_RW_COUNT)
		return -ENOMEM;
	if (inode->i_sb->s_maxbytes - offset < count)
		return -ENOMEM;

	trace_xfile_pwrite(xf, offset, count);

	pflags = memalloc_nofs_save();
	while (count > 0) {
		void		*fsdata;
		void		*p, *kaddr;
		unsigned int	len;

		len = min_t(ssize_t, count, PAGE_SIZE - offset_in_page(offset));

		/*
		 * We call pagecache_write_begin directly here to avoid all
		 * the freezer protection lock-taking that happens in the
		 * normal path.  shmem doesn't support fs freeze, but lockdep
		 * doesn't know that and will trip over that.
		 */
		error = pagecache_write_begin(NULL, mapping, offset, len,
				AOP_FLAG_NOFS, &page, &fsdata);
		if (error)
			break;

		/*
		 * xfile pages must never be mapped into userspace, so we skip
		 * the dcache flush.
		 */
		kaddr = kmap_local_page(page);
		p = kaddr + offset_in_page(offset);
		memcpy(p, buf, len);
		kunmap_local(kaddr);

		error = pagecache_write_end(NULL, mapping, offset, len, len,
				page, fsdata);
		if (error < 0)
			break;

		count -= len;
		offset += len;
		buf += len;
	}
	memalloc_nofs_restore(pflags);

	/*
	 * Since we're treating this file as "memory", any IO error or short
	 * write should be treated as a failure to allocate memory.
	 */
	return count > 0 ? -ENOMEM : 0;
}

/* Discard pages backing a range of the xfile. */
void
xfile_discard(
	struct xfile		*xf,
	loff_t			start,
	loff_t			end)
{
	trace_xfile_discard(xf, start, end);
	shmem_truncate_range(file_inode(xf->file), start, end);
}

/* Find the next batch of xfile data for a given offset. */
loff_t
xfile_seek_data(
	struct xfile		*xf,
	loff_t			pos)
{
	loff_t			ret;

	ret = vfs_llseek(xf->file, pos, SEEK_DATA);
	trace_xfile_seek_data(xf, pos, ret);
	return ret;
}

/* Query statx information for an xfile. */
int
xfile_statx(
	struct xfile		*xf,
	struct kstat		*statbuf)
{
	return vfs_getattr_nosec(&xf->file->f_path, statbuf,
			STATX_SIZE | STATX_BLOCKS, AT_STATX_DONT_SYNC);
}
