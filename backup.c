/*
 * QEMU backup
 *
 * Copyright (C) 2013 Proxmox Server Solutions
 *
 * Authors:
 *  Dietmar Maurer (dietmar@proxmox.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "block/block.h"
#include "block/block_int.h"
#include "block/blockjob.h"
#include "qemu/ratelimit.h"
#include "backup.h"

#define DEBUG_BACKUP 0

#define USE_ALLOCATION_CHECK 0

#define DPRINTF(fmt, ...) \
    do { if (DEBUG_BACKUP) { printf("backup: " fmt, ## __VA_ARGS__); } } \
    while (0)


#define SLICE_TIME 100000000ULL /* ns */

typedef struct BackupBlockJob {
    BlockJob common;
    RateLimit limit;
    CoRwlock rwlock;
    uint64_t sectors_read;
    unsigned long *bitmap;
    int bitmap_size;
    BackupDumpFunc *backup_dump_cb;
    BlockDriverCompletionFunc *backup_complete_cb;
    void *opaque;
} BackupBlockJob;

static bool backup_get_bitmap(BackupBlockJob *job, int64_t cluster_num)
{
    assert(job);
    assert(job->bitmap);

    unsigned long val, idx, bit;

    idx = cluster_num / BITS_PER_LONG;

    assert(job->bitmap_size > idx);

    bit = cluster_num % BITS_PER_LONG;
    val = job->bitmap[idx];

    return !!(val & (1UL << bit));
}

static void backup_set_bitmap(BackupBlockJob *job, int64_t cluster_num,
                              bool dirty)
{
    assert(job);
    assert(job->bitmap);

    unsigned long val, idx, bit;

    idx = cluster_num / BITS_PER_LONG;

    assert(job->bitmap_size > idx);

    bit = cluster_num % BITS_PER_LONG;
    val = job->bitmap[idx];
    if (dirty) {
        val |= 1UL << bit;
    } else {
        val &= ~(1UL << bit);
    }
    job->bitmap[idx] = val;
}

static int coroutine_fn backup_do_cow(BlockDriverState *bs,
                                      int64_t sector_num, int nb_sectors)
{
    assert(bs);
    BackupBlockJob *job = (BackupBlockJob *)bs->job;
    assert(job);

    BlockDriver *drv = bs->drv;
    struct iovec iov;
    QEMUIOVector bounce_qiov;
    void *bounce_buffer = NULL;
    int ret = 0;

    qemu_co_rwlock_rdlock(&job->rwlock);

    int64_t start, end;

    start = sector_num / BACKUP_BLOCKS_PER_CLUSTER;
    end = (sector_num + nb_sectors + BACKUP_BLOCKS_PER_CLUSTER - 1) /
        BACKUP_BLOCKS_PER_CLUSTER;

    DPRINTF("brdv_co_backup_cow enter %s C%" PRId64 " %" PRId64 " %d\n",
            bdrv_get_device_name(bs), start, sector_num, nb_sectors);

    for (; start < end; start++) {
        bool zero = 0;

        if (backup_get_bitmap(job, start)) {
            DPRINTF("brdv_co_backup_cow skip C%" PRId64 "\n", start);
            continue; /* already copied */
        }

        /* immediately set bitmap (avoid coroutine race) */
        backup_set_bitmap(job, start, 1);

        DPRINTF("brdv_co_backup_cow C%" PRId64 "\n", start);

        if (!bounce_buffer) {
            iov.iov_len = BACKUP_CLUSTER_SIZE;
            iov.iov_base = bounce_buffer = qemu_blockalign(bs, iov.iov_len);
            qemu_iovec_init_external(&bounce_qiov, &iov, 1);
        }

#if USE_ALLOCATION_CHECK
        int n = 0;
        ret = bdrv_co_is_allocated_above(bs, NULL,
                                         start * BACKUP_BLOCKS_PER_CLUSTER,
                                         BACKUP_BLOCKS_PER_CLUSTER, &n);
        if (ret < 0) {
            DPRINTF("brdv_co_backup_cow is_allocated C%" PRId64 " failed\n",
                    start);
            goto out;
        }

        zero = (ret == 0) && (n == BACKUP_BLOCKS_PER_CLUSTER);

        if (!zero) {
#endif
            ret = drv->bdrv_co_readv(bs, start * BACKUP_BLOCKS_PER_CLUSTER,
                                     BACKUP_BLOCKS_PER_CLUSTER,
                                     &bounce_qiov);
            if (ret < 0) {
                DPRINTF("brdv_co_backup_cow bdrv_read C%" PRId64 " failed\n",
                        start);
                goto out;
            }
#if USE_ALLOCATION_CHECK
        }
#endif
        job->sectors_read += BACKUP_BLOCKS_PER_CLUSTER;

        ret = job->backup_dump_cb(job->opaque, bs, start,
                                  zero ? NULL : bounce_buffer);
        if (ret < 0) {
            DPRINTF("brdv_co_backup_cow dump_cluster_cb C%" PRId64 " failed\n",
                    start);
            goto out;
        }

        DPRINTF("brdv_co_backup_cow done C%" PRId64 "\n", start);
    }

out:
    if (bounce_buffer) {
        qemu_vfree(bounce_buffer);
    }

    qemu_co_rwlock_unlock(&job->rwlock);

    return ret;
}

static int coroutine_fn backup_before_read(BlockDriverState *bs,
                                           int64_t sector_num,
                                           int nb_sectors, QEMUIOVector *qiov)
{
    return backup_do_cow(bs, sector_num, nb_sectors);
}

static int coroutine_fn backup_before_write(BlockDriverState *bs,
                                            int64_t sector_num,
                                            int nb_sectors, QEMUIOVector *qiov)
{
    return backup_do_cow(bs, sector_num, nb_sectors);
}

static void backup_set_speed(BlockJob *job, int64_t speed, Error **errp)
{
    BackupBlockJob *s = container_of(job, BackupBlockJob, common);

    if (speed < 0) {
        error_set(errp, QERR_INVALID_PARAMETER, "speed");
        return;
    }
    ratelimit_set_speed(&s->limit, speed / BDRV_SECTOR_SIZE, SLICE_TIME);
}

static BlockJobType backup_job_type = {
    .instance_size = sizeof(BackupBlockJob),
    .before_read = backup_before_read,
    .before_write = backup_before_write,
    .job_type = "backup",
    .set_speed = backup_set_speed,
};

static void coroutine_fn backup_run(void *opaque)
{
    BackupBlockJob *job = opaque;
    BlockDriverState *bs = job->common.bs;
    assert(bs);

    int64_t start, end;

    start = 0;
    end = (bs->total_sectors + BACKUP_BLOCKS_PER_CLUSTER - 1) /
        BACKUP_BLOCKS_PER_CLUSTER;

    DPRINTF("backup_run start %s %" PRId64 " %" PRId64 "\n",
            bdrv_get_device_name(bs), start, end);

    int ret = 0;

    for (; start < end; start++) {
        if (block_job_is_cancelled(&job->common)) {
            ret = -1;
            break;
        }

        /* we need to yield so that qemu_aio_flush() returns.
         * (without, VM does not reboot)
         * Note: use 1000 instead of 0 (0 prioritize this task too much)
         */
        if (job->common.speed) {
            uint64_t delay_ns = ratelimit_calculate_delay(
                &job->limit, job->sectors_read);
            job->sectors_read = 0;
            block_job_sleep_ns(&job->common, rt_clock, delay_ns);
        } else {
            block_job_sleep_ns(&job->common, rt_clock, 1000);
        }

        if (block_job_is_cancelled(&job->common)) {
            ret = -1;
            break;
        }

        if (backup_get_bitmap(job, start)) {
            continue; /* already copied */
        }

        DPRINTF("backup_run loop C%" PRId64 "\n", start);

        /**
         * This triggers a cluster copy
         * Note: avoid direct call to brdv_co_backup_cow, because
         * this does not call tracked_request_begin()
         */
        ret = bdrv_co_backup(bs, start*BACKUP_BLOCKS_PER_CLUSTER, 1);
        if (ret < 0) {
            break;
        }
        /* Publish progress */
        job->common.offset += BACKUP_CLUSTER_SIZE;
    }

    /* wait until pending backup_do_cow()calls have completed */
    qemu_co_rwlock_wrlock(&job->rwlock);
    qemu_co_rwlock_unlock(&job->rwlock);

    DPRINTF("backup_run complete %d\n", ret);
    block_job_completed(&job->common, ret);
}

static void backup_job_cleanup_cb(void *opaque, int ret)
{
    BlockDriverState *bs = opaque;
    assert(bs);
    BackupBlockJob *job = (BackupBlockJob *)bs->job;
    assert(job);

    DPRINTF("backup_job_cleanup_cb start %d\n", ret);

    job->backup_complete_cb(job->opaque, ret);

    DPRINTF("backup_job_cleanup_cb end\n");

    g_free(job->bitmap);
}

void
backup_job_start(BlockDriverState *bs, bool cancel)
{
    assert(bs);
    assert(bs->job);
    assert(bs->job->co == NULL);

    if (cancel) {
        block_job_cancel(bs->job); /* set cancel flag */
    }

    bs->job->co = qemu_coroutine_create(backup_run);
    qemu_coroutine_enter(bs->job->co, bs->job);
}

int
backup_job_create(BlockDriverState *bs, BackupDumpFunc *backup_dump_cb,
                  BlockDriverCompletionFunc *backup_complete_cb,
                  void *opaque, int64_t speed)
{
    assert(bs);
    assert(backup_dump_cb);
    assert(backup_complete_cb);

    if (bs->job) {
        DPRINTF("bdrv_backup_init failed - running job on %s\n",
                bdrv_get_device_name(bs));
        return -1;
    }

    int64_t bitmap_size;
    const char *devname = bdrv_get_device_name(bs);

    if (!devname || !devname[0]) {
        return -1;
    }

    DPRINTF("bdrv_backup_init %s\n", bdrv_get_device_name(bs));

    Error *errp;
    BackupBlockJob *job = block_job_create(&backup_job_type, bs, speed,
                                           backup_job_cleanup_cb, bs, &errp);

    qemu_co_rwlock_init(&job->rwlock);

    job->common.cluster_size = BACKUP_CLUSTER_SIZE;

    bitmap_size = bs->total_sectors +
        BACKUP_BLOCKS_PER_CLUSTER * BITS_PER_LONG - 1;
    bitmap_size /= BACKUP_BLOCKS_PER_CLUSTER * BITS_PER_LONG;

    job->backup_dump_cb = backup_dump_cb;
    job->backup_complete_cb = backup_complete_cb;
    job->opaque = opaque;
    job->bitmap_size = bitmap_size;
    job->bitmap = g_new0(unsigned long, bitmap_size);

    job->common.len = bs->total_sectors*BDRV_SECTOR_SIZE;

    return 0;
}
