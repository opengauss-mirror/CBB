/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * CBB is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_disklock.c
 * 
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_disklock.c
 *
 * -------------------------------------------------------------------------
 */

#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "securec.h"
#include "cm_defs.h"
#include "cm_num.h"
#include "cm_types.h"
#include "cm_error.h"
#include "cm_encrypt.h"
#include "cm_date_to_text.h"

#include "cm_disklock.h"

#define CM_BLOCK_SIZE (512)
#define CM_ALIGN_SIZE (8192)
#define CM_LOCK_FULL_SIZE (CM_BLOCK_SIZE * (CM_MAX_INST_COUNT + 1))
#define CM_DL_MAGIC (0xFEDCBA9801234567ULL)
#define CM_DL_PROC_VER (1)
#define CM_MAX_RETRY_WAIT_TIME_MS (200)

typedef enum e_lockstatus { LS_NO_LOCK = 0, LS_PRE_LOCK = 1, LS_LOCKED = 2 } lockstatus_t;
typedef enum e_locktype { LT_NORMAL = 0, LT_LEASE = 1} locktype_t;
typedef enum e_checkperiod {CP_PRE_CHECK = 0, CP_CONFIRM = 1} checkperiod_t;

#ifdef __cplusplus
extern "C" {
#endif

typedef union u_dl_stat {
    struct {
        unsigned long long magic;
        unsigned long long proc_ver;
        unsigned long long inst_id;
        unsigned long long locked;
        unsigned long long lock_time;
        unsigned long long unlock_time;
    };
    struct {
        char placeholder[CM_BLOCK_SIZE];
    };
} dl_stat_t;

typedef struct st_dl_stat {
    unsigned long long peer_lock_time;
    unsigned long long lock_hb_time;
} dl_hb_t;

typedef struct st_dl_lock {
    char path[CM_MAX_PATH_SIZE];
    unsigned long long offset;
    unsigned long long inst_id;
    int fd;
    unsigned int lease_sec;
    locktype_t type;
    dl_stat_t *lock_stat;
    dl_hb_t *hb;
} cm_dl_t;

typedef struct st_dl_ctx {
    cm_dl_t lock_info[CM_MAX_DISKLOCK_COUNT];
    pthread_mutex_t lock;
} dl_ctx_t;

static dl_ctx_t g_dl_ctx;

static int cm_dl_unlock_inner(unsigned int lock_id, unsigned long long inst_id);

static inline unsigned long long cm_dl_now_ns()
{
    struct timespec tv;
    (void)clock_gettime(CLOCK_MONOTONIC, &tv);
    return (unsigned long long)tv.tv_sec * NANOSECS_PER_SECOND_LL + (unsigned long long)tv.tv_nsec;
}

unsigned int cm_dl_alloc(const char *path, unsigned long long offset, unsigned long long inst_id)
{
    if (path == NULL) {
        LOG_RUN_ERR("DL:invalid path[NULL].");
        return CM_INVALID_LOCK_ID;
    }

    size_t len = strlen(path);
    if (len == 0 || len > CM_MAX_PATH_SIZE - 1) {
        LOG_RUN_ERR("DL:invalid path length.");
        return CM_INVALID_LOCK_ID;
    }

    if ((offset & (CM_ALIGN_SIZE - 1)) != 0) {
        LOG_RUN_ERR("DL:invalid offset:not %d aligned.", CM_ALIGN_SIZE);
        return CM_INVALID_LOCK_ID;
    }

    if (inst_id >= CM_MAX_INST_COUNT) {
        LOG_RUN_ERR("DL:invalid inst_id[%lld].", inst_id);
        return CM_INVALID_LOCK_ID;
    }

    if (pthread_mutex_lock(&g_dl_ctx.lock) != 0) {
        LOG_RUN_ERR("DL:pthread_mutex_lock failed.");
        return CM_INVALID_LOCK_ID;
    }

    unsigned int id = 0;
    for (; id < CM_MAX_DISKLOCK_COUNT; id++) {
        if (g_dl_ctx.lock_info[id].fd <= 0) {
            g_dl_ctx.lock_info[id].fd = CM_MAX_INT32;
            break;
        }
    }

    if (pthread_mutex_unlock(&g_dl_ctx.lock) != 0) {
        LOG_RUN_ERR("DL:pthread_mutex_unlock failed.");
        return CM_INVALID_LOCK_ID;
    }

    if (id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:insufficient lock area.");
        return CM_INVALID_LOCK_ID;
    }

    int fd = open(path, O_RDWR | O_DIRECT | O_SYNC);
    if (fd <= 0) {
        (void)close(fd);
        g_dl_ctx.lock_info[id].fd = 0;
        LOG_RUN_ERR("DL:open path failed:%d,%s.", errno, strerror(errno));
        return CM_INVALID_LOCK_ID;
    }

    int64 size = lseek64(fd, 0, SEEK_END);
    if (size < (off_t)offset + CM_LOCK_FULL_SIZE) {
        (void)close(fd);
        g_dl_ctx.lock_info[id].fd = 0;
        LOG_RUN_ERR("DL:insufficient path size:%lld,%s.", size, strerror(errno));
        return CM_INVALID_LOCK_ID;
    }

    dl_stat_t *lock_stat = (dl_stat_t *)aligned_alloc(CM_BLOCK_SIZE, CM_BLOCK_SIZE * (CM_MAX_INST_COUNT + 1));
    if (lock_stat == NULL) {
        (void)close(fd);
        g_dl_ctx.lock_info[id].fd = 0;
        LOG_RUN_ERR("DL:insufficient memory.");
        return CM_INVALID_LOCK_ID;
    }

    errno_t errcode = strcpy_sp(g_dl_ctx.lock_info[id].path, CM_MAX_PATH_SIZE, path);
    if (errcode != EOK) {
        (void)close(fd);
        g_dl_ctx.lock_info[id].fd = 0;
        free(lock_stat);
        LOG_RUN_ERR("DL:strcpy_sp failed.");
        return CM_INVALID_LOCK_ID;
    }

    g_dl_ctx.lock_info[id].lock_stat = lock_stat;
    g_dl_ctx.lock_info[id].hb = NULL;
    g_dl_ctx.lock_info[id].fd = fd;
    g_dl_ctx.lock_info[id].offset = offset;
    g_dl_ctx.lock_info[id].inst_id = inst_id;
    g_dl_ctx.lock_info[id].type = LT_NORMAL;

    LOG_RUN_INF("DL:cm_dl_alloc succeed:%s:%lld.", path, offset);

    return id;
}

int cm_dl_dealloc(unsigned int lock_id)
{
    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    if (lock_info->fd <= 0) {
        LOG_RUN_ERR("DL:invalid lock not ready,lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    LOG_RUN_INF("DL:cm_dl_dealloc:%s:%lld.", lock_info->path, lock_info->offset);

    if (lock_info->lock_stat != NULL) {
        free(lock_info->lock_stat);
        lock_info->lock_stat = NULL;
    }

    if(lock_info->hb != NULL) {
        free(lock_info->hb);
        lock_info->hb = NULL;
    }

    (void)close(lock_info->fd);
    lock_info->fd = 0;

    return CM_SUCCESS;
}

static int cm_dl_check_lock(unsigned int lock_id, checkperiod_t checkperiod)
{
    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    dl_stat_t *lock_stat = lock_info->lock_stat;

    ssize_t size = pread(lock_info->fd, lock_stat, CM_LOCK_FULL_SIZE, (off_t)lock_info->offset);
    if (size != CM_LOCK_FULL_SIZE) {
        LOG_RUN_ERR("DL:read path failed:%d,%s.", errno, strerror(errno));
        return CM_DL_ERR_IO;
    }

    for (unsigned long long inst_id = 0; inst_id < CM_MAX_INST_COUNT; inst_id++) {
        if (inst_id == lock_info->inst_id) {
            continue;
        }
        
        lock_stat = &lock_info->lock_stat[inst_id + 1];
        if (lock_stat->magic != CM_DL_MAGIC) {
            continue;
        }

        if (lock_stat->locked == LS_NO_LOCK) {
            continue;
        }

        if (lock_info->type == LT_NORMAL) {
            return CM_DL_ERR_OCCUPIED;
        } else if (lock_info->type == LT_LEASE) {
            LOG_DEBUG_INF("DL:check lease:%d.", checkperiod);
            if (checkperiod == CP_CONFIRM) {
                LOG_DEBUG_INF("DL:return CM_DL_ERR_OCCUPIED lease:%d.", checkperiod);
                return CM_DL_ERR_OCCUPIED;
            }

            dl_hb_t *hb = &lock_info->hb[inst_id];
            LOG_DEBUG_INF("DL:lock_time=%lld,peer_lock_time=%lld.", lock_stat->lock_time, hb->peer_lock_time);
            if (lock_stat->lock_time != hb->peer_lock_time) {
                hb->peer_lock_time = lock_stat->lock_time;
                hb->lock_hb_time = cm_dl_now_ns();
                LOG_DEBUG_INF(
                    "DL:update hb:peer_lock_time=%lld,lock_hb_time=%lld", hb->peer_lock_time, hb->lock_hb_time);
            }

            LOG_DEBUG_INF("DL:now=%lld,lock_hb_time=%lld,lease_ns=%lld.", 
                cm_dl_now_ns(),
                hb->lock_hb_time, 
                lock_info->lease_sec * NANOSECS_PER_SECOND_LL);

            if (cm_dl_now_ns() - hb->lock_hb_time > lock_info->lease_sec * NANOSECS_PER_SECOND_LL) {
                LOG_DEBUG_INF("DL:release lock,inst_id=%llu", inst_id);
                cm_dl_unlock_inner(lock_id, inst_id);
            } else {
                LOG_DEBUG_INF("DL:CM_DL_ERR_OCCUPIED");
                return CM_DL_ERR_OCCUPIED;
            }
        }
    }

    return CM_SUCCESS;
}

static int cm_dl_lock_inner(unsigned int lock_id)
{
    int ret = 0;

    ret = cm_dl_check_lock(lock_id, CP_PRE_CHECK);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    dl_stat_t *lock_stat = &lock_info->lock_stat[lock_info->inst_id + 1];

    lock_stat->magic = CM_DL_MAGIC;
    lock_stat->proc_ver = CM_DL_PROC_VER;
    lock_stat->inst_id = lock_info->inst_id;
    lock_stat->lock_time = cm_dl_now_ns();
    lock_stat->locked = LS_PRE_LOCK;

    ssize_t size = pwrite(
        lock_info->fd, lock_stat, CM_BLOCK_SIZE, (off_t)(lock_info->offset + CM_BLOCK_SIZE * (lock_info->inst_id + 1)));
    if (size != CM_BLOCK_SIZE) {
        LOG_RUN_ERR("DL:write path failed:size=%lu,%d,%s.", size, errno, strerror(errno));
        return CM_DL_ERR_IO;
    }

    ret = cm_dl_check_lock(lock_id, CP_CONFIRM);
    if (ret != CM_SUCCESS) {
        (void)cm_dl_unlock_inner(lock_id, lock_info->inst_id);
        return ret;
    }

    lock_stat->locked = LS_LOCKED;
    size = pwrite(
        lock_info->fd, lock_stat, CM_BLOCK_SIZE, (off_t)(lock_info->offset + CM_BLOCK_SIZE * (lock_info->inst_id + 1)));
    if (size != CM_BLOCK_SIZE) {
        (void)cm_dl_unlock_inner(lock_id, lock_info->inst_id);
        LOG_RUN_ERR("DL:write path failed:size=%lu,%d,%s.", size, errno, strerror(errno));
        return CM_DL_ERR_IO;
    }

    return CM_SUCCESS;
}

int cm_dl_lock(unsigned int lock_id, int timeout_ms)
{
    int ret;

    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    if (lock_info->fd <= 0) {
        LOG_RUN_ERR("DL:invalid lock not ready,lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    unsigned long long start = cm_dl_now_ns();
    do {
        ret = cm_dl_lock_inner(lock_id);
        if (ret != CM_DL_ERR_OCCUPIED) {
            break;
        }

        unsigned long long now = cm_dl_now_ns();
        if (timeout_ms >= 0) {
            if (now - start > (unsigned long long)timeout_ms * NANOSECS_PER_MILLISECS_LL) {
                return CM_DL_ERR_TIMEOUT;
            }
        }

        unsigned long long random_time = 
            ((start + now) & (CM_MAX_INST_COUNT - 1)) * (CM_MAX_RETRY_WAIT_TIME_MS / CM_MAX_INST_COUNT) + 
            lock_info->inst_id;
        cm_sleep(random_time);
        LOG_DEBUG_INF("DL:wait for retry:%lldms.", random_time);
    } while (1);
        
    return ret;
}

static int cm_dl_unlock_inner(unsigned int lock_id, unsigned long long inst_id)
{
    if (inst_id >= CM_MAX_INST_COUNT) {
        LOG_RUN_ERR("DL:invalid inst_id[%lld].", inst_id);
        return CM_DL_ERR_INVALID_PARAM;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    dl_stat_t *lock_stat = &lock_info->lock_stat[inst_id + 1];

    lock_stat->magic = CM_DL_MAGIC;
    lock_stat->proc_ver = CM_DL_PROC_VER;
    lock_stat->inst_id = inst_id;
    lock_stat->unlock_time = cm_dl_now_ns();
    lock_stat->locked = LS_NO_LOCK;

    ssize_t size = 
        pwrite(lock_info->fd, lock_stat, CM_BLOCK_SIZE, (off_t)(lock_info->offset + CM_BLOCK_SIZE * (inst_id + 1)));
    if (size != CM_BLOCK_SIZE) {
        LOG_RUN_ERR("DL:write path failed:%d,%s.", errno, strerror(errno));
        return CM_DL_ERR_IO;
    }

    return CM_SUCCESS;
}

int cm_dl_unlock(unsigned int lock_id)
{
    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    if (lock_info->fd <= 0) {
        LOG_RUN_ERR("DL:invalid lock not ready,lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    return cm_dl_unlock_inner(lock_id, lock_info->inst_id);
}

int cm_dl_clean(unsigned int lock_id, unsigned long long inst_id)
{
    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    if (lock_info->fd <= 0) {
        LOG_RUN_ERR("DL:invalid lock not ready,lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    return cm_dl_unlock_inner(lock_id, inst_id);
}

static int cm_dl_getlockstat(unsigned int lock_id, dl_stat_t **lock_stat)
{
    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }

    if (lock_stat == NULL) {
        LOG_RUN_ERR("DL:invalid lock_stat.");
        return CM_DL_ERR_INVALID_PARAM;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    dl_stat_t *lock_stat_x = lock_info->lock_stat;

    ssize_t size = pread(lock_info->fd, lock_stat_x, CM_LOCK_FULL_SIZE, (off_t)lock_info->offset);
    if(size != CM_LOCK_FULL_SIZE) {
        LOG_RUN_ERR("DL:read path failed:%d,%s.", errno, strerror(errno));
        return CM_DL_ERR_IO;
    }

    *lock_stat = NULL;
    for (unsigned long long x_inst_id = 0; x_inst_id < CM_MAX_INST_COUNT; x_inst_id++) {
        if (lock_stat_x[x_inst_id + 1].locked == LS_LOCKED) {
            if (*lock_stat == NULL) {
                *lock_stat = &lock_stat_x[x_inst_id + 1];
            } else {
                LOG_RUN_ERR(
                    "DL:This lock hash more than one owner:inst1=%lld,inst2=%lld.", (*lock_stat)->inst_id, x_inst_id);
                return CM_DL_ERR_INVALID_LOCKSTAT;
            }
        }
    }

    return CM_SUCCESS;
}

int cm_dl_getowner(unsigned int lock_id, unsigned long long *inst_id)
{
    dl_stat_t *lock_stat = NULL;
    int ret = cm_dl_getlockstat(lock_id, &lock_stat);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (lock_stat == NULL) {
        *inst_id = CM_INVALID_INST_ID;
    } else {
        *inst_id = lock_stat->inst_id;
    }

    return CM_SUCCESS;
}

int cm_dl_getlocktime(unsigned int lock_id, unsigned long long *locktime)
{
    dl_stat_t *lock_stat = NULL;
    int ret = cm_dl_getlockstat(lock_id, &lock_stat);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    if (lock_stat == NULL) {
        *locktime = 0;
    } else {
        *locktime = lock_stat->lock_time;
    }

    return CM_SUCCESS;
}

unsigned int cm_dl_alloc_lease(
    const char *path, unsigned long long offset, unsigned long long inst_id, unsigned int lease_sec)
{
    unsigned int lock_id = cm_dl_alloc(path, offset, inst_id);
    if (lock_id == CM_INVALID_LOCK_ID) {
        return CM_INVALID_LOCK_ID;
    }

    dl_hb_t *hb = (dl_hb_t *)malloc(sizeof(dl_hb_t) * CM_MAX_INST_COUNT);
    if (hb == NULL) {
        cm_dl_dealloc(lock_id);
        LOG_RUN_ERR("DL:insufficient memory.");
        return CM_INVALID_LOCK_ID;
    }

    errno_t errcode = memset_sp(hb, sizeof(dl_hb_t) * CM_MAX_INST_COUNT, 0, sizeof(dl_hb_t) * CM_MAX_INST_COUNT);
    if (errcode != EOK) {
        cm_dl_dealloc(lock_id);
        free(hb);
        LOG_RUN_ERR("DL:memset_sp failed.");
        return CM_INVALID_LOCK_ID;
    }

    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    lock_info->type = LT_LEASE;
    lock_info->lease_sec = lease_sec;
    lock_info->hb = hb;

    return lock_id;
}

int cm_dl_check_lock_remain(unsigned int lock_id, unsigned long long inst_id, unsigned int *is_remain)
{
    *is_remain = CM_FALSE;
    if (lock_id >= CM_MAX_DISKLOCK_COUNT) {
        LOG_RUN_ERR("DL:invalid lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }
    cm_dl_t *lock_info = &g_dl_ctx.lock_info[lock_id];
    dl_stat_t *lock_stat = &lock_info->lock_stat[inst_id + 1];
    if (lock_info->fd <= 0) {
        LOG_RUN_ERR("DL:invalid lock not ready, lock_id:%u.", lock_id);
        return CM_DL_ERR_INVALID_LOCK_ID;
    }
    ssize_t size = pread(
        lock_info->fd, lock_stat, CM_BLOCK_SIZE, (off_t)(lock_info->offset + CM_BLOCK_SIZE * (inst_id + 1)));
    if(size != CM_BLOCK_SIZE) {
        LOG_RUN_ERR("DL:read path failed:%d,%s.", errno, strerror(errno));
        return CM_DL_ERR_IO;
    }
    if (lock_stat->locked != LS_NO_LOCK) {
        *is_remain = CM_TRUE;
    }
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif
