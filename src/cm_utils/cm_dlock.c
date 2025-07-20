/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
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
 * cm_dlock.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_dlock.c
 *
 * -------------------------------------------------------------------------
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "cm_log.h"
#include "cm_date.h"
#include "cm_utils.h"
#include "ddes_perctrl_api.h"
#include "cm_dlock.h"

const int BLOCK_NUMS = 3;
const uint32 LOCK_BLOCK_NUMS = 2;
const time_t MAX_VALID_LOCK_TIME = 125;
const time_t BASE_VALID_LOCK_TIME = 1;

time_t CalcLockTime(time_t lockTime)
{
    // system function execute lock cmd result range is [0, 127], 127 and 126 maybe system command failed result
    // so get lock time valid range is [1, 125]
    // 0:get lock success;-1:get lock failed and get lock time failed;[1,125]:get lock failed but get lock time success
    return lockTime % MAX_VALID_LOCK_TIME + BASE_VALID_LOCK_TIME;
}

static status_t cm_open_scsi_dev(const dlock_t *lock, const char *scsi_dev, int32 *fd)
{
#ifdef WIN32
#else
    if (lock == NULL || scsi_dev == NULL) {
        return CM_ERROR;
    }

    *fd = open(scsi_dev, O_RDWR | O_DIRECT | O_SYNC);
    if (*fd < 0) {
        LOG_RUN_ERR("Open dev %s failed, errno %d.", scsi_dev, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_alloc_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t errcode = EOK;
    uint64 buff_size = BLOCK_NUMS * CM_DEF_BLOCK_SIZE + DISK_LOCK_ALIGN_SIZE_512;
    uint64 offset;

    if (lock_addr % CM_DEF_BLOCK_SIZE != 0) {
        LOG_DEBUG_ERR("Invalid lock addr %llu, the addr value must be an integer multiple of the block size.",
            lock_addr);
        return CM_ERROR;
    }

    if (lock != NULL) {
        errcode = memset_sp(lock, sizeof(dlock_t), 0, sizeof(dlock_t));
        securec_check_ret(errcode);

        lock->buff = cm_malloc_prot(buff_size);
        if (lock->buff == NULL) {
            cm_reset_error();
            CM_THROW_ERROR(ERR_ALLOC_MEMORY, buff_size, "cm disk lock");
            return CM_ERROR;
        }

        errcode = memset_sp(lock->buff, buff_size, 0, buff_size);
        if (errcode != EOK) {
            CM_FREE_PROT_PTR(lock->buff);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }

        // three buff area, lockr buff|lockw buff|tmp buff
        offset = (DISK_LOCK_ALIGN_SIZE_512 - ((uint64)lock->buff) % DISK_LOCK_ALIGN_SIZE_512);
        lock->lockr = lock->buff + offset;
        lock->lockw = lock->lockr + CM_DEF_BLOCK_SIZE;
        lock->tmp = lock->lockw + CM_DEF_BLOCK_SIZE;

        errcode = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 1, CM_DEF_BLOCK_SIZE);
        if (errcode != EOK) {
            CM_FREE_PROT_PTR(lock->buff);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CM_ERROR;
        }

        cm_init_dlock_header(lock, lock_addr, inst_id);
    }

#endif
    return CM_SUCCESS;
}

status_t cm_init_dlock(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t errcode = EOK;
    uint64 buff_size = BLOCK_NUMS * CM_DEF_BLOCK_SIZE + DISK_LOCK_ALIGN_SIZE_512;

    if (lock != NULL) {
        errcode = memset_sp(lock->buff, buff_size, 0, buff_size);
        securec_check_ret(errcode);

        errcode = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 1, CM_DEF_BLOCK_SIZE);
        securec_check_ret(errcode);

        cm_init_dlock_header(lock, lock_addr, inst_id);
    }
#endif
    return CM_SUCCESS;
}

void cm_init_dlock_header(dlock_t *lock, uint64 lock_addr, int64 inst_id)
{
#ifdef WIN32
#else
    errno_t errcode = EOK;

    if (lock != NULL) {
        // clear lockr header
        errcode = memset_sp(lock->lockr, DISK_LOCK_HEADER_LEN, 0, DISK_LOCK_HEADER_LEN);
        if (errcode != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return;
        }

        // set lockw members
        // header magic num
        LOCKW_LOCK_MAGICNUM(*lock) = (int64)DISK_LOCK_HEADER_MAGIC;
        // tail magic num
        int64 *tail_magic = (int64 *)(lock->lockw + CM_DEF_BLOCK_SIZE - sizeof(int64));
        *tail_magic = (int64)DISK_LOCK_HEADER_MAGIC;
        LOCKW_INST_ID(*lock) = inst_id + 1;
        LOCKW_LOCK_VERSION(*lock) = DISK_LOCK_VERSION;
        lock->lock_addr = lock_addr;
    }
#endif
}

void cm_destory_dlock(dlock_t *lock)
{
#ifdef WIN32
#else
    if (lock->buff != NULL) {
        CM_FREE_PROT_PTR(lock->buff);
        lock->buff = NULL;
    }
#endif
    lock->buff = NULL;
}

int32 cm_disk_lock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    int32 ret;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    ret = cm_disk_lock(lock, fd, scsi_dev);
    if (CM_SUCCESS != ret) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_disk_timed_lock_s(dlock_t *lock, const char *scsi_dev, uint64 wait_usecs, int32 lock_interval,
    uint32 dlock_retry_count)
{
#ifdef WIN32
#else
    int32 fd = 0;
    status_t status;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    status = cm_disk_timed_lock(lock, fd, wait_usecs, lock_interval, dlock_retry_count, scsi_dev);
    if (CM_SUCCESS != status) {
        (void)close(fd);
        return status;
    }

    (void)close(fd);
    LOG_DEBUG_INF("end lock timeouts");
#endif
    return CM_SUCCESS;
}

int32 cm_disk_lockf_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    int32 ret;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    ret = cm_disk_lockf(lock, fd, scsi_dev);
    if (ret != CM_SUCCESS) {
        (void)close(fd);
        return ret;
    }

    (void)close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    status_t status;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    status = cm_disk_unlock(lock, fd, scsi_dev);
    if (CM_SUCCESS != status) {
        (void)close(fd);
        return status;
    }

    (void)close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlockf_s(dlock_t *lock, const char *scsi_dev, int64 old_inst_id)
{
#ifdef WIN32
#else
#endif
    return CM_SUCCESS;
}

int32 cm_preempt_dlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 ret;

    if (lock == NULL || scsi_dev == NULL) {
        return CM_ERROR;
    }

    ret = cm_preempt_dlock(lock, scsi_dev);
    if (CM_SUCCESS != ret) {
        return ret;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_erase_dlock_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 fd = 0;
    status_t status;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    status = cm_erase_dlock(lock, fd);
    if (CM_SUCCESS != status) {
        (void)close(fd);
        return status;
    }

    (void)close(fd);
#endif
    return CM_SUCCESS;
}

status_t cm_get_dlock_info_s(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 status;
    int32 fd = 0;

    CM_RETURN_IFERR(cm_open_scsi_dev(lock, scsi_dev, &fd));

    status = cm_get_dlock_info(lock, fd);
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Get lock info from dev %s failed.", scsi_dev);
        (void)close(fd);
        return status;
    }

    (void)close(fd);
#endif
    return CM_SUCCESS;
}

int32 cm_disk_lock(dlock_t *lock, int32 fd, const char *scsi_dev)
{
    if (lock == NULL || fd < 0) {
        return CM_ERROR;
    }

#ifdef WIN32
#else
    int32 buff_len = LOCK_BLOCK_NUMS * CM_DEF_BLOCK_SIZE;
    status_t status;
    LOG_DEBUG_INF("begin lock.");
    time_t t = time(NULL);
    LOCKW_LOCK_TIME(*lock) = CalcLockTime(t);
    LOCKW_LOCK_CREATE_TIME(*lock) = t;
    int32 ret = perctrl_scsi3_caw(scsi_dev, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE != ret) {
            LOG_RUN_ERR("Scsi3 caw failed, addr %llu, dev %s, errno %d.", lock->lock_addr, scsi_dev, errno);
            return CM_ERROR;
        }
    } else {
        LOG_DEBUG_INF("lock succ.");
        return CM_SUCCESS;
    }

    // there is a lock on disk, get lock info
    status = cm_get_dlock_info(lock, fd);
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Get lock info from dev failed.");
        return CM_ERROR;
    }
    LOG_DEBUG_INF("first lock occupied, fd %d, inst_id(disk) %lld, inst_id(lock) %lld.", fd, LOCKR_INST_ID(*lock),
        LOCKW_INST_ID(*lock));
    // if the owner of the lock on the disk is the current instance, we can lock succ
    LOCKR_INST_ID(*lock) = LOCKW_INST_ID(*lock);
    LOCKW_LOCK_CREATE_TIME(*lock) = LOCKR_LOCK_CREATE_TIME(*lock);
    ret = perctrl_scsi3_caw(scsi_dev, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE == ret) {
            // the lock is hold by another instance
            LOCKW_LOCK_TIME(*lock) = LOCKR_LOCK_TIME(*lock);
            return CM_DLOCK_ERR_LOCK_OCCUPIED;
        } else {
            LOG_RUN_ERR("Scsi3 caw failed, addr %llu, dev %s, errno %d.", lock->lock_addr, scsi_dev, errno);
            LOCKW_LOCK_TIME(*lock) = LOCKR_LOCK_TIME(*lock);
            return CM_ERROR;
        }
    }
#endif
    LOG_DEBUG_INF("lock succ.");
    return CM_SUCCESS;
}

status_t cm_disk_timed_lock(dlock_t *lock, int32 fd, uint64 wait_usecs, int32 lock_interval, uint32 dlock_retry_count,
    const char *scsi_dev)
{
#ifdef WIN32
    return CM_SUCCESS;
#else
    LOG_DEBUG_INF("Begin lock with time, fd %d.", fd);
    int32 ret = 0;
    uint64 usecs = 0;
    timeval_t tv_begin, tv_end;
    uint32 disk_lock_interval = DISK_DEFAULT_LOCK_INTERVAL;
    uint32 times = 0;

    if (lock == NULL || fd < 0) {
        return CM_ERROR;
    }

    if (lock_interval > 0) {
        disk_lock_interval = (uint32)lock_interval;
    }

    (void)cm_gettimeofday(&tv_begin);
    for (;;) {
        ret = cm_disk_lock(lock, fd, scsi_dev);
        if (ret == CM_SUCCESS) {
            LOG_DEBUG_INF("Lock with time succ.");
            return CM_SUCCESS;
        } else {
            if (ret == CM_DLOCK_ERR_LOCK_OCCUPIED) {
                LOG_DEBUG_INF("Lock occupied, try to lock again, fd %d.", fd);
            } else {
                LOG_RUN_ERR("Scsi3 caw failed, addr %llu, dev %s, errno %d.", lock->lock_addr, scsi_dev, errno);
                return CM_ERROR;
            }
        }

        (void)cm_gettimeofday(&tv_end);
        usecs = TIMEVAL_DIFF_US(&tv_begin, &tv_end);
        if (usecs >= wait_usecs) {
            LOG_DEBUG_INF("Lock with time timeout.");
            return CM_TIMEDOUT;
        }

        times++;
        if (times == dlock_retry_count) {
            cm_usleep(disk_lock_interval);
            times = 0;
        }
    }
#endif
}

int32 cm_disk_lockf(dlock_t *lock, int32 fd, const char *scsi_dev)
{
#ifdef WIN32
#else
    status_t status;
    int32 ret;

    if (lock == NULL || fd < 0) {
        return CM_ERROR;
    }

    status = cm_get_dlock_info(lock, fd);
    if (CM_SUCCESS != status) {
        LOG_DEBUG_ERR("Get lock info from dev failed, fd %d.", fd);
        return CM_ERROR;
    }

    ret = cm_disk_lock(lock, fd, scsi_dev);
    if (CM_SUCCESS != ret) {
        return ret;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlock_interal(dlock_t *lock, int32 fd, bool32 clean_body, const char *scsi_dev)
{
#ifdef WIN32
#else
    errno_t errcode;
    status_t status;
    int32 ret;
    int32 buff_len = LOCK_BLOCK_NUMS * CM_DEF_BLOCK_SIZE;

    if (lock == NULL || fd < 0) {
        return CM_ERROR;
    }

    status = cm_get_dlock_info(lock, fd);
    if (CM_SUCCESS != status) {
        LOG_RUN_ERR("Get lock info from dev failed, fd %d.", fd);
        return status;
    }

    if (LOCKR_INST_ID(*lock) == 0) {
        LOG_RUN_INF("Unlock succ, ther is no lock on disk.");
        return CM_SUCCESS;
    }

    if (LOCKR_INST_ID(*lock) != LOCKW_INST_ID(*lock)) {
        LOG_RUN_ERR("Unlock failed, this lock is held by another instance, another inst_id(disk) %lld, curr "
                      "inst_id(lock) %lld.",
            LOCKR_INST_ID(*lock), LOCKW_INST_ID(*lock));
        cm_reset_error();
        CM_THROW_ERROR(ERR_SCSI_LOCK_OCCUPIED, "");
        return CM_ERROR;
    }

    if (clean_body) {
        // clear write area for caw
        errcode = memset_sp(lock->lockw, CM_DEF_BLOCK_SIZE, 0, CM_DEF_BLOCK_SIZE);
        securec_check_ret(errcode);
    } else {
        // just clean lock header
        errcode = memcpy_s(lock->lockw, CM_DEF_BLOCK_SIZE, lock->lockr, CM_DEF_BLOCK_SIZE);
        securec_check_ret(errcode);
        errcode = memset_sp(lock->lockw, DISK_LOCK_HEADER_LEN, 0, DISK_LOCK_HEADER_LEN);
        securec_check_ret(errcode);
    }
    ret = perctrl_scsi3_caw(scsi_dev, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (CM_SUCCESS != ret) {
        LOG_RUN_ERR("Scsi3 caw failed, addr %llu, dev %s, ret %d, errno %d.", lock->lock_addr, scsi_dev, ret, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlock(dlock_t *lock, int32 fd, const char *scsi_dev)
{
#ifdef WIN32
#else
    status_t status;

    status = cm_disk_unlock_interal(lock, fd, CM_TRUE, scsi_dev);
    if (CM_SUCCESS != status) {
        return status;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlock_ex(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    status_t status;

    status = cm_disk_unlock_interal(lock, fd, CM_FALSE, NULL);
    if (CM_SUCCESS != status) {
        return status;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_disk_unlockf(dlock_t *lock, int32 fd, int64 old_inst_id)
{
#ifdef WIN32
#else
#endif
    return CM_SUCCESS;
}

static status_t cm_seek_dev(const dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    if (lock == NULL || fd < 0) {
        return CM_ERROR;
    }

    if (lseek64(fd, (off64_t)lock->lock_addr, SEEK_SET) == -1) {
        LOG_RUN_ERR("Seek failed, addr %llu, errno %d.", lock->lock_addr, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

status_t cm_erase_dlock(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    int32 size;

    CM_RETURN_IFERR(cm_seek_dev(lock, fd));
    size = write(fd, lock->lockr, CM_DEF_BLOCK_SIZE);
    if (size == -1) {
        LOG_RUN_ERR("Write failed, ret %d, errno %d.", size, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}

int32 cm_preempt_dlock(dlock_t *lock, const char *scsi_dev)
{
#ifdef WIN32
#else
    int32 ret;
    int32 buff_len = LOCK_BLOCK_NUMS * CM_DEF_BLOCK_SIZE;

    if (lock == NULL) {
        return CM_ERROR;
    }

    time_t t = time(NULL);
    LOCKW_LOCK_TIME(*lock) = t;
    LOCKW_LOCK_CREATE_TIME(*lock) = t;
    ret = perctrl_scsi3_caw(scsi_dev, lock->lock_addr / CM_DEF_BLOCK_SIZE, lock->lockr, buff_len);
    if (CM_SUCCESS != ret) {
        if (CM_SCSI_ERR_MISCOMPARE == ret) {
            return CM_DLOCK_ERR_LOCK_OCCUPIED;
        } else {
            LOG_RUN_ERR("Scsi3 caw failed, addr %llu, dev %s, errno %d.", lock->lock_addr, scsi_dev, errno);
            return CM_ERROR;
        }
    }
#endif
    return CM_SUCCESS;
}

status_t cm_get_dlock_info(dlock_t *lock, int32 fd)
{
#ifdef WIN32
#else
    int32 size;

    CM_RETURN_IFERR(cm_seek_dev(lock, fd));
    size = read(fd, lock->lockr, CM_DEF_BLOCK_SIZE);
    if (size == -1) {
        LOG_RUN_ERR("Read lockr info failed, ret %d, errno %d.", size, errno);
        return CM_ERROR;
    }
#endif
    return CM_SUCCESS;
}
status_t cm_check_dlock_remain(dlock_t *lock, int32 fd, bool32 *is_remain)
{
    *is_remain = CM_FALSE;
#ifdef WIN32
#else
    status_t status = cm_get_dlock_info(lock, fd);
    if (status != CM_SUCCESS) {
        return CM_ERROR;
    }
    if (LOCKR_INST_ID(*lock) == 0) {
        LOG_DEBUG_INF("there is no lock on disk.");
        return CM_SUCCESS;
    }

    if (LOCKR_INST_ID(*lock) != LOCKW_INST_ID(*lock)) {
        LOG_DEBUG_INF(
            "another inst_id(disk) %lld, curr inst_id(lock) %lld.", LOCKR_INST_ID(*lock), LOCKW_INST_ID(*lock));
        return CM_SUCCESS;
    }
    *is_remain = CM_TRUE;
#endif
    return CM_SUCCESS;
}
