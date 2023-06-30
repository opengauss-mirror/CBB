/*
 * Copyright (c) 2023 Vastdata Technologies Co.,Ltd.
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
 * cm_nvme.c
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cm_nvme.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_nvme.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_binary.h"
#ifdef WIN32
#else
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#endif

#define PAGE_SIZE 4096

#define CM_SCSI_ERR_CONFLICT (-2)

int cm_nvme_get_nsid(int fd, int32 *nsid)
{
    static struct stat nvme_stat;

    int err = fstat(fd, &nvme_stat);
    if (err < 0)
        return CM_ERROR;

    if (!S_ISBLK(nvme_stat.st_mode)) {
        LOG_DEBUG_INF("Error: requesting namespace-id from non-block device\n");
        errno = ENOTBLK;
        return CM_ERROR;
    }

    *nsid = ioctl(fd, NVME_IOCTL_ID);
    if (*nsid == -1) {
        LOG_DEBUG_INF("ioctl get nsid error : %s\n", strerror(errno));
    }
    return CM_SUCCESS;
}

int cm_nvme_submit_passthru(int fd, unsigned long ioctl_cmd, struct nvme_passthru_cmd *cmd)
{
    return ioctl(fd, ioctl_cmd, cmd);
}

int cm_nvme_submit_admin_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
    return ioctl(fd, NVME_IOCTL_ADMIN_CMD, cmd);
}

int cm_nvme_submit_io_passthru(int fd, struct nvme_passthru_cmd *cmd)
{
    return ioctl(fd, NVME_IOCTL_IO_CMD, cmd);
}

int cm_nvme_io(int fd, uint8 opcode, uint8 flags, uint64 slba, uint16 nblocks, uint16 control,
               uint32 dsmgmt, uint32 reftag, uint16 apptag, uint16 appmask, void *data,
               void *metadata)
{
    struct nvme_user_io io = {
        .opcode     = opcode,
        .flags      = flags,
        .control    = control,
        .nblocks    = nblocks,
        .rsvd       = 0,
        .metadata   = (uint64)(uintptr_t) metadata,
        .addr       = (uint64)(uintptr_t) data,
        .slba       = slba,
        .dsmgmt     = dsmgmt,
        .reftag     = reftag,
        .appmask    = appmask,
        .apptag     = apptag,
    };
    return ioctl(fd, NVME_IOCTL_SUBMIT_IO, &io);
}

bool32 cm_nvme_is_rkey_exist(const int64 *reg_keys, int32 key_count, int64 rkey)
{
    int32 i;

    for (i = 0; i < key_count; i++) {
        if (*(reg_keys + i) == rkey) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}


int32 cm_nvme_register(int32 fd, int64 nrkey)
{
    uint8 rrega = 0;  // Register Reservation Key
    uint8 cptpl = 0;  // No change to Persist Through Power Loss State
    bool8 iekey = 0; // Ignore Existing Key
    uint64 crkey = 0; // Current Reservation Key
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
    uint32 cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) | (cptpl << 30);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_register,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        if (status == CM_NVME_SC_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("NVMe register get reservation confict return, nrkey %lld.", nrkey);
            return CM_SCSI_ERR_CONFLICT;
        } else {
            LOG_DEBUG_ERR("Sending NVMe register command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int32 cm_nvme_unregister(int32 fd, int64 crkey)
{
    uint8 rrega = 1;  // Unregister Reservation Key
    uint8 cptpl = 0;  // No change to Persist Through Power Loss State
    bool8 iekey = 0; //  Ignore Existing Key
    uint64 nrkey = 0; // New Reservation Key
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
    uint32 cdw10 = (rrega & 0x7) | (iekey ? 1 << 3 : 0) | (cptpl << 30);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_register,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        if (status == CM_NVME_SC_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("NVMe unregister get reservation confict return, crkey %lld.", crkey);
            return CM_SCSI_ERR_CONFLICT;
        } else {
            LOG_DEBUG_ERR("Sending NVMe unregister command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int32 cm_nvme_reserve(int32 fd, int64 crkey)
{
    bool8 iekey = 0; // Ignore Existing Key
    uint8 rtype = 0; // Reservation Type:Reserved
    uint8 rrela = 2; // Reservation Release Action:Reserved
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[1] = { cpu_to_le64(crkey) };
    uint32 cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_release,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        if (status == CM_NVME_SC_RESERVATION_CONFLICT) {
            LOG_DEBUG_INF("NVMe reserve get reservation confict return, crkey %lld.", crkey);
            return CM_SCSI_ERR_CONFLICT;
        } else {
            LOG_DEBUG_ERR("Sending NVMe reserve command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
            return CM_ERROR;
        }
    }

    return CM_SUCCESS;
}

int32 cm_nvme_release(int32 fd, int64 crkey)
{
    bool8 iekey = 0; // Ignore Existing Key
    uint8 rtype = 0; // Reservation Type:Reserved
    uint8 rrela = 0; // Reservation Release Action:Release
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[1] = { cpu_to_le64(crkey) };
    uint32 cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_release,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe release command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}


int32 cm_nvme_clear(int32 fd, int64 crkey)
{
    bool8 iekey = 0; // Ignore Existing Key
    uint8 rtype = 0; // Reservation Type:Reserved
    uint8 rrela = 1; // Reservation Release Action:Clear
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[1] = { cpu_to_le64(crkey) };
    uint32 cdw10 = (rrela & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_release,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe clear command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int32 cm_nvme_preempt(int32 fd, int64 crkey, int64 nrkey)
{
    bool8 iekey = 0; // Ignore Existing Key
    uint8 rtype = 0; // Reservation Type:Reserved
    uint8 racqa = 1; // Reservation Acquire Action: Preempt
    uint32 nsid = 0;
    int32 status = 0;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    __le64 payload[2] = { cpu_to_le64(crkey), cpu_to_le64(nrkey) };
    uint32 cdw10 = (racqa & 0x7) | (iekey ? 1 << 3 : 0) | (rtype << 8);

    struct nvme_passthru_cmd cmd = {
        .opcode         = nvme_cmd_resv_acquire,
        .nsid           = nsid,
        .cdw10          = cdw10,
        .addr           = (uint64)(uintptr_t) (payload),
        .data_len       = sizeof(payload),
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    status = cm_nvme_submit_io_passthru(fd, &cmd);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe preempt command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

int32 cm_nvme_resv_report(int fd, uint32 nsid, uint32 numd, __u32 cdw11, void *data)
{
    struct nvme_passthru_cmd cmd = {
        .opcode     = nvme_cmd_resv_report,
        .nsid       = nsid,
        .cdw10      = numd,
        .cdw11      = cdw11,
        .addr       = (uint64)(uintptr_t) data,
        .data_len   = (numd + 1) << 2,
        .timeout_ms     = CM_NVME_TIMEOUT * 1000,
    };

    return cm_nvme_submit_io_passthru(fd, &cmd);
}


int32 cm_nvme_rkeys(int32 fd, int64 *reg_keys, int32 *key_count, uint32 *generation)
{
    uint32 nsid = 0;
    int32 status = 0;
    int64 reg_key = 0;
    uint32 size = 0;
    int i = 0;
    int regctl = 0;
    int entries = 0;
    uint32 unique_keys_count = 0;

    struct nvme_reservation_status* res_status;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    size = ((*key_count) + 1) << 2;

    if (posix_memalign((void **)&res_status, getpagesize(), size)) {
        LOG_DEBUG_ERR("NVMe read keys failed:No memory for resv report:%d\n", size);
        return CM_ERROR;
    }

    securec_check_ret(memset_sp(res_status, size, 0, size));

    status = cm_nvme_resv_report(fd, nsid, *key_count, 1, res_status);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe read keys command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        free(res_status);
        return CM_ERROR;
    }

    *generation = le32_to_cpu(res_status->gen);
    regctl = (res_status->regctl[0]) | ((res_status->regctl[1]) << 8);
    entries = (size - 24) / 24;
    if (entries < regctl) {
        regctl = entries;
    }

    for (i = 0; i < regctl; i++) {
        reg_key = le64_to_cpu(res_status->regctl_ds[i].rkey);

        if (unique_keys_count >= *key_count) {
            LOG_DEBUG_ERR("NVMe read buff not engouth, rk %lld, key_count %d.", reg_key, *key_count);
            free(res_status);
            return CM_ERROR;
        }

        if (cm_nvme_is_rkey_exist(reg_keys, *key_count, reg_key)) {
            LOG_DEBUG_INF("NVMe read duplicate key %lld.", reg_key);
            continue;
        }

        *(reg_keys + unique_keys_count) = reg_key;
        unique_keys_count++;
        LOG_DEBUG_INF("NVMe read key %lld.", reg_key);
    }
    *key_count = unique_keys_count;
    free(res_status);

    return CM_SUCCESS;
}
int32 cm_nvme_rres(int32 fd, int64 *crkey, uint32 *generation)
{
    uint32 nsid = 0;
    int32 status = 0;
    uint32 size = 0;
    int regctl;

    struct nvme_reservation_status* res_status;

    CM_RETURN_IFERR(cm_nvme_get_nsid(fd, (int32*)(&nsid)));

    size = (PAGE_SIZE + 1) << 2;

    if (posix_memalign((void **)&res_status, getpagesize(), size)) {
        LOG_DEBUG_ERR("NVMe read keys failed:No memory for resv report:%d\n", size);
        return CM_ERROR;
    }

    securec_check_ret(memset_sp(res_status, size, 0, size));

    status = cm_nvme_resv_report(fd, nsid, PAGE_SIZE, 1, res_status);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe read keys command failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        free(res_status);
        return CM_ERROR;
    }

    *generation = le32_to_cpu(res_status->gen);
    regctl = res_status->regctl[0] | (res_status->regctl[1] << 8);

    if (regctl > 0) {
        *crkey = le64_to_cpu(res_status->regctl_ds[0].rkey);
        LOG_DEBUG_INF("NVMe read reservation key %lld.", *crkey);
    }

    free(res_status);

    return CM_SUCCESS;
}

// nvme vaai read
int32 cm_nvme_read(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    int32 status;
    uint8 opcode = nvme_cmd_read;
    uint8 flags = 0;
    uint64 slba = block_addr;
    uint16 nblocks = block_count - 1;
    uint16 control = 0;
    uint32 dsmgmt = 0;
    uint32 reftag = 0;
    uint16 apptag = 0;
    uint16 appmask = 0;
    void *data = buff;
    void *metadata  = 0;

    status = cm_nvme_io(fd, opcode, flags, slba, nblocks, control, dsmgmt, reftag, apptag, appmask, data, metadata);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe compare command in caw failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// nvme vaai write
int32 cm_nvme_write(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    int32 status;
    uint8 opcode = nvme_cmd_write;
    uint8 flags = 0;
    uint64 slba = block_addr;
    uint16 nblocks = block_count - 1;
    uint16 control = 0;
    uint32 dsmgmt = 0;
    uint32 reftag = 0;
    uint16 apptag = 0;
    uint16 appmask = 0;
    void *data = buff;
    void *metadata  = 0;

    status = cm_nvme_io(fd, opcode, flags, slba, nblocks, control, dsmgmt, reftag, apptag, appmask, data, metadata);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe compare command in caw failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

// nvme vaai compare and write
int32 cm_nvme_caw(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len)
{
    int32 status;
    uint8 opcode = nvme_cmd_compare;
    uint8 flags = 0;
    uint64 slba = block_addr;
    uint16 nblocks = (block_count / 2) - 1;
    uint16 control = 0;
    uint32 dsmgmt = 0;
    uint32 reftag = 0;
    uint16 apptag = 0;
    uint16 appmask = 0;
    void *data = buff;
    void *metadata  = 0;

    status = cm_nvme_io(fd, opcode, flags, slba, nblocks, control, dsmgmt, reftag, apptag, appmask, data, metadata);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe compare command in caw failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    opcode = nvme_cmd_write;
    data = buff + (buff_len / 2);
    status = cm_nvme_io(fd, opcode, flags, slba, nblocks, control, dsmgmt, reftag, apptag, appmask, data, metadata);
    if (status != CM_NVME_SC_SUCCESS) {
        LOG_DEBUG_ERR("Sending NVMe write command in caw failed, %s(%#x).", cm_nvme_status_to_string(status), status);
        return CM_ERROR;
    }

    return CM_SUCCESS;
}

const char* cm_nvme_status_to_string(uint32 status)
{
    switch (status & 0x3ff) {
    case CM_NVME_SC_SUCCESS:
        return "SUCCESS: The command completed successfully";
    case CM_NVME_SC_INVALID_OPCODE:
        return "INVALID_OPCODE: The associated command opcode field is not valid";
    case CM_NVME_SC_INVALID_FIELD:
        return "INVALID_FIELD: A reserved coded value or an unsupported value in a defined field";
    case CM_NVME_SC_CMDID_CONFLICT:
        return "CMDID_CONFLICT: The command identifier is already in use";
    case CM_NVME_SC_DATA_XFER_ERROR:
        return "DATA_XFER_ERROR: Error while trying to transfer the data or metadata";
    case CM_NVME_SC_POWER_LOSS:
        return "POWER_LOSS: Command aborted due to power loss notification";
    case CM_NVME_SC_INTERNAL:
        return "INTERNAL: The command was not completed successfully due to an internal error";
    case CM_NVME_SC_ABORT_REQ:
        return "ABORT_REQ: The command was aborted due to a Command Abort request";
    case CM_NVME_SC_ABORT_QUEUE:
        return "ABORT_QUEUE: The command was aborted due to a Delete I/O Submission Queue request";
    case CM_NVME_SC_FUSED_FAIL:
        return "FUSED_FAIL: The command was aborted due to the other command in a fused operation failing";
    case CM_NVME_SC_FUSED_MISSING:
        return "FUSED_MISSING: The command was aborted due to a Missing Fused Command";
    case CM_NVME_SC_INVALID_NS:
        return "INVALID_NS: The namespace or the format of that namespace is invalid";
    case CM_NVME_SC_CMD_SEQ_ERROR:
        return "CMD_SEQ_ERROR: The command was aborted due to a protocol violation in a multicommand sequence";
    case CM_NVME_SC_SGL_INVALID_LAST:
        return "SGL_INVALID_LAST: The command includes an invalid SGL Last Segment or SGL Segment descriptor.";
    case CM_NVME_SC_SGL_INVALID_COUNT:
        return "SGL_INVALID_COUNT: There is an SGL Last Segment descriptor or an SGL Segment descriptor in a"
               " location other than the last descriptor of a segment based on the length indicated.";
    case CM_NVME_SC_SGL_INVALID_DATA:
        return "SGL_INVALID_DATA: This may occur if the length of a Data SGL is too short.";
    case CM_NVME_SC_SGL_INVALID_METADATA:
        return "SGL_INVALID_METADATA: This may occur if the length of a Metadata SGL is too short";
    case CM_NVME_SC_SGL_INVALID_TYPE:
        return "SGL_INVALID_TYPE: The type of an SGL Descriptor is a type that is not supported by the controller.";
    case CM_NVME_SC_CMB_INVALID_USE:
        return "CMB_INVALID_USE: The attempted use of the Controller Memory Buffer is not supported by the controller.";
    case CM_NVME_SC_PRP_INVALID_OFFSET:
        return "PRP_INVALID_OFFSET: The Offset field for a PRP entry is invalid.";
    case CM_NVME_SC_ATOMIC_WRITE_UNIT_EXCEEDED:
        return "ATOMIC_WRITE_UNIT_EXCEEDED: The length specified exceeds the atomic write unit size.";
    case CM_NVME_SC_OPERATION_DENIED:
        return "OPERATION_DENIED: The command was denied due to lack of access rights.";
    case CM_NVME_SC_SGL_INVALID_OFFSET:
        return "SGL_INVALID_OFFSET: The offset specified in a descriptor is invalid.";
    case CM_NVME_SC_INCONSISTENT_HOST_ID:
        return "INCONSISTENT_HOST_ID: The NVM subsystem detected the simultaneous use of 64-bit and 128-bit Host"
               " Identifier values on different controllers.";
    case CM_NVME_SC_KEEP_ALIVE_EXPIRED:
        return "KEEP_ALIVE_EXPIRED: The Keep Alive Timer expired.";
    case CM_NVME_SC_KEEP_ALIVE_INVALID:
        return "KEEP_ALIVE_INVALID: The Keep Alive Timeout value specified is invalid.";
    case CM_NVME_SC_PREEMPT_ABORT:
        return "PREEMPT_ABORT: The command was aborted due to a Reservation Acquire command with the Reservation"
               " Acquire Action (RACQA) set to 010b (Preempt and Abort).";
    case CM_NVME_SC_SANITIZE_FAILED:
        return "SANITIZE_FAILED: The most recent sanitize operation failed and no recovery actions has been"
               " successfully completed";
    case CM_NVME_SC_SANITIZE_IN_PROGRESS:
        return "SANITIZE_IN_PROGRESS: The requested function is prohibited while a sanitize operation is in progress";
    case CM_NVME_SC_LBA_RANGE:
        return "LBA_RANGE: The command references a LBA that exceeds the size of the namespace";
    case CM_NVME_SC_NS_WRITE_PROTECTED:
        return "NS_WRITE_PROTECTED: The command is prohibited while the namespace is write protected by the host.";
    case CM_NVME_SC_TRANSIENT_TRANSPORT:
        return "TRANSIENT_TRANSPORT: A transient transport error was detected.";
    case CM_NVME_SC_CAP_EXCEEDED:
        return "CAP_EXCEEDED: The execution of the command has caused the capacity of the namespace to be exceeded";
    case CM_NVME_SC_NS_NOT_READY:
        return "NS_NOT_READY: The namespace is not ready to be accessed as a result of a condition other than a"
               " condition that is reported as an Asymmetric Namespace Access condition";
    case CM_NVME_SC_RESERVATION_CONFLICT:
        return "RESERVATION_CONFLICT: The command was aborted due to a conflict with a reservation held on"
               " the accessed namespace";
    case CM_NVME_SC_FORMAT_IN_PROGRESS:
        return "FORMAT_IN_PROGRESS: A Format NVM command is in progress on the namespace.";
    case CM_NVME_SC_CQ_INVALID:
        return "CQ_INVALID: The Completion Queue identifier specified in the command does not exist";
    case CM_NVME_SC_QID_INVALID:
        return "QID_INVALID: The creation of the I/O Completion Queue failed due to an invalid queue identifier"
               " specified as part of the command. An invalid queue identifier is one that is currently in use"
               " or one that is outside the range supported by the controller";
    case CM_NVME_SC_QUEUE_SIZE:
        return "QUEUE_SIZE: The host attempted to create an I/O Completion Queue with an invalid number of entries";
    case CM_NVME_SC_ABORT_LIMIT:
        return "ABORT_LIMIT: The number of concurrently outstanding Abort commands has exceeded the limit indicated"
               " in the Identify Controller data structure";
    case CM_NVME_SC_ABORT_MISSING:
        return "ABORT_MISSING: The abort command is missing";
    case CM_NVME_SC_ASYNC_LIMIT:
        return "ASYNC_LIMIT: The number of concurrently outstanding Asynchronous Event Request commands"
               " has been exceeded";
    case CM_NVME_SC_FIRMWARE_SLOT:
        return "FIRMWARE_SLOT: The firmware slot indicated is invalid or read only. This error is indicated if the"
               " firmware slot exceeds the number supported";
    case CM_NVME_SC_FIRMWARE_IMAGE:
        return "FIRMWARE_IMAGE: The firmware image specified for activation is invalid and not loaded"
               " by the controller";
    case CM_NVME_SC_INVALID_VECTOR:
        return "INVALID_VECTOR: The creation of the I/O Completion Queue failed due to an invalid interrupt vector"
               " specified as part of the command";
    case CM_NVME_SC_INVALID_LOG_PAGE:
        return "INVALID_LOG_PAGE: The log page indicated is invalid. This error condition is also returned if a"
               " reserved log page is requested";
    case CM_NVME_SC_INVALID_FORMAT:
        return "INVALID_FORMAT: The LBA Format specified is not supported. This may be due to various conditions";
    case CM_NVME_SC_FW_NEEDS_CONV_RESET:
        return "FW_NEEDS_CONVENTIONAL_RESET: The firmware commit was successful, however, activation of the firmware"
               " image requires a conventional reset";
    case CM_NVME_SC_INVALID_QUEUE:
        return "INVALID_QUEUE: This error indicates that it is invalid to delete the I/O Completion Queue specified."
               " The typical reason for this error condition is that there is an associated I/O Submission Queue"
               " that has not been deleted.";
    case CM_NVME_SC_FEATURE_NOT_SAVEABLE:
        return "FEATURE_NOT_SAVEABLE: The Feature Identifier specified does not support a saveable value";
    case CM_NVME_SC_FEATURE_NOT_CHANGEABLE:
        return "FEATURE_NOT_CHANGEABLE: The Feature Identifier is not able to be changed";
    case CM_NVME_SC_FEATURE_NOT_PER_NS:
        return "FEATURE_NOT_PER_NS: The Feature Identifier specified is not namespace specific. The Feature Identifier"
               " settings apply across all namespaces";
    case CM_NVME_SC_FW_NEEDS_SUBSYS_RESET:
        return "FW_NEEDS_SUBSYSTEM_RESET: The firmware commit was successful, however, activation of the firmware image"
               " requires an NVM Subsystem";
    case CM_NVME_SC_FW_NEEDS_RESET:
        return "FW_NEEDS_RESET: The firmware commit was successful; however, the image specified does not support being"
               " activated without a reset";
    case CM_NVME_SC_FW_NEEDS_MAX_TIME:
        return "FW_NEEDS_MAX_TIME_VIOLATION: The image specified if activated immediately would exceed"
               " the Maximum Time for Firmware Activation (MTFA) value reported in Identify Controller."
               " To activate the firmware, the Firmware Commit command needs to be re-issued"
               " and the image activated using a reset";
    case CM_NVME_SC_FW_ACTIVATE_PROHIBITED:
        return "FW_ACTIVATION_PROHIBITED: The image specified is being prohibited from activation by the controller"
               " for vendor specific reasons";
    case CM_NVME_SC_OVERLAPPING_RANGE:
        return "OVERLAPPING_RANGE: This error is indicated if the firmware image has overlapping ranges";
    case CM_NVME_SC_NS_INSUFFICIENT_CAP:
        return "NS_INSUFFICIENT_CAPACITY: Creating the namespace requires more free space than is currently available."
               " The Command Specific Information field of the Error Information Log specifies"
               " the total amount of NVM capacity required to create the namespace in bytes";
    case CM_NVME_SC_NS_ID_UNAVAILABLE:
        return "NS_ID_UNAVAILABLE: The number of namespaces supported has been exceeded";
    case CM_NVME_SC_NS_ALREADY_ATTACHED:
        return "NS_ALREADY_ATTACHED: The controller is already attached to the namespace specified";
    case CM_NVME_SC_NS_IS_PRIVATE:
        return "NS_IS_PRIVATE: The namespace is private and is already attached to one controller";
    case CM_NVME_SC_NS_NOT_ATTACHED:
        return "NS_NOT_ATTACHED: The request to detach the controller could not be completed because"
               " the controller is not attached to the namespace";
    case CM_NVME_SC_THIN_PROV_NOT_SUPP:
        return "THIN_PROVISIONING_NOT_SUPPORTED: Thin provisioning is not supported by the controller";
    case CM_NVME_SC_CTRL_LIST_INVALID:
        return "CONTROLLER_LIST_INVALID: The controller list provided is invalid";
    case CM_NVME_SC_DEVICE_SELF_TEST_IN_PROGRESS:
        return "DEVICE_SELF_TEST_IN_PROGRESS: The controller or NVM subsystem already has"
               " a device self-test operation in process.";
    case CM_NVME_SC_BP_WRITE_PROHIBITED:
        return "BOOT PARTITION WRITE PROHIBITED: The command is trying to modify a Boot Partition while it is locked";
    case CM_NVME_SC_INVALID_CTRL_ID:
        return "INVALID_CTRL_ID: An invalid Controller Identifier was specified.";
    case CM_NVME_SC_INVALID_SECONDARY_CTRL_STATE:
        return "INVALID_SECONDARY_CTRL_STATE: The action requested for the secondary controller is invalid based"
               " on the current state of the secondary controller and its primary controller.";
    case CM_NVME_SC_INVALID_NUM_CTRL_RESOURCE:
        return "INVALID_NUM_CTRL_RESOURCE: The specified number of Flexible Resources is invalid";
    case CM_NVME_SC_INVALID_RESOURCE_ID:
        return "INVALID_RESOURCE_ID: At least one of the specified resource identifiers was invalid";
    case CM_NVME_SC_ANA_INVALID_GROUP_ID:
        return "ANA_INVALID_GROUP_ID: The specified ANA Group Identifier (ANAGRPID) is not supported"
               " in the submitted command.";
    case CM_NVME_SC_ANA_ATTACH_FAIL:
        return "ANA_ATTACH_FAIL: The controller is not attached to the namespace as a result of an ANA condition";
    case CM_NVME_SC_BAD_ATTRIBUTES:
        return "BAD_ATTRIBUTES: Bad attributes were given";
    case CM_NVME_SC_WRITE_FAULT:
        return "WRITE_FAULT: The write data could not be committed to the media";
    case CM_NVME_SC_READ_ERROR:
        return "READ_ERROR: The read data could not be recovered from the media";
    case CM_NVME_SC_GUARD_CHECK:
        return "GUARD_CHECK: The command was aborted due to an end-to-end guard check failure";
    case CM_NVME_SC_APPTAG_CHECK:
        return "APPTAG_CHECK: The command was aborted due to an end-to-end application tag check failure";
    case CM_NVME_SC_REFTAG_CHECK:
        return "REFTAG_CHECK: The command was aborted due to an end-to-end reference tag check failure";
    case CM_NVME_SC_COMPARE_FAILED:
        return "COMPARE_FAILED: The command failed due to a miscompare during a Compare command";
    case CM_NVME_SC_ACCESS_DENIED:
        return "ACCESS_DENIED: Access to the namespace and/or LBA range is denied due to lack of access rights";
    case CM_NVME_SC_UNWRITTEN_BLOCK:
        return "UNWRITTEN_BLOCK: The command failed due to an attempt to read from an LBA range containing"
               " a deallocated or unwritten logical block";
    case CM_NVME_SC_ANA_PERSISTENT_LOSS:
        return "ASYMMETRIC_NAMESPACE_ACCESS_PERSISTENT_LOSS: The requested function (e.g., command)"
               " is not able to be performed as a result of the relationship between the controller"
               " and the namespace being in the ANA Persistent Loss state";
    case CM_NVME_SC_ANA_INACCESSIBLE:
        return "ASYMMETRIC_NAMESPACE_ACCESS_INACCESSIBLE: The requested function (e.g., command)"
               " is not able to be performed as a result of the relationship between the controller"
               " and the namespace being in the ANA Inaccessible state";
    case CM_NVME_SC_ANA_TRANSITION:
        return "ASYMMETRIC_NAMESPACE_ACCESS_TRANSITION: The requested function (e.g., command)"
               " is not able to be performed as a result of the relationship between the controller"
               " and the namespace transitioning between Asymmetric Namespace Access states";
    case CM_NVME_SC_CMD_INTERRUPTED:
        return "CMD_INTERRUPTED: Command processing was interrupted and the controller is unable"
               " to successfully complete the command. The host should retry the command.";
    case CM_NVME_SC_PMR_SAN_PROHIBITED:
        return "Sanitize Prohibited While Persistent Memory Region is Enabled: A sanitize operation"
               " is prohibited while the Persistent Memory Region is enabled.";
    default:
        return "Unknown";
    }
}