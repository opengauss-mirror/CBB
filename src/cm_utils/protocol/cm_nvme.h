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
 * cm_nvme.h
 *
 *
 * IDENTIFICATION
 *    src/cm_protocol/cm_nvme.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _CM_NVME_H
#define _CM_NVME_H

#include <sys/types.h>
#include <linux/types.h>

#include "cm_types.h"
#include "cm_utils/cm_scsi.h"

#ifndef FORCE_CONVERT
#ifdef __CHECKER__
#define FORCE_CONVERT     __attribute__((force))
#else
#define FORCE_CONVERT
#endif
#endif

static inline __le16 cpu_to_le16(uint16 x)
{
    return (FORCE_CONVERT __le16)htole16(x);
}
static inline __le32 cpu_to_le32(uint32 x)
{
    return (FORCE_CONVERT __le32)htole32(x);
}
static inline __le64 cpu_to_le64(uint64 x)
{
    return (FORCE_CONVERT __le64)htole64(x);
}

static inline uint16 le16_to_cpu(__le16 x)
{
    return le16toh((FORCE_CONVERT __u16)x);
}
static inline uint32 le32_to_cpu(__le32 x)
{
    return le32toh((FORCE_CONVERT __u32)x);
}
static inline uint64 le64_to_cpu(__le64 x)
{
    return le64toh((FORCE_CONVERT __u64)x);
}

enum {
    CM_NVME_CMD_FUSE_FIRST = (1 << 0),
    CM_NVME_CMD_FUSE_SECOND    = (1 << 1),

    CM_NVME_CMD_SGL_METABUF    = (1 << 6),
    CM_NVME_CMD_SGL_METASEG    = (1 << 7),
    CM_NVME_CMD_SGL_ALL    = CM_NVME_CMD_SGL_METABUF | CM_NVME_CMD_SGL_METASEG,
};

enum {
    /*
     * Generic Command Status:
     */
    CM_NVME_SC_SUCCESS         = 0x0,
    CM_NVME_SC_INVALID_OPCODE      = 0x1,
    CM_NVME_SC_INVALID_FIELD       = 0x2,
    CM_NVME_SC_CMDID_CONFLICT      = 0x3,
    CM_NVME_SC_DATA_XFER_ERROR     = 0x4,
    CM_NVME_SC_POWER_LOSS      = 0x5,
    CM_NVME_SC_INTERNAL        = 0x6,
    CM_NVME_SC_ABORT_REQ       = 0x7,
    CM_NVME_SC_ABORT_QUEUE     = 0x8,
    CM_NVME_SC_FUSED_FAIL      = 0x9,
    CM_NVME_SC_FUSED_MISSING       = 0xa,
    CM_NVME_SC_INVALID_NS      = 0xb,
    CM_NVME_SC_CMD_SEQ_ERROR       = 0xc,
    CM_NVME_SC_SGL_INVALID_LAST    = 0xd,
    CM_NVME_SC_SGL_INVALID_COUNT   = 0xe,
    CM_NVME_SC_SGL_INVALID_DATA    = 0xf,
    CM_NVME_SC_SGL_INVALID_METADATA    = 0x10,
    CM_NVME_SC_SGL_INVALID_TYPE    = 0x11,
    CM_NVME_SC_CMB_INVALID_USE     = 0x12,
    CM_NVME_SC_PRP_INVALID_OFFSET  = 0x13,
    CM_NVME_SC_ATOMIC_WRITE_UNIT_EXCEEDED = 0x14,
    CM_NVME_SC_OPERATION_DENIED    = 0x15,
    CM_NVME_SC_SGL_INVALID_OFFSET  = 0x16,

    CM_NVME_SC_INCONSISTENT_HOST_ID = 0x18,
    CM_NVME_SC_KEEP_ALIVE_EXPIRED  = 0x19,
    CM_NVME_SC_KEEP_ALIVE_INVALID  = 0x1A,
    CM_NVME_SC_PREEMPT_ABORT       = 0x1B,
    CM_NVME_SC_SANITIZE_FAILED     = 0x1C,
    CM_NVME_SC_SANITIZE_IN_PROGRESS    = 0x1D,

    CM_NVME_SC_NS_WRITE_PROTECTED  = 0x20,
    CM_NVME_SC_CMD_INTERRUPTED     = 0x21,
    CM_NVME_SC_TRANSIENT_TRANSPORT = 0x22,

    CM_NVME_SC_LBA_RANGE       = 0x80,
    CM_NVME_SC_CAP_EXCEEDED        = 0x81,
    CM_NVME_SC_NS_NOT_READY        = 0x82,
    CM_NVME_SC_RESERVATION_CONFLICT    = 0x83,
    CM_NVME_SC_FORMAT_IN_PROGRESS  = 0x84,

    /*
     * Command Specific Status:
     */
    CM_NVME_SC_CQ_INVALID      = 0x100,
    CM_NVME_SC_QID_INVALID     = 0x101,
    CM_NVME_SC_QUEUE_SIZE      = 0x102,
    CM_NVME_SC_ABORT_LIMIT     = 0x103,
    CM_NVME_SC_ABORT_MISSING       = 0x104,
    CM_NVME_SC_ASYNC_LIMIT     = 0x105,
    CM_NVME_SC_FIRMWARE_SLOT       = 0x106,
    CM_NVME_SC_FIRMWARE_IMAGE      = 0x107,
    CM_NVME_SC_INVALID_VECTOR      = 0x108,
    CM_NVME_SC_INVALID_LOG_PAGE    = 0x109,
    CM_NVME_SC_INVALID_FORMAT      = 0x10a,
    CM_NVME_SC_FW_NEEDS_CONV_RESET = 0x10b,
    CM_NVME_SC_INVALID_QUEUE       = 0x10c,
    CM_NVME_SC_FEATURE_NOT_SAVEABLE    = 0x10d,
    CM_NVME_SC_FEATURE_NOT_CHANGEABLE  = 0x10e,
    CM_NVME_SC_FEATURE_NOT_PER_NS  = 0x10f,
    CM_NVME_SC_FW_NEEDS_SUBSYS_RESET   = 0x110,
    CM_NVME_SC_FW_NEEDS_RESET      = 0x111,
    CM_NVME_SC_FW_NEEDS_MAX_TIME   = 0x112,
    CM_NVME_SC_FW_ACTIVATE_PROHIBITED  = 0x113,
    CM_NVME_SC_OVERLAPPING_RANGE   = 0x114,
    CM_NVME_SC_NS_INSUFFICIENT_CAP = 0x115,
    CM_NVME_SC_NS_ID_UNAVAILABLE   = 0x116,
    CM_NVME_SC_NS_ALREADY_ATTACHED = 0x118,
    CM_NVME_SC_NS_IS_PRIVATE       = 0x119,
    CM_NVME_SC_NS_NOT_ATTACHED     = 0x11a,
    CM_NVME_SC_THIN_PROV_NOT_SUPP  = 0x11b,
    CM_NVME_SC_CTRL_LIST_INVALID   = 0x11c,
    CM_NVME_SC_DEVICE_SELF_TEST_IN_PROGRESS = 0x11d,
    CM_NVME_SC_BP_WRITE_PROHIBITED = 0x11e,
    CM_NVME_SC_INVALID_CTRL_ID     = 0x11f,
    CM_NVME_SC_INVALID_SECONDARY_CTRL_STATE = 0x120,
    CM_NVME_SC_INVALID_NUM_CTRL_RESOURCE   = 0x121,
    CM_NVME_SC_INVALID_RESOURCE_ID = 0x122,
    CM_NVME_SC_PMR_SAN_PROHIBITED  = 0x123,
    CM_NVME_SC_ANA_INVALID_GROUP_ID = 0x124,
    CM_NVME_SC_ANA_ATTACH_FAIL     = 0x125,

    /*
     * I/O Command Set Specific - NVM commands:
     */
    CM_NVME_SC_BAD_ATTRIBUTES      = 0x180,
    CM_NVME_SC_INVALID_PI      = 0x181,
    CM_NVME_SC_READ_ONLY       = 0x182,
    CM_NVME_SC_ONCS_NOT_SUPPORTED  = 0x183,

    /*
     * I/O Command Set Specific - Fabrics commands:
     */
    CM_NVME_SC_CONNECT_FORMAT      = 0x180,
    CM_NVME_SC_CONNECT_CTRL_BUSY   = 0x181,
    CM_NVME_SC_CONNECT_INVALID_PARAM   = 0x182,
    CM_NVME_SC_CONNECT_RESTART_DISC    = 0x183,
    CM_NVME_SC_CONNECT_INVALID_HOST    = 0x184,

    CM_NVME_SC_DISCOVERY_RESTART   = 0x190,
    CM_NVME_SC_AUTH_REQUIRED       = 0x191,

    /*
     * Media and Data Integrity Errors:
     */
    CM_NVME_SC_WRITE_FAULT     = 0x280,
    CM_NVME_SC_READ_ERROR      = 0x281,
    CM_NVME_SC_GUARD_CHECK     = 0x282,
    CM_NVME_SC_APPTAG_CHECK        = 0x283,
    CM_NVME_SC_REFTAG_CHECK        = 0x284,
    CM_NVME_SC_COMPARE_FAILED      = 0x285,
    CM_NVME_SC_ACCESS_DENIED       = 0x286,
    CM_NVME_SC_UNWRITTEN_BLOCK     = 0x287,

    /*
     * Path-related Errors:
     */
    CM_NVME_SC_ANA_PERSISTENT_LOSS = 0x301,
    CM_NVME_SC_ANA_INACCESSIBLE    = 0x302,
    CM_NVME_SC_ANA_TRANSITION      = 0x303,

    CM_NVME_SC_CRD         = 0x1800,
    CM_NVME_SC_DNR         = 0x4000,
};

struct nvme_user_io {
    uint8    opcode;
    uint8    flags;
    uint16    control;
    uint16    nblocks;
    uint16    rsvd;
    uint64    metadata;
    uint64    addr;
    uint64    slba;
    uint32    dsmgmt;
    uint32    reftag;
    uint16    apptag;
    uint16    appmask;
};

struct nvme_passthru_cmd {
    uint8    opcode;
    uint8    flags;
    uint16    rsvd1;
    uint32    nsid;
    uint32    cdw2;
    uint32    cdw3;
    uint64    metadata;
    uint64    addr;
    uint32    metadata_len;
    uint32    data_len;
    uint32    cdw10;
    uint32    cdw11;
    uint32    cdw12;
    uint32    cdw13;
    uint32    cdw14;
    uint32    cdw15;
    uint32    timeout_ms;
    uint32    result;
};


struct nvme_reservation_status {
    __le32  gen;
    uint8    rtype;
    uint8    regctl[2];
    uint8    resv5[2];
    uint8    ptpls;
    uint8    resv10[13];
    struct {
        __le16  cntlid;
        uint8    rcsts;
        uint8    resv3[5];
        __le64  hostid;
        __le64  rkey;
    } regctl_ds[];
};

struct nvme_reservation_status_ext {
    __le32  gen;
    uint8   rtype;
    uint8   regctl[2];
    uint8   resv5[2];
    uint8   ptpls;
    uint8   resv10[14];
    uint8   resv24[40];
    struct {
        __le16  cntlid;
        uint8   rcsts;
        uint8   resv3[5];
        __le64  rkey;
        uint8   hostid[16];
        uint8   resv32[32];
    } regctl_eds[];
};

/* I/O commands */
enum nvme_opcode {
    nvme_cmd_flush      = 0x00,
    nvme_cmd_write      = 0x01,
    nvme_cmd_read       = 0x02,
    nvme_cmd_write_uncor    = 0x04,
    nvme_cmd_compare    = 0x05,
    nvme_cmd_write_zeroes   = 0x08,
    nvme_cmd_dsm        = 0x09,
    nvme_cmd_verify     = 0x0c,
    nvme_cmd_resv_register  = 0x0d,
    nvme_cmd_resv_report    = 0x0e,
    nvme_cmd_resv_acquire   = 0x11,
    nvme_cmd_resv_release   = 0x15,
};

/* Admin commands */
enum nvme_admin_opcode {
    nvme_admin_delete_sq        = 0x00,
    nvme_admin_create_sq        = 0x01,
    nvme_admin_get_log_page     = 0x02,
    nvme_admin_delete_cq        = 0x04,
    nvme_admin_create_cq        = 0x05,
    nvme_admin_identify         = 0x06,
    nvme_admin_abort_cmd        = 0x08,
    nvme_admin_set_features     = 0x09,
    nvme_admin_get_features     = 0x0a,
    nvme_admin_async_event      = 0x0c,
    nvme_admin_ns_mgmt          = 0x0d,
    nvme_admin_activate_fw      = 0x10,
    nvme_admin_download_fw      = 0x11,
    nvme_admin_dev_self_test    = 0x14,
    nvme_admin_ns_attach        = 0x15,
    nvme_admin_keep_alive       = 0x18,
    nvme_admin_directive_send   = 0x19,
    nvme_admin_directive_recv   = 0x1a,
    nvme_admin_virtual_mgmt     = 0x1c,
    nvme_admin_nvme_mi_send     = 0x1d,
    nvme_admin_nvme_mi_recv     = 0x1e,
    nvme_admin_dbbuf            = 0x7C,
    nvme_admin_format_nvm       = 0x80,
    nvme_admin_security_send    = 0x81,
    nvme_admin_compare          = 0x81,
    nvme_admin_security_recv    = 0x82,
    nvme_admin_sanitize_nvm     = 0x84,
    nvme_admin_get_lba_status   = 0x86,
};

struct nvme_lbaf {
    __le16   ms;
    uint8    ds;
    uint8    rp;
};

struct nvme_id_ns {
    __le64              nsze;
    __le64              ncap;
    __le64              nuse;
    uint8               nsfeat;
    uint8               nlbaf;
    uint8               flbas;
    uint8               mc;
    uint8               dpc;
    uint8               dps;
    uint8               nmic;
    uint8               rescap;
    uint8               fpi;
    uint8               dlfeat;
    __le16              nawun;
    __le16              nawupf;
    __le16              nacwu;
    __le16              nabsn;
    __le16              nabo;
    __le16              nabspf;
    __le16              noiob;
    uint8               nvmcap[16];
    __le16              npwg;
    __le16              npwa;
    __le16              npdg;
    __le16              npda;
    __le16              nows;
    uint8               rsvd74[18];
    __le32              anagrpid;
    uint8               rsvd96[3];
    uint8               nsattr;
    __le16              nvmsetid;
    __le16              endgid;
    uint8               nguid[16];
    uint8               eui64[8];
    struct nvme_lbaf    lbaf[16];
    uint8               rsvd192[192];
    uint8               vs[3712];
};

struct nvme_id_power_state {
    __le16              max_power;  /* centiwatts */
    uint8               rsvd2;
    uint8               flags;
    __le32              entry_lat;  /* microseconds */
    __le32              exit_lat;   /* microseconds */
    uint8               read_tput;
    uint8               read_lat;
    uint8               write_tput;
    uint8               write_lat;
    __le16              idle_power;
    uint8               idle_scale;
    uint8               rsvd19;
    __le16              active_power;
    uint8               active_work_scale;
    uint8               rsvd23[9];
};

struct nvme_id_ctrl {
    __le16                      vid;
    __le16                      ssvid;
    char                        sn[20];
    char                        mn[40];
    char                        fr[8];
    uint8                       rab;
    uint8                       ieee[3];
    uint8                       cmic;
    uint8                       mdts;
    __le16                      cntlid;
    __le32                      ver;
    __le32                      rtd3r;
    __le32                      rtd3e;
    __le32                      oaes;
    __le32                      ctratt;
    __le16                      rrls;
    uint8                       rsvd102[9];
    uint8                       cntrltype;
    char                        fguid[16];
    __le16                      crdt1;
    __le16                      crdt2;
    __le16                      crdt3;
    uint8                       rsvd134[122];
    __le16                      oacs;
    uint8                       acl;
    uint8                       aerl;
    uint8                       frmw;
    uint8                       lpa;
    uint8                       elpe;
    uint8                       npss;
    uint8                       avscc;
    uint8                       apsta;
    __le16                      wctemp;
    __le16                      cctemp;
    __le16                      mtfa;
    __le32                      hmpre;
    __le32                      hmmin;
    uint8                       tnvmcap[16];
    uint8                       unvmcap[16];
    __le32                      rpmbs;
    __le16                      edstt;
    uint8                       dsto;
    uint8                       fwug;
    __le16                      kas;
    __le16                      hctma;
    __le16                      mntmt;
    __le16                      mxtmt;
    __le32                      sanicap;
    __le32                      hmminds;
    __le16                      hmmaxd;
    __le16                      nsetidmax;
    __le16                      endgidmax;
    uint8                       anatt;
    uint8                       anacap;
    __le32                      anagrpmax;
    __le32                      nanagrpid;
    __le32                      pels;
    uint8                       rsvd356[156];
    uint8                       sqes;
    uint8                       cqes;
    __le16                      maxcmd;
    __le32                      nn;
    __le16                      oncs;
    __le16                      fuses;
    uint8                       fna;
    uint8                       vwc;
    __le16                      awun;
    __le16                      awupf;
    uint8                       nvscc;
    uint8                       nwpc;
    __le16                      acwu;
    uint8                       rsvd534[2];
    __le32                      sgls;
    __le32                      mnan;
    uint8                       rsvd544[224];
    char                        subnqn[256];
    uint8                       rsvd1024[768];
    __le32                      ioccsz;
    __le32                      iorcsz;
    __le16                      icdoff;
    uint8                       ctrattr;
    uint8                       msdbd;
    uint8                       rsvd1804[244];
    struct nvme_id_power_state  psd[32];
    uint8                       vs[1024];
};

enum {
    /*
     * Generic VENDOR VID:
     */
    CM_NVME_VENDOR_HUAWEI        = 0x19e5,
    CM_NVME_VENDOR_HGST          = 0x0016,
    CM_NVME_VENDOR_INTEL         = 0x0020,
    CM_NVME_VENDOR_MICRON        = 0x0025,
    CM_NVME_VENDOR_SAMSUNG       = 0x0043,
    CM_NVME_VENDOR_TOSHIBA       = 0x004D,
    CM_NVME_VENDOR_SANDISK       = 0x007D,
    CM_NVME_VENDOR_KINGSTON      = 0x0108,
    CM_NVME_VENDOR_SKHYNIX       = 0x0116,
    CM_NVME_VENDOR_SEAGATE       = 0x0134,
    CM_NVME_VENDOR_PHISON        = 0x02C0,
    CM_NVME_VENDOR_SILICON       = 0x02D0,
    CM_NVME_VENDOR_ATP           = 0x02E0,
    CM_NVME_VENDOR_LITEON        = 0x0362,
    CM_NVME_VENDOR_WESTERN       = 0x0416,
    CM_NVME_VENDOR_TOSHIBAM      = 0x0451,
    CM_NVME_VENDOR_MARVELL       = 0x0462,
    CM_NVME_VENDOR_JMICRON       = 0x059B,
    CM_NVME_VENDOR_KINGSTOND     = 0x0953,
    CM_NVME_VENDOR_LENOVO        = 0x1000,
    CM_NVME_VENDOR_SKHYNIXMEMORY = 0x144D,
    CM_NVME_VENDOR_PHISONE       = 0x1C58,
    CM_NVME_VENDOR_CORSAIR       = 0x1FD4,
    CM_NVME_VENDOR_MAXIOTEK      = 0x6565,
    CM_NVME_VENDOR_GOOGLE        = 0x8649,
};

#define nvme_admin_cmd nvme_passthru_cmd


#define CM_NVME_TIMEOUT 60 // secs
#define NVME_IDENTIFY_DATA_SIZE 4096

#define NVME_IOCTL_ID        _IO('N', 0x40)
#define NVME_IOCTL_ADMIN_CMD    _IOWR('N', 0x41, struct nvme_admin_cmd)
#define NVME_IOCTL_SUBMIT_IO    _IOW('N', 0x42, struct nvme_user_io)
#define NVME_IOCTL_IO_CMD    _IOWR('N', 0x43, struct nvme_passthru_cmd)
#define NVME_IOCTL_RESET    _IO('N', 0x44)
#define NVME_IOCTL_SUBSYS_RESET    _IO('N', 0x45)
#define NVME_IOCTL_RESCAN    _IO('N', 0x46)

int32 cm_nvme_register(int32 fd, int64 nrkey);
int32 cm_nvme_unregister(int32 fd, int64 crkey);
int32 cm_nvme_reserve(int32 fd, int64 nrkey);
int32 cm_nvme_release(int32 fd, int64 crkey);
int32 cm_nvme_clear(int32 fd, int64 crkey);
int32 cm_nvme_preempt(int32 fd, int64 crkey, int64 nrkey);
int32 cm_nvme_rkeys(int32 fd, int64 *reg_keys, int32 *key_count, uint32 *generation);
int32 cm_nvme_rres(int32 fd, int64 *crkey, uint32 *generation);
int32 cm_nvme_read(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len);
int32 cm_nvme_write(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len);
int32 cm_nvme_caw(int32 fd, uint64 block_addr, uint16 block_count, char *buff, int32 buff_len);

// nvme inquiry(get lun info)
int32 cm_nvme_inql(int32 fd, inquiry_data_t *inquiry_data);

const char* cm_nvme_vid_to_vendor(uint16 vid);
const char* cm_nvme_status_to_string(uint32 status);


#endif /* _CM_NVME_H */