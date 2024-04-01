/*
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * cm_system.c
 *
 *
 * IDENTIFICATION
 *    src/cm_utils/cm_system.c
 *
 * -------------------------------------------------------------------------
 */
#include <signal.h>
#include "cm_spinlock.h"
#include "cm_text.h"
#include "cm_system.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <pwd.h>
#include <fcntl.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#pragma warning(disable : 4996)  // avoid GetVersionEx to be warned
#endif

static const bool32 volatile g_system_initialized = CM_FALSE;
static spinlock_t g_system_lock;
static char g_program_name[CM_FILE_NAME_BUFFER_SIZE + 1] = {0};
static char g_user_name[CM_NAME_BUFFER_SIZE] = {0};
static char g_host_name[CM_HOST_NAME_BUFFER_SIZE] = {0};
static char g_platform_name[CM_NAME_BUFFER_SIZE] = {0};
static uint64 g_process_id = 0;

static void cm_get_host_name(void)
{
    (void)gethostname(g_host_name, CM_HOST_NAME_BUFFER_SIZE);
}

static void cm_get_process_id(void)
{
#ifdef WIN32
    g_process_id = (uint64)GetCurrentProcessId();
#else
    g_process_id = (uint64)getpid();
#endif
}

static void cm_get_program_name(void)
{
    int64 len;
#ifdef WIN32
    len = GetModuleFileName(NULL, g_program_name, CM_FILE_NAME_BUFFER_SIZE);
#elif defined(AIX)
    pid_t pid;
    struct procentry64 processInfo;

    while (getprocs64(&processInfo, sizeof(processInfo), 0, 0, &pid, 1) > 0) {
        if ((uint64)(processInfo.pi_pid) == g_process_id) {
            len = getargs(&processInfo, sizeof(processInfo), g_program_name, CM_FILE_NAME_BUFFER_SIZE);
            break;
        }
    }
#else /* linux */
    len = readlink("/proc/self/exe", g_program_name, CM_FILE_NAME_BUFFER_SIZE);
    if (len > 0) {
        g_program_name[len] = '\0';
        return;
    }
#endif

    // Handle error, just set the error information into audit log, and
    // set g_program_name as empty, here We do not return Error, as the
    // architecture is hard to be allowed
    if (len == 0) {
        CM_THROW_ERROR(ERR_SYSTEM_CALL, cm_get_os_error());
        if (snprintf_s(g_program_name, CM_FILE_NAME_BUFFER_SIZE, CM_FILE_NAME_BUFFER_SIZE - 1, "<empty>") == -1) {
            cm_panic(0);
        }
    }
}

static void cm_get_user_name(void)
{
#ifdef WIN32
    uint32 size = CM_NAME_BUFFER_SIZE;
    GetUserName(g_user_name, &size);
#else
    struct passwd *pw = getpwuid(geteuid());
    uint32 name_len;
    if (pw == NULL) {
        g_user_name[0] = '\0';
        return;
    }

    name_len = (uint32)strlen(pw->pw_name);
    if (strncpy_s(g_user_name, CM_NAME_BUFFER_SIZE, pw->pw_name, name_len) != EOK) {
        cm_panic(0);
    }
#endif
}

static void cm_get_linux_platform_name(void)
{
    FILE *fp = fopen("/etc/system-release", "r");
    if (fp == NULL) {
        fp = fopen("/etc/SuSE-release", "r");
        if (fp == NULL) {
            g_platform_name[0] = '\0';
            return;
        }
    }

    if (fgets(g_platform_name, sizeof(g_platform_name) - 1, fp) == NULL) {
        g_platform_name[0] = '\0';
    }
    fclose(fp);
}

static void cm_get_platform_name(void)
{
#ifdef WIN32
    static char *platform_name = "";
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (!GetVersionEx(&osvi)) {
        g_platform_name[0] = '\0';
        return;
    }

    if (osvi.dwMajorVersion == 5) {
        switch (osvi.dwMinorVersion) {
            case 0:
                platform_name = "Windows 2000";
                break;
            case 1:
                platform_name = "Windows XP";
                break;
            case 2:
                platform_name = "Windows Server 2003";
                break;
            default:
                platform_name = "Unknown System";
                break;
        }
    } else if (osvi.dwMajorVersion == 6) {
        switch (osvi.dwMinorVersion) {
            case 0:
                platform_name = "Windows Vista";
                break;
            case 1:
                platform_name = "Windows 7";
                break;
            case 2:
                platform_name = "Windows 8";
                break;
            default:
                platform_name = "Unknown System";
                break;
        }
    } else if (osvi.dwMajorVersion == 10) {
        platform_name = "Windows 10";
    } else {
        platform_name = "Unknown System";
    }
    errno_t errcode = strncpy_s(g_platform_name, CM_NAME_BUFFER_SIZE, platform_name, strlen(platform_name));
    if (errcode != EOK) {
        cm_panic(0);
    }
#else
    cm_get_linux_platform_name();
#endif
}

void cm_try_init_system(void)
{
    if (g_system_initialized) {
        return;
    }

    cm_spin_lock(&g_system_lock, NULL);

    if (g_system_initialized) {
        cm_spin_unlock(&g_system_lock);
        return;
    }

    cm_get_process_id();
    cm_get_host_name();
    cm_get_user_name();
    cm_get_program_name();
    cm_get_platform_name();

    cm_spin_unlock(&g_system_lock);
}

uint64 cm_sys_pid(void)
{
    cm_try_init_system();
    return g_process_id;
}

char *cm_sys_program_name(void)
{
    cm_try_init_system();
    return g_program_name;
}

char *cm_sys_user_name(void)
{
    cm_try_init_system();
    return g_user_name;
}

char *cm_sys_host_name(void)
{
    cm_try_init_system();
    return g_host_name;
}

char *cm_sys_platform_name(void)
{
    cm_try_init_system();
    return g_platform_name;
}

#ifdef WIN32

static time_t cm_convert_filetime(FILETIME *ft)
{
    ULARGE_INTEGER ull;
    CM_ASSERT(ft != NULL);
    ull.LowPart = ft->dwLowDateTime;
    ull.HighPart = ft->dwHighDateTime;
    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}
#endif

status_t cm_sys_process_start_time(uint64 pid, int64 *process_time)
{
#ifdef WIN32
    FILETIME create_time, exit_time, kernel_time, user_time;
    HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (handle == 0) {
        return CM_ERROR;
    }
    if (GetProcessTimes(handle, &create_time, &exit_time, &kernel_time, &user_time) != 0) {
        CloseHandle(handle);
        return CM_ERROR;
    }
    CloseHandle(handle);
    *process_time = (int64)cm_convert_filetime(&create_time);
    return CM_SUCCESS;
#else
    char path[32] = {0};
    char stat_buf[2048];
    int32 size, ret;
    int64 ticks;
    text_t stat_text, ticks_text;
    if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%llu/stat", pid) == -1) {
        cm_panic(0);
    }
    int32 fd = open(path, O_RDONLY);
    if (fd == -1) {
        LOG_RUN_INF("[PROCESS]failed to open file with handle %d, error code %d, can not get process stat", fd, errno);
        return CM_ERROR;
    }
    size = (int32)read(fd, stat_buf, sizeof(stat_buf) - 1);
    if (size == -1) {
        LOG_RUN_ERR("[PROCESS]failed to read file with handle %d, error code %d, can not read process stat", fd, errno);
        ret = close(fd);
        if (ret != 0) {
            LOG_RUN_ERR("[PROCESS]failed to close file with handle %d, error code %d", fd, errno);
        }
        return CM_ERROR;
    }
    ret = close(fd);
    if (ret != 0) {
        LOG_RUN_ERR("[PROCESS]failed to close file with handle %d, error code %d", fd, errno);
    }
    stat_buf[size] = '\0';
    cm_str2text(stat_buf, &stat_text);
    /* remove first section */
    for (uint32 i = 0; i <= 21; ++i) {
        (void)cm_fetch_text(&stat_text, ' ', '\0', &ticks_text);
    }
    /*
     * Time the process started after system boot.
     * The value is expressed in clock ticks.
     */
    (void)cm_text2bigint(&ticks_text, &ticks);
    *process_time = ticks;
    return CM_SUCCESS;
#endif
}

bool32 cm_sys_process_alived(uint64 pid, int64 start_time)
{
    int ret = kill((pid_t)pid, 0);
    if (ret != CM_SUCCESS && cm_get_os_error() == ESRCH) {
        LOG_RUN_INF("[PROCESS]pid %llu start_time %lld status %d, errno %d is not alived", pid, start_time,
            ret, cm_get_os_error());
        return CM_FALSE;
    }

    int64 process_time = 0;
    status_t status = cm_sys_process_start_time(pid, &process_time);
    if (status != CM_SUCCESS) {
        LOG_RUN_INF("[PROCESS]pid %llu start_time %lld, process is alive but can not get start time, maybe "
                    "process is exitting", pid, start_time);
        return CM_TRUE;
    }
#ifdef WIN32
    return (llabs(start_time - process_time) <= 1);
#else
    return (start_time == process_time);
#endif
}

#ifdef __cplusplus
}
#endif
