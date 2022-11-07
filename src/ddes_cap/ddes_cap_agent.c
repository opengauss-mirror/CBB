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
 * ddes_cap_agent.c
 *
 *
 * IDENTIFICATION
 *    src/ddes_cap/ddes_cap_agent.c
 *
 * -------------------------------------------------------------------------
 */

#include "ddes_cap_exec.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WIN32

int main(int argc, char **argv)
{
    return agent_proc();
}

#endif

#ifdef __cplusplus
}
#endif
