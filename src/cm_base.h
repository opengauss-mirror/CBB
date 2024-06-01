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
 * cm_base.h
 *
 *
 * IDENTIFICATION
 *    src/cm_base.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_BASE__
#define __CM_BASE__

#include "securec.h"

#ifdef WIN32
#if defined(DDES_EXPORTS)
#define DDES_DECLARE __declspec(dllexport)
#elif defined(DDES_IMPORTS)
#define DDES_DECLARE __declspec(dllimport)
#else
#define DDES_DECLARE
#endif
#else
#define DDES_DECLARE __attribute__((visibility("default")))
#endif

#endif
