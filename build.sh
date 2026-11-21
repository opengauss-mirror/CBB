#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd
# CBB is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# version V1.0
#
# used for build dcc entry
#
set -e
SCRIPTPATH=$(cd "$(dirname "$0")"; pwd)
cd ${SCRIPTPATH}/build/linux/opengauss
chmod +x build.sh
./build.sh "$@"