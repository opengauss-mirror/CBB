#!/bin/bash
#############################################################################
# Copyright (c) 2020 Huawei Technologies Co.,Ltd.
#
# openGauss is licensed under Mulan PSL v2.
# You can use this software according to the terms
# and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#          http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.
# ----------------------------------------------------------------------------
# Description  : cbb build for opengauss
#############################################################################

set -e

function print_help()
{
    echo "Usage: $0 [OPTION]
    -h|--help              show help information.
    -3rd|--binarylib_dir   the directory of third party binarylibs.
    -m|--version_mode      this values of paramenter is Debug, Release, Memcheck, the default value is Release.
    -t|--build_tool        this values of parameter is cmake, make, the default value is cmake.
"
}

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            print_help
            exit 1
            ;;
        -3rd|--binarylib_dir)
            if [ "$2"X = X ]; then
                echo "no given binarylib directory values"
                exit 1
            fi
            binarylib_dir=$2
            shift 2
            ;;
        -m|--version_mode)
          if [ "$2"X = X ]; then
              echo "no given version number values"
              exit 1
          fi
          version_mode=$2
          shift 2
          ;;
        -t|--build_tool)
          if [ "$2"X = X ]; then
              echo "no given build_tool values"
              exit 1
          fi
          build_tool=$2
          shift 2
          ;;
         *)
            echo "Internal Error: option processing error: $1" 1>&2
            echo "please input right paramtenter, the following command may help you"
            echo "./build.sh --help or ./build.sh -h"
            exit 1
    esac
done

if [ -z "${version_mode}" ] || [ "$version_mode"x == ""x ]; then
    version_mode=Release
fi
if [ -z "${binarylib_dir}" ]; then
    echo "ERROR: 3rd bin dir not set"
    exit 1
fi
if [ -z "${build_tool}" ] || [ "$build_tool"x == ""x ]; then
    build_tool=cmake
fi
if [ ! "$version_mode"x == "Debug"x ] && [ ! "$version_mode"x == "Release"x ] && [ ! "$version_mode"x == "Memcheck"x ]; then
    echo "ERROR: version_mode param is error"
    exit 1
fi
if [ ! "$build_tool"x == "make"x ] && [ ! "$build_tool"x == "cmake"x ]; then
    echo "ERROR: build_tool param is error"
    exit 1
fi

export CFLAGS="-std=gnu99"

LOCAL_PATH=${0}

CUR_PATH=$(pwd)

LOCAL_DIR=$(dirname "${LOCAL_PATH}")
export PACKAGE=$LOCAL_DIR/../../../
export OUT_PACKAGE=cbb

# gcc version
if [[ -d "${binarylib_dir}/buildtools/gcc10.3" ]]; then
    gcc_version="10.3"
elif [[ -d "${binarylib_dir}/buildtools/gcc8.3" ]];then
    gcc_version="8.3"
else
    gcc_version="7.3"
fi

export GCC_PATH=$binarylib_dir/buildtools/gcc$gcc_version/
export CC=$GCC_PATH/gcc/bin/gcc
export CXX=$GCC_PATH/gcc/bin/g++
export LD_LIBRARY_PATH=$GCC_PATH/gcc/lib64:$GCC_PATH/isl/lib:$GCC_PATH/mpc/lib/:$GCC_PATH/mpfr/lib/:$GCC_PATH/gmp/lib/:$LD_LIBRARY_PATH
export PATH=$GCC_PATH/gcc/bin:$PATH

export CBB_LIBRARYS=$(pwd)/../../../library

[ -d "${CBB_LIBRARYS}/huawei_security" ] && rm -rf ${CBB_LIBRARYS}/huawei_security
[ -d "${CBB_LIBRARYS}/openssl" ] && rm -rf ${CBB_LIBRARYS}/openssl
[ -d "${CBB_LIBRARYS}/zlib" ] && rm -rf ${CBB_LIBRARYS}/zlib
mkdir -p $CBB_LIBRARYS/huawei_security
mkdir -p $CBB_LIBRARYS/openssl
mkdir -p $CBB_LIBRARYS/zlib

export LIB_PATH=$binarylib_dir/kernel/dependency
export P_LIB_PATH=$binarylib_dir/kernel/platform

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/lib           $CBB_LIBRARYS/huawei_security/lib
cp -r $LIB_PATH/openssl/comm/lib                     $CBB_LIBRARYS/openssl/lib
cp -r $LIB_PATH/zlib1.2.11/comm/lib                  $CBB_LIBRARYS/zlib/lib

cp -r $P_LIB_PATH/Huawei_Secure_C/comm/include       $CBB_LIBRARYS/huawei_security/include
cp -r $LIB_PATH/openssl/comm/include                 $CBB_LIBRARYS/openssl/include
cp -r $LIB_PATH/zlib1.2.11/comm/include              $CBB_LIBRARYS/zlib/include

cd $PACKAGE
if [ "$build_tool"x == "cmake"x ];then
    cmake . -DCMAKE_BUILD_TYPE=${version_mode} -DUSE_GM_TLS=OFF
    make -sj 8
else
    make clean
    make BUILD_TYPE=${version_mode} -sj 8
fi

mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
mkdir -p $binarylib_dir/kernel/component/${OUT_PACKAGE}/bin
cp src/*.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
cp src/*/*.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
cp src/*/*/*.h $binarylib_dir/kernel/component/${OUT_PACKAGE}/include
cp output/lib/libcbb* $binarylib_dir/kernel/component/${OUT_PACKAGE}/lib
cp output/bin/* $binarylib_dir/kernel/component/${OUT_PACKAGE}/bin
