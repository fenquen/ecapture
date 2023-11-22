#!/usr/bin/env bash

# /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/gojue/ecapture/master/builder/init_env.sh)"

# 环境检测
release_num=$(lsb_release -r --short)
if [ $? -ne 0 ]; then
  echo "command not found, supported ubuntu only."
  exit
fi

CLANG_NUM=12
# shellcheck disable=SC2209
MAKE_ECAPTURE=make
if [ ${release_num} == "20.04" ]; then
  CLANG_NUM=9
  MAKE_ECAPTURE="make nocore"
  elif [ ${release_num} == "20.10" ]; then
  CLANG_NUM=10
  MAKE_ECAPTURE="make nocore"
  elif [ ${release_num} == "21.04" ]; then
  CLANG_NUM=11
  elif [ ${release_num} == "21.10" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "22.04" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "22.10" ]; then
  CLANG_NUM=12
  elif [ ${release_num} == "23.04" ];then
  CLANG_NUM=15
  else
    echo "unsupported release version ${release_num}" && exit
fi

echo "CLANG_NUM=${CLANG_NUM}"

cd ~

uname -a
sudo apt-get update

# 环境安装
sudo apt-get install --yes build-essential pkgconf libelf-dev llvm-${CLANG_NUM} clang-${CLANG_NUM} linux-tools-common linux-tools-generic
for tool in "clang" "llc" "llvm-strip"
do
  sudo rm -f /usr/bin/$tool
  sudo ln -s /usr/bin/$tool-${CLANG_NUM} /usr/bin/$tool
done

clang --version

cd .. || exit
${MAKE_ECAPTURE}
