#!/bin/sh

MTUNE=$1
DIR=./libcrypto_${MTUNE}

build=false
if [[ ! -d ${DIR} ]]
then  # !
    echo "output dir does not exist => build"
    build=true
else
    git log -n 1 --no-decorate --oneline > /tmp/current_gitstatus
    diff /tmp/current_gitstatus ${DIR}/gitstatus
    if [[ ! $? -eq 0 ]]; then
        echo "different version or base version unknown => build"
        build=true
    fi
fi

if [[ ${build} == true ]]
then
    CFLAGS="-mtune=${MTUNE} -ffunction-sections" CPPFLAGS="-mtune=${MTUNE} -ffunction-sections" ./config -static --static
    make -j4 || echo "ignore error"
    mkdir -p ${DIR}
    rm -rf ${DIR}/*
    ar --output=${DIR} x libcrypto.a
    git log -n 1 --no-decorate --oneline > ${DIR}/gitstatus
else
    echo "won't rebuild"
fi
