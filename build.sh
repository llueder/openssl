MTUNE=raptorlake
DIR=~/libcrypto_${MTUNE}
CFLAGS="-mtune=${MTUNE} -ffunction-sections" CPPFLAGS="-mtune=${MTUNE} -ffunction-sections" ./config -static --static
make -j4 || echo "ignore error"
mkdir -p ${DIR}
rm -rf ${DIR}/*
ar --output=${DIR} x libcrypto.a

MTUNE=tremont
DIR=~/libcrypto_${MTUNE}
CFLAGS="-mtune=${MTUNE} -ffunction-sections" CPPFLAGS="-mtune=${MTUNE} -ffunction-sections" ./config -static --static
make -j4 || echo "ignore error"
mkdir -p ${DIR}
rm -rf ${DIR}/*
ar --output=${DIR} x libcrypto.a
