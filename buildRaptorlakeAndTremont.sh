#!/bin/sh

./build.sh raptorlake
for f in $(ls libcrypto_raptorlake/*.o); do
    mv $f ${f%.o}_A.o
done
./build.sh tremont
for f in $(ls libcrypto_tremont/*.o); do
    mv $f ${f%.o}_B.o
done
