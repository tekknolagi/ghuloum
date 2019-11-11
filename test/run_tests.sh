#!/bin/bash

mkdir -p build

for t in *.in; do
  make -s $(basename -s .in $t).diff
done
