#!/bin/bash

DEST="install"

cp arch/arm64/boot/Image $DEST/5.4.55-v8.img
cp arch/arm64/boot/dts/broadcom/*.dtb $DEST/
cp arch/arm64/boot/dts/overlays/*.dtb* $DEST/overlays/
cp arch/arm64/boot/dts/overlays/README $DEST/overlays/
