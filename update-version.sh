#!/bin/bash

if [ ! $# -eq 1 ]; then
	echo "Usage: update-version.sh 0.3.1" 1>&2
	exit 1
fi

VER="$1"

sed -i "s~go-libiptc v[^ ]*~go-libiptc v${VER}~g" $(find . -name '*.go' -type f)
