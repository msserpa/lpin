#!/bin/bash

DIR="$( cd -P "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -d "obj-intel64" ]; then
	pinobjdir="obj-intel64"
elif [ -d "obj-ia64" ]; then
	pinobjdir="obj-ia64"
else
	echo "untested arch"
	exit
fi

#(cd $DIR && make) || exit 127
(cd $DIR) || exit 127
time -p /opt/pin/pin -ifeellucky -t $DIR/$pinobjdir/analysis.so -- ${@}
