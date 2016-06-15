#!/bin/bash

GCC_ETHNC=(
"gcc"
)
APP_ETHNC=(
"ethnc"
"ethnc.mipsel"
"ethnc.mips"
)

#clean
if [ "$1" == "clean" ]; then
	for app in ${APP_ETHNC[*]}
	do
		if [ -f "${app}" ]; then
			rm ${app}
			echo "rm ${app}"
		fi
	done
	if [ -f "ethns" ]; then
		rm ethns
		echo "rm ethns"
	fi
	exit 0
fi

#build ethnc
if [[ -z "$1" || "$1" == "ethnc" ]]; then
	NUM_GCC=${#GCC_ETHNC[@]}
	if [ $NUM_GCC -gt ${#APP_ETHNC[@]} ]; then
		echo "err: len(GCC_ETHNC) > len(APP_ETHNC)"
		exit 1
	fi
	for ((i=0; i<NUM_GCC; i++))
	{
		echo "build ${APP_ETHNC[i]}"
		${GCC_ETHNC[i]} -o ${APP_ETHNC[i]} ethnc.c md5.c twofish.c misc.c tap_linux.c nat_detect.c
	}
fi

#build ethns
if [[ -z "$1" || "$1" == "ethns" ]]; then
	echo "build ethns"
	gcc -o ethns ethns.c md5.c misc.c nat_detect.c
fi
