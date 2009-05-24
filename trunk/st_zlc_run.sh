#!/bin/bash

if [[ $UID -ne 0 ]];then
	echo "Need to be ROOT!"
	exit 1
fi

./zlevoclient -u username -p password -b

exit 0
