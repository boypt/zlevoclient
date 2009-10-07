#!/bin/bash
if [ `id -u` -ne 0 ]
then
    echo "Need to be ROOT."
    exit 1
fi

./zlevoclient -u username -p password -b

exit 0
