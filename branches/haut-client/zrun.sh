#!/bin/bash
#############################################
##请更改一下两个参数为你的802.1x的用户名和密码
##
##Edit by anyanmw@gmail.com in haut 2010-4-6
#############################################

USERNAME=username
PASSWORD=password

if [ ! $(id -u) -eq 0 ];then
	echo "You are not root,Need to be ROOT.";
	if uname -a |grep -i ubuntu ;then
            echo "Run as root in ubuntu with commond 'sudo'autolly...";
            sudo ./zlevoclient -u $USERNAME -p $PASSWORD -b
        fi
	exit 0
fi

./zlevoclient -u $USERNAME -p $PASSWORD -b
exit 0
