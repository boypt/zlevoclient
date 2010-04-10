#!/bin/bash
#echo "  zautorun.sh 自动安装或执行zlevoclient的脚本 v1.0"

USERNAME=20064140606
PASSWORD=111111

#脚本变量
zver="1.0"
infox="请执行sudo $0 uninstall;sudo $0进行安装"
#
##check检查
#
if [ "$1" == "check" ];then
	echo "@(`id -un`)check信息:"
	if [ -f /usr/local/bin/zlevoclient ];then 
	echo "(1:ok)存在/usr/local/bin/zlevoclient";
		if ls -l /usr/local/bin/zlevoclient |grep -i s >/dev/null;then 
		    echo "(2:ok)已经赋予uid位,普通用户可以执行";
		    else echo "#2:没有赋予uid位,$infox";
		fi
	else echo "#1:不存在/usr/local/bin/zlevoclient,$infox"
	fi
	
	if [ -f /usr/local/bin/zrun.sh ];then 
	    echo "(3:ok)存在/usr/local/bin/zrun.sh";
	    else echo "#3:不存在/usr/local/bin/zrun.sh,$infox"
	fi
	
	if ps -A|grep zlevoclient>/dev/null;then
	    echo "(4:ok)已经运行zlevoclient";
	    else echo "没有运行zlevoclient,请运行zrun.sh"
	fi

	exit 0
fi
#-v 版本信息
if [ "$1" == "-v" ];then
    echo "zautorun.sh 自动安装或执行zlevoclient的脚本 $zver"
    echo ""
	echo "    本脚本由ayanmw编辑,如果你觉得有 那里不妥(会函数的给改下)告诉我"
	echo "    My Email: anyanmw (at) gmail.com   欢迎来信交流!"
    echo "                                  2010-4-10 in haut"
    exit 0

fi
#帮助信息
if [ "$1" == "-h" ];then
	echo "帮助信息$zver:"
	echo "  $0           代表执行安装程序(root权限)"
	echo "  $0           代表运行位于/usr/local/bin下的程序"
	echo "  $0 uninstal  代表卸载位于/usr/local/bin下的程序(root权限)"
	echo "  $0 check     检查是否安装"
	echo "  $0 -l        下线"
	echo "  $0 -h        显示本帮助信息"
	echo "  $0 -v        显示本版本信息"
	echo ""
	exit 0
fi

##############################
#检测是否存在zlevoclient,避免异常(2合一)
#         返回-1代表失败
##############################

if [ ! -f ./zlevoclient ];then
	echo ERROR:no zlevoclient in `pwd`
	exit -1
fi
##############################
#若没有安装,则进行安装,需要root权限 
#         返回-1代表失败
#  返回1代表安装成功(见文件末尾)
##############################
if [ ! -f /usr/local/bin/zlevoclient ];then
	if [ `id -u` -ne 0 ];then 
		echo "请使用sudo或者su执行本文件，一劳永逸的安装"
		exit -1
	fi
echo "@(`id -un`)现在执行安装过程..."
	if [ ! -d /usr/local/bin ];then
		mkdir /usr/local/bin
	fi

	cp ./zlevoclient /usr/local/bin/zlevoclient
	cp -f $0 /usr/local/bin/zrun.sh
	chown root /usr/local/bin/zlevoclient
	chmod 4755 /usr/local/bin/zlevoclient
	ls -l /usr/local/bin/zlevoclient
fi
####################################
#可以从系统中删除zlevoclient,需要root权限
#          返回2代表删除成功
####################################
if [ "$1" == "uninstall" ];then
	if [ `id -u` -ne 0 ];then 
		echo "请使用sudo或者su执行本文件,删除/usr/local/bin/zlevoclient需要root权限"
		exit -1
	fi
echo "@(`id -un`)现在执行删除过程..."
	echo 即将删除 /usr/local/bin/zlevoclient
	rm -f  /usr/local/bin/zlevoclient
	rm -f /usr/local/bin/zrun.sh
	#上面这个zrun.sh脚本是删还是不删????
	exit 2
fi
##################################################
#
#安装成功后,无论本文件在那里,都会跳过以上步骤,执行以下命令
#
##################################################
echo "@(`id -un`)现在执行运行过程..."
if ps -A |grep zlevoclient>/dev/null;then
	#
	#检测是否需要下线处理	
	#
	if [ "$1" == "-l" ];then
		/usr/local/bin/zlevoclient -l
		exit 0
	fi
	#
	#检测处理:已经运行则不需要再次运行
	#
	echo "已经运行zlevoclient了,若要退出请使用zlevoclient -l命令 或者 $0 -l"
	exit 0
fi
/usr/local/bin/zlevoclient -u $USERNAME -p $PASSWORD -b
exit 1



#
#本脚本由ayanmw编辑,如果你觉得有 那里不妥(会函数的给改下)
#tell me : anyanmw (at) gmail.com
#			2010-4-10
#
#更新历史:
#
#2010-4-10 v1.0:花了两个多小时,终于完成这个脚本,实现了自动安装,以及一些辅助信息,详细见$0 -h
#

