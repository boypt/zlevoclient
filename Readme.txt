ZLEVOClient v0.2 Readme

编译：
	编译需要libpcap库，一般Linux发行版里面安装libpcap-dev包即可，如ubuntu： sudo apt-get install libpcap-dev
	然后从命令行进入源代码目录，运行make，应该很快就能生成zdclient，当然前提是系统中安装了gcc等编译环境，这里不再累赘。
	理论上兼容包括Mac、Solaris等Unix系系统。
	
运行：
	运行需要root权限，看例子即可：
	
	sudo ./zlevoclient -u username -p password --background
	
	u、p分别是用户名、密码，--background参数可让程序进入后台运行，具体可./zdclient --help查看

	压缩包内提供了启动脚本zlevo_run.sh，用gedit等编辑软件修改sh文件内的username、password，
	以后运行sudo ./xx_zdc_run.sh即可。
	
终止：
	默认方式启动的程序，按Ctrl + C即可正常下线，程序终止；
	如果是以后台方式启动的，可另外使用-l参数运行ZDClient，当然也需要root权限，便能通知原程序下线并退出了。


Another PT Work. 

项目主页： http://code.google.com/p/zdcclient/
Blog:    http://apt-blog.co.cc
GMail:   pentie@gmail.com

2009-05-20 于广州大学城
