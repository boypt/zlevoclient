## 项目目标 ##
作为开源的第三方的supplicant客户端兼容联想的802.1x协议校园网认证系统，支持在Unix系操作系统下跨平台使用。

本项目已经停止多年，无法保证程序可用，源码在仓库中，仅供研究，欢迎Fork。


## 文档 ##
  * [用户手册](http://code.google.com/p/zlevoclient/wiki/UserManual)
  * [详细使用教程](http://code.google.com/p/zlevoclient/wiki/StepByStep_Toturial)
  * DeveloperDocument 开发者手册，获取、编译源代码

## ZlevoClient ##

[**NEW 2010.1.25**]: 此前的掉线是因为程序BUG所致，已修正，请用户重新下载。

在imagelife同学的邀请和帮助下，通过分析wireshark的抓包编写出来的的认证客户端。由于之前有了写[ZDClient](http://code.google.com/p/zdcclient/)的经验，上手比较快…… 联想的协议似乎更简单，没有神州那样在报文里面附上一大堆ip阿网关阿DNS这些恶作剧的东西……所以直接拿了ZDC的代码来删删删，然后根据他们整理出来的一份协议的简单分析，大概整理出了雏形。

目前的ZlevoClient已经能通过认证保持在线，雏形已成，有待更多人的帮忙测试。

## 通过测试的环境 ##
湖南人文科技学院、河南工业大学、吉林大学珠海学院（v0.6+）

## 最新更新 ##
  * 0.10版支持在MacOS/BSD系列系统内编译运行, [r82](https://code.google.com/p/zlevoclient/source/detail?r=82)
  * 基于0.8的win版本认证客户端
  * 0.8版的二进制包采用pcap的静态编译，应该在所有系统中都可以直接运行，欢迎大家测试。
  * 0.7版改变副本检测、后台运行的方式(避免出现问题进程)
  * 0.6版支持吉林大学珠海学院的认证机制
  * 0.5版开始能真正使用！向服务器上传真实IP以供校验。
  * 0.2版加入离线参数-l，优化发送保持数据包的线程；