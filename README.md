tcplstat - TCP网络监控工具
==========================

<!-- TOC -->

- [1. 概述](#1-概述)
- [2. 安装](#2-安装)
    - [2.1. 源码编译安装](#21-源码编译安装)
- [3. 使用](#3-使用)
    - [3.1. 命令行参数说明](#31-命令行参数说明)
    - [3.2. 一个示例（即时输出TCP分组事件）](#32-一个示例即时输出tcp分组事件)
    - [3.3. 另一个示例（短连接断开后输出统计信息）](#33-另一个示例短连接断开后输出统计信息)
    - [3.4. 再一个示例（采集统计SQL耗时）](#34-再一个示例采集统计sql耗时)
- [4. 最后](#4-最后)

<!-- /TOC -->

# 1. 概述

只因为上周五晚上我不小心看了一眼libpcap资料，创造情结蠢蠢欲动，一个周末都没过好，经过四个晚上奋力疾书，于是在周二晚的现在诞生了这个TCP网络监控工具。

tcplstat是基于libpcap网络嗅探程序包的网络监控工具，它能**旁路**捕获所有经过网络设备过滤规则的TCP数据，跟踪当前所有TCP连接会话，记录所有经过的TCP分组，当连接断开或到达最大记录数时倒出统计信息，包含但不限于连接两端网络地址、建立时间戳、三步握手各分组延迟、四步分手各分组延迟，数据分组明细、往来分组间延迟和相反方向分组延迟的最小、平均、最大统计值。

tcplstat在**旁路**工作，所以不会对应用造成任何影响，也无需侵入应用，即可获得网络数据往来分组明细和统计信息。

tcplstat在实现基础网络监控功能时还实现了采集分析SQL耗时和HTTP耗时信息，同样也是**旁路**捕获，不影响应用也无需改造应用，帮助应用优化性能。

tcplstat是开源的，除了引用了Linux内核的红黑树和链表源码外，自身源码只有1500行左右，源码结构简单易读。

# 2. 安装

（理论上tcplstat可以安装在任何有libpcap的环境，包括Linux、WINDOWS、AIX等，以下以Linux操作系统为例）

## 2.1. 源码编译安装

从tcplstat源码托管站点（网址在最后）下载最新源码包，解开并进入源码目录

```
$ tar xvzf tcplstat.tar.gz
...
￥ cd tcplstat/src
```

按需修改安装目录

```
$ vi makeinstall
_BINBASE        =       $(HOME)/bin
```

**注意：编译环境需要开发包libpcap-devel，请预先安装好。**

编译、安装tcplstat

```
$ make -f makefile.Linux
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c list.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c rbtree.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c rbtree_ins.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c Util.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c main.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c PcapCallback.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c ProcessTcpPacket.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c AddTcpPacket.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -I/home/calvin/include -I. -I/home/calvin/include  -c OutputTcplSession.c
gcc -g -fPIC -O2 -Wall -Werror -fno-strict-aliasing -o tcplstat list.o rbtree.o rbtree_ins.o Util.o main.o PcapCallback.o ProcessTcpPacket.o AddTcpPacket.o OutputTcplSession.o -L/home/calvin/lib -L. -L/home/calvin/lib -lpcap 
$ make -f makefile.Linux install
cp -rf tcplstat /home/calvin/bin/
```

编译链接只产生了一个可执行程序`tcplstat`，也可自行复制到目标目录。

显示版本信息

```
$ tcplstat -v
tcplstat v0.5.0 build Feb  6 2018 22:40:44
copyright by calvin<calvinwilliams@163.com> 2018
```

# 3. 使用

## 3.1. 命令行参数说明

不带命令行参数执行显示所有命令行参数

```
$ tcplstat
USAGE : tcplstat -v
                 -l
                 [ -i (network_interface) ] [ -f (filter_string) ] [ -o [ESPDd] ] [ --sql ] [ --http ] [ --max-packet-trace-count ] [ --log-file (pathfilename) ]
-o E : Output EVENT
   S : Output SESSION
   P : Output PACKET
   D : Output PACKET DATA
   d : Output DEBUG
--sql : Output SQL time elapse
NOTICE : See pcap-filter(7) for the syntax of filter
```

* `-i`设置网络设备接口，不设置则默认使用`any`
* `-f`设置网络过滤规则，比如`tcp port 445`嗅探所有连接到端口445的往来TCP分组，具体参见`pcap-filter(7)`
* `-o`一旦捕获到TCP分组，输出数据类型，E表示输出分组事件，S表示连接断开输出会话统计信息，P表示连接断开输出TCP分组统计信息，D表示连接断开输出TCP分组数据信息，d表示输出调试信息
* `--sql`捕获SQL统计耗时信息
* `--http`捕获HTTP统计耗时信息
* `--max-packet-trace-count`针对长连接不释放，总是不能侦测到连接断开也就不能输出会话总结信息，该选项设置TCP分组累积到多少时强制输出并清空TCP分组明细信息，默认为1000，下次输出会话统计信息时前缀从'E |'变成'E -'
* `--log-file`输出到日志文件，不设置文件则输出到屏幕

**注意：执行tcplstat需要root权限。**

## 3.2. 一个示例（即时输出TCP分组事件）

第一屏运行tcplstat

```
# tcplstat -f "tcp port 445" -o E
```

第二屏向445端口发送一个字符串，然后被samba服务器无情强行断开

```
$ echo "hello" | nc 114.215.179.129 445
```

第一屏输出

```
E | 2018-02-07T20:09:21.249992 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[44200] DPORT[445] SEQ[3750544418] ACKSEQ[0] SYN[1] ACK[0] FIN[0] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.250004 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[445] DPORT[44200] SEQ[974809372] ACKSEQ[3767321634] SYN[1] ACK[1] FIN[0] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.250018 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[44200] DPORT[445] SEQ[3767321634] ACKSEQ[991586588] SYN[0] ACK[1] FIN[0] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.251501 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[44200] DPORT[445] SEQ[3767321634] ACKSEQ[991586588] SYN[0] ACK[1] FIN[0] PSH[1] RST[0] URG[0] | [6]BYTES
E |                  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
E |     0x00000000   68 65 6C 6C 6F 0A                                 hello.          
E | 2018-02-07T20:09:21.251507 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[445] DPORT[44200] SEQ[991586588] ACKSEQ[3867984930] SYN[0] ACK[1] FIN[0] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.251661 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[44200] DPORT[445] SEQ[3867984930] ACKSEQ[991586588] SYN[0] ACK[1] FIN[1] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.256246 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[445] DPORT[44200] SEQ[991586588] ACKSEQ[3884762146] SYN[0] ACK[1] FIN[1] PSH[0] RST[0] URG[0] | [0]BYTES
E | 2018-02-07T20:09:21.256267 | LHT[113] | SMAC[] DMAC[] | SIP[114.215.179.129] DIP[114.215.179.129] | SPORT[44200] DPORT[445] SEQ[3884762146] ACKSEQ[1008363804] SYN[0] ACK[1] FIN[0] PSH[0] RST[0] URG[0] | [0]BYTES
...
```

E开头的行为一个TCP分组，各列分别是发生时间戳、链路层头结构、发送方MAC、接收方MAC、发送方IP、接收方IP、发送方PORT、接收方PORT、序列号、反馈序列号、分组类型标志集合、有效荷载数据长度。

## 3.3. 另一个示例（短连接断开后输出统计信息）

第一屏运行tcplstat

```
# tcplstat -f "tcp port 445" -o SPD
```

第二屏向445端口发送一个字符串，然后被samba服务器无情强行断开

```
$ echo "hello" | nc 114.215.179.129 445
```

第一屏输出

```
S | [114.215.179.129:44205]->[114.215.179.129:445] | 2018-02-07T20:20:41.903338 | 0.016535 | 0.000016 0.000015 , 0.000006 0.000741 0.001477 0.000006 0.000749 0.001492 , 0.000036 0.014964 0.000021 | 2 6
P |     2018-02-07T20:20:41.903338 | 0.000000 0.000000 | [114.215.179.129:44205]->[114.215.179.129:445] | S..... 0
P |     2018-02-07T20:20:41.903354 | 0.000016 0.000016 | [114.215.179.129:44205]<-[114.215.179.129:445] | S..A.. 0
P |     2018-02-07T20:20:41.903369 | 0.000015 0.000015 | [114.215.179.129:44205]->[114.215.179.129:445] | ...A.. 0
P |     2018-02-07T20:20:41.904846 | 0.001477 0.001492 | [114.215.179.129:44205]->[114.215.179.129:445] | ..PA.. 6
D |                  0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF
D |     0x00000000   68 65 6C 6C 6F 0A                                 hello.          
P |     2018-02-07T20:20:41.904852 | 0.000006 0.000006 | [114.215.179.129:44205]<-[114.215.179.129:445] | ...A.. 0
P |     2018-02-07T20:20:41.904888 | 0.000036 0.000036 | [114.215.179.129:44205]->[114.215.179.129:445] | .F.A.. 0
P |     2018-02-07T20:20:41.919852 | 0.014964 0.014964 | [114.215.179.129:44205]<-[114.215.179.129:445] | .F.A.. 0
P |     2018-02-07T20:20:41.919873 | 0.000021 0.000021 | [114.215.179.129:44205]->[114.215.179.129:445] | ...A.. 0
...
```

S开头的行为一个连接统计信息，各列分别是连接方地址、被连接方地址、建立连接时间戳、连接总存在时间、三步握手各分组延迟、四步分手各分组延迟、往来分组间延迟和相反方向分组延迟的最小、平均、最大统计值，总分组数，有效载荷数据总大小。

P开头的行为一个连接中的一个TCP分组统计信息，各列分别是分组发生时间戳、往来分组间延迟和相反方向分组延迟、连接方地址、分组发送方向、被连接方地址、分组类型标志集合、有效荷载数据长度。

可以看出，自己想获得什么样的数据，就组合命令行参数`-o`后面的字母集合即可，最详细的信息参数组合是`ESPDd`

## 3.4. 再一个示例（采集统计SQL耗时）

捕获SQL的原理很简单，检查每一个TCP分组中是否存在SQL语句，如果有则做个标记，等待下一个有效载荷的反向TCP分组到来后，计算时间差即是SQL执行时间。

这里以PostgreSQL为例，MySQL、Oracle等同样有效。

第一屏运行tcplstat

```
# tcplstat -f "tcp port 8432" --sql
```

第二屏用psql打开数据库连接，查询所有表总记录数

```
calvin=# \d
                               关联列表
 架构模式 |                   名称                   |  型别  | 拥有者 
----------+------------------------------------------+--------+--------
 public   | alphastock_company_info                  | 资料表 | calvin
 public   | alphastock_company_ipo                   | 资料表 | calvin
 public   | alphastock_stock_code                    | 资料表 | calvin
 public   | alphastock_stock_kline                   | 资料表 | calvin
 public   | alphastock_stock_kline_max_closing_price | 资料表 | calvin
 public   | financing_chinawealth                    | 资料表 | calvin
 public   | whoispider_domain                        | 资料表 | calvin
(7 行记录)

calvin=# select count(*) from alphastock_company_info;
 count 
-------
  3596
(1 行记录)

calvin=# select count(*) from alphastock_company_ipo ;
 count 
-------
  3596
(1 行记录)

calvin=# select count(*) from alphastock_stock_code ;
 count 
-------
  3596
(1 行记录)

calvin=# select count(*) from alphastock_stock_kline ;
  count  
---------
 8826375
(1 行记录)

calvin=# select count(*) from financing_chinawealth ;
calvin-# ;
 count  
--------
 168148
(1 行记录)
```

第一屏输出

```
Q | 2018-02-07T20:28:07.978745 0.000869 | select count(*) from alphastock_company_info;
Q | 2018-02-07T20:28:10.427744 0.000605 | select count(*) from alphastock_company_ipo ;
Q | 2018-02-07T20:28:12.923744 0.000737 | select count(*) from alphastock_stock_code ;
Q | 2018-02-07T20:28:15.291747 42.884759 | select count(*) from alphastock_stock_kline ;
Q | 2018-02-07T20:29:35.218747 3.505407 | select count(*) from financing_chinawealth ;
...
```

Q开头的行为一条SQL耗时统计，各列是开始执行时间戳、执行耗时、SQL语句。

可以看到表`alphastock_stock_kline`很大，SQL`select count(*) from alphastock_stock_kline`花了42秒，表`alphastock_company_ipo`很小，SQL`select count(*) from alphastock_company_ipo`花了0.6毫秒。

整个采集统计过程完全以**旁路**方式进行，不影响应用也无需侵入应用。

# 4. 最后

欢迎使用tcplstat，如果你使用中碰到了问题请告诉我，谢谢 ^_^

源码托管地址 : [开源中国](https://gitee.com/calvinwilliams/tcplstat)、[github](https://github.com/calvinwilliams/tcplstat)

作者邮箱 : [网易](mailto:calvinwilliams@163.com)、[Gmail](mailto:calvinwilliams.c@gmail.com)
