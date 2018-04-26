title: metasploit学习小记
author: Qianye
abbrlink: 49ca178a
tags:
  - knowledge
  - note
categories:
  - knowledge
  - note
date: 2018-03-19 09:45:00
---
# [metasploit的基础知识](https://www.offensive-security.com/metasploit-unleashed/) 

以前一直在使用这个渗透神器，不知道其原理，这次特地借了一本书，来深入理解一下。
<!-- more -->
1.metasploit框架的体系结构 

![](http://p4gdp8beq.bkt.clouddn.com/123456ass.jpg)  



模块  
Exploit: 渗透攻击模块，一段程序，利用目标的安全漏洞进行攻击。   
Payload: 攻击载荷模块，在成功完成对目标的一次渗透攻击后，在目标主机上运行，获得需要的访问和行动权限。   
Auxiliary:包含了一系列的辅助支持模块，包括扫描模块、fuzz测试漏洞发掘模块、网络协议欺骗以及其他模块。  
Encoder: 编码器模块通常对我们的攻击模块进行代码混淆，来逃过目标安全保护机制的检测。   
基础库：  
Ruby扩展(REX)：处理几乎所有的核心功能，如设置网络套接字、网络的连接、格式化和所有其他基本功能。   
MSF核心：提供了基本的应用编程接口和框架的实际核心。   
MSF基础：对模块提供了友好的应用编程接口   


2.[命令](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/) 
```bash
use[Auxiliary/Exploit/Payload/Encoder]    选择一个指定的模块并使其开始工作
show [auxiliary/exploit/payload/encoder/options] 显示可用的特定功能的模块
set [options/payload]   给某个特定的对象赋值  
setg [options/payload]  给某个特定的对象赋值的同时设定作用域为全局，在模块进行切换的时候，该对象的值不会改变
run   		在设定一个辅助模块需要的所有选项之后，启动该模块 
exploit  	 启动一个渗透攻击模块 
back      	取消当前选择的模块并且退回到上一级命令窗口 
info 		 列出模块的相关信息 
search  	  搜索符合条件的特定模块
check  	   检查摸个特定目标是否易受到攻击 
sessions      列出当前可用会话

```
3.[meterpreter的命令](http://www.91ri.org/8476.html)  
4.一次渗透命令 
```bash
sysinfo  	收集一些有关目标系统额基本信息
getuid   	获取当前会话权限 
getpid   	当前会话所在的进程标识符pid 
ps       	查看所有进程标识符
migrate  	转换进程 (渗透时建议转换explorer.exe进程pid)
getsystem	获取系统权限 
download     下载一根目标计算机的文件
rmdir        删除一个文件夹
 
run persistence                运行此模块在目标主机上安装一个后门，实现访问控制持久化 

msf>use exploit/multi/handler  与运行persitstence时设置的payload和lport选项一样 

run event_manager -c           清除掉目标系统上与渗透测试相关的事件日志  
```
5.数据库的存储和取回结果 
```bash
systemctl start postgresql  启动数据库
mysql init         初始化数据库 
msf>db_connect  用来与默认数据库之外的数据库交互
db_import       用来向数据库导入来自其他扫描工具（如nessus和nmap）的扫描结果
db_status       数据库的连接状态
db_disconnect   从指定的数据库断开连接
db_nmap         用namp尽心扫描，结果保存在数据库里 
db_rebuild_cache 用来重新建立缓存，主要目的是使用心的配置替换之前缓存文件中错误或者过时的配置   
hosts            显示数据库中存储的主机信息  
services         查看数据库中存储的扫描过的主机开启的端口服务  
```

# metasploit模块

1.[ruby语言](http://www.runoob.com/ruby/ruby-command-line-options.html) 
1.在命令行中定义方法
```bash
def method_name[([arg [=default]]...[,*arg [,&expr]])]
expr 
end
```
split函数 将一个字符串的值分割为多个连续的变量   
squeeze函数 将制定的字符串中去除重复的空格 
to_i 将字符串类型的输入转换成数字 
to_s 将一个数字转换成字符串  
2.以被控计算机为跳板  
在被控制的计算机上
```bash 
meterpreter>run autoroute -s 目标服务器
```
3.设置永久访问权限
```bash
meterpreter>run metsvc -A
```
4.RailGun 
```bash
meterpreter>irb
>>client.railgun.DLLname.function(parameter)
```
例子：
被渗透的系统进入锁定状态
```bash
>>client.railgun.user32.LockWorkStation()
```
删除被渗透系统的指定用户   
第一个参数代表局域网，假如不在同一个网络中，应填写目标系统的NET-BIOS,第二个代表用户

```bash
>>client.railgun.netapi.NetUserDel(nil,"qianye")
```
[windows api资料](https://msdn.microsoft.com/en-us/library/windows/desktop/ff818516)  
5.汇编语言基础  
寄存器   
是一种高速的计算机内存组件 
```bash
EAX   用来存储数据和操作数的累加器，大小32
EBX   基地寄存器，同时也是一个指向数据的指针
ECX   实现循环为目的的计数器
EDX   用来保存I/O指针数据寄存器 
ESI/EDI 两者都是索引寄存器，用作内存运算时的数据指针
ESP   栈指针寄存器,准确地告诉你当前栈顶的位置
EBP   栈数据指针寄存器
EIP   程序计数器，保存要执行下一条指令的地址
SS DS ES CS FS GS  端寄存器，大小为16位
```
段  
```bash
.data  用来存储已经初始化的数据
.bss   用来存储为初始化的数据
.text  所有的程序指令都可以在这里定义
.global_start  外部可调用的程序
_start  主函数程序 
Stack   存放变量和数据
```
数据类型
```bash
.byte 单字节
.ascii  字符串
.asciz  以null结尾的字符串
.int  32位整形
.short 16位整形
.float 单精度浮点型
.double 双精度浮点型
```