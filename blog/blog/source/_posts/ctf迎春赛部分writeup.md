title: moctf迎春赛部分writeup
author: Qianye
abbrlink: 58504f2f
tags:
  - moctf
categories:
  - ctf
date: 2018-02-17 12:24:00
---
春节之际，集大和理工的学长开始搞事情啦！
<!-- more -->
先做个小广告 :  [moctf平台](http://www.moctf.com/home) MOCTF平台是厦门理工大学CodeMonster和集美大学Mokirin这两支CTF战队所搭建的一个CTF在线答题系统。题目形式与各大CTF比赛相同。目的是为两个学校中热爱信息安全的同学们提供一个刷题的平台，能够一起学习、进步。

[官方的writeup](https://github.com/xishir/moctf/tree/master/2018MOCTF)


此次比赛，能力不足, web题就只做出简单的一题

![](http://img1.gtimg.com/comic/pics/hv1/103/133/2032/132164818.jpg)

# 是时候让你的手指锻炼一下了

首先查看源代码
![](http://p4gdp8beq.bkt.clouddn.com/1231.png)
看代码可知，只要clicks>108000就会发送一个get请求，如果手动点击108000，那你加油哦！ 直接构造 ？clicks=108001 get请求，即可看到flag


做不了web题，只能来做杂项了。
# 流量分析

这题，应该是一台主机向另一台主机请求flag信息，只要看返回的那条信息数据包，即那第二条显眼的黑色数据包，是192.168.1.2返回192.168.1.1的应答。直接追踪流->tcp就得到flag
# base全家桶

用了base16 、base32、base64加密，依次解密即可的flag


# 颜文字

aaencode加密，直接在粘贴到浏览器上的控制台上运行即可得到flag

# 奇怪的十六进制

是先转化成ascii码，在base64两次解密即可得到flag

# 先越过这道栅栏再说

先栅栏解密，然后在凯撒解密


# 空word
一开始改后缀为压缩包格式，没发现什么。然后把word中文件->选项->显示中全部都打上勾。发现横横点点，猜是摩斯密码，一个个的拼接起来，看的眼多花了，还弄错了几个，心累。

摩斯密码解密后，16进制数转化成ascii码，得到flag

# 一万年的爱有多久

这道题压缩包被压缩了5000次，直接上py解压.

``` bash
import zipfile
import os
filename1="KIhn9j7FfG .zip"
i=0
while True:
    filename=filename1
    if(zipfile.is_zipfile(filename)):
        fz=zipfile.ZipFile(filename)
    else:
        print("解压完成")
        file=open("filename",'r')
        s=file.read()
        print(s)
        exit(0)
    for file in fz.namelist():
        i=i+1
        print(i)
        filename1=file
        fz.extract(file)
        try:
            os.remove(filename)
        except:
            pass


``` 
# Hacker!!!

这道题其实就是向服务器发送一条条请求，猜解This_Is_Column_Name这个字段的值，即flag的值。观察下图两个方框的值（后面的两个方框为同一个），所以只要查看猜解这个字段第n个字符的最后一条发送的数据包，所有的位置拼接起来就是flag，做这题真的是看得眼都花了。
![](http://p4gdp8beq.bkt.clouddn.com/45646.png)
# 李华的疑惑

一开始直接打开txt文档，里面全部是满满的数，什么鬼，不知道什么东西。然后用notepad++打开，是一条条以逗号间隔的数的三位数，我觉得有点像rgb,然后就百度了一下，发现可以可以用 这些数字，拼成图片。直接上Py得到解码密码。


``` bash
from PIL import Image
x=150
y=150
im=Image.new("RGB",(x,y))
file=open("pa.txt")
for i in range(0,x):
    for j in range(0,y):
        print(n)
        line=file.readline()
        rgb=line.split(",")
        im.putpixel((i,j),(int(rgb[0]),int(rgb[1]),int(rgb[2])))
im.show()
im.save("flag.jpg")
``` 

进入后，发现一堆好像是base64加密的字符串，多次拆分用字符串，用base64解密不成功，只好放弃。尝试了大量的解密方法后，偶然用aes解密正确。