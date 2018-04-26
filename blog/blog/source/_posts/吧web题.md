title: 实验吧web题
author: Qianye
abbrlink: 761c3e82
tags:
  - ctf
categories:
  - ctf
date: 2018-03-28 18:48:00
---
# 简单的登录题

```bash
<?php define("SECRET_KEY", '***********');
define("METHOD", "aes-128-cbc");
error_reporting(0);
include('conn.php');
function sqliCheck($str){
	if(preg_match("/\\\|,|-|#|=|~|union|like|procedure/i",$str)){
		return 1;
	}
	return 0;
}
function get_random_iv(){
	$random_iv='';
	for ($i=0;$i<16;$i++){
		$random_iv.=chr(rand(1,255));
	}
	return $random_iv;
}
function login($info){
	$iv = get_random_iv();
	$plain = serialize($info);
	$cipher = openssl_encrypt($plain, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv);
	setcookie("iv", base64_encode($iv));
	setcookie("cipher", base64_encode($cipher));
}
function show_homepage(){
	global $link;
	if(isset($_COOKIE['cipher']) && isset($_COOKIE['iv'])){
		$cipher = base64_decode($_COOKIE['cipher']);
		$iv = base64_decode($_COOKIE["iv"]);
		if($plain = openssl_decrypt($cipher, METHOD, SECRET_KEY, OPENSSL_RAW_DATA, $iv)){
			$info = unserialize($plain) or die("
base64_decode('".base64_encode($plain)."') can't unserialize
");
			$sql="select * from users limit ".$info['id'].",0";
			$result=mysqli_query($link,$sql);
			if(mysqli_num_rows($result)>0 or die(mysqli_error($link))){
				$rows=mysqli_fetch_array($result);
				echo '
Hello!'.$rows['username'].'
';
			} else{
				echo '
Hello!
';
			}
		} else{
			die("ERROR!");
		}
	}
}
if(isset($_POST['id'])){
	$id = (string)$_POST['id'];
	if(sqliCheck($id)) die("
sql inject detected!
");
	$info = array('id'=>$id);
	login($info);
	echo '
Hello!
';
} else{
	if(isset($_COOKIE["iv"])&&isset($_COOKIE['cipher'])){
		show_homepage();
	} else{
		echo '
';
	}
}
?>
```
[aes加密算法](https://www.cnblogs.com/block2016/p/5596676.html)   
# 后台登录 
查看源码可得
```bash
	<!-- $password=$_POST['password'];
	$sql = "SELECT * FROM admin WHERE username = 'admin' and password = '".md5($password,true)."'";
	$result=mysqli_query($link,$sql);
		if(mysqli_num_rows($result)>0){
			echo 'flag is :'.$flag;
		}
		else{
			echo '密码错误!';
		} -->

``` 
可以下url连接，就大概猜到考什么了，做过两三次了， 直接提交 
```bash
ffifdyop
```
# 加了料的报错注入  
查看源码
```bash
<!-- $sql="select * from users where username='$username' and password='$password'";  -->
```