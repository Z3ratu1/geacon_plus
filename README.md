# geacon_plus
golang实现的CobaltStrike stageless http(s)/dns beacon,支持windows/linux/macos

感谢好兄弟[@H4de5](https://github.com/H4de5-7)提供的windows部分代码支持  
二次开发思路[CobaltStrike beacon二开指南](https://blog.z3ratu1.top/CobaltStrike%20beacon%E4%BA%8C%E5%BC%80%E6%8C%87%E5%8D%97.html)  
dns beacon实现细节[CS DNS beacon二次开发指北](https://blog.z3ratu1.top/CS%20DNS%20beacon%E4%BA%8C%E6%AC%A1%E5%BC%80%E5%8F%91%E6%8C%87%E5%8C%97.html)  

## 免责声明
请在完全阅读并认同如下内容后使用本项目  

**该项目仅用于对CobaltStrike协议的学习以及相关技术手法实现的测试。
请勿使用于任何非法用途，严禁使用该项目对计算机信息系统进行攻击。由此产生的后果由使用者自行承担**。  

姊妹项目[geacon_pro](https://github.com/H4de5-7/geacon_pro)由于存在较高的攻击性，存在被滥用风险，已转为私有，不再对外开放  
本项目未同步更新pro版本中后期添加的免杀相关功能，仅作为学习CS beacon的设计使用。


## 实现功能
支持跨平台使用,可在linux及macOS上执行简单命令(没有macOS所以是理论上可以执行)  
已通过本地windows7/10,winserver 2012与ubuntu22.04的测试  
实现了实验性质的dns beacon,在CS4.0和CS4.3版本下测试通过。

好像大家更喜欢高版本。。。所以进行了4.1+版本的兼容，可以在config/config.go中使用Support41Plus指定使用4.0版本还是4.1+版本

## 使用方法
本项目基于[darkr4y/geacon](https://github.com/darkr4y/geacon)进行改进，具体使用方法可参考原项目  
c2profile支持部分编码和填充，项目中的c2profile来自于经典jquery.profile，此处一并给出  
编译时可添加-ldflags "-H windowsgui -s -w"减小程序体积并取消黑框，同样可以使用[go-strip](https://github.com/boy-hack/go-strip)项目删除符号表等数据(好像该项目在go高版本下已失效)

### c2profile
实现了对c2profile的部分支持 
支持对服务端客户端数据的编码以及prepend append，编码算法支持base64,base64url,netbios,netbiosu,mask

dns部分支持自定义域名前缀

### 文件管理
实现了mv,cp,mkdir,rm,upload,download,fileBrowse  
以标准格式返回数据，支持CS图形化界面交互

### 进程管理
实现了listProcess和kill,同样支持图形化交互

### 命令执行
实现了shell、run和execute，使用本地shell执行命令，windows下使用CreateProcess创建进程

### 进程注入
仅支持windows平台
支持反射dll注入，实现有单纯进程注入与拉起傀儡进程注入，支持screenshot,portscan,netview等CobaltStrike RDI任务
由于注入远程线程有一定几率被抓，添加了一个patch dll的exitProcess为exitThread后将spawn+inject的改为注入自身的操作，可以在config中选开

### token相关
尝试实现了runas、make token，steal token等功能
steal token能用，runas处报迷之错误，不清楚什么情况，
make token很怪，用LOGON32_LOGON_BATCH输什么都密码错误，用LOGON32_LOGON_NEW_CREDENTIALS输啥都对拿回来的token用不了，好像是仅能用于网络交互?不是很熟

### 后渗透功能
支持内存加载PowerShell module，支持使用反射DLL注入或go语言内存执行C#

## TODO
转到issue里了

## reference
本项目开发过程中参考了如下优秀项目  
[mai1zhi2/SharpBeacon](https://github.com/mai1zhi2/SharpBeacon)  
[darkr4y/geacon](https://github.com/darkr4y/geacon)  
[WBGlIl/ReBeacon_Src](https://github.com/WBGlIl/ReBeacon_Src)