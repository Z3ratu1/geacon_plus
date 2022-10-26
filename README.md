# geacon_plus
golang实现的CobaltStrike stageless http(s) beacon,在geacon项目基础上进行了较多扩展

**该项目仅用于对CobaltStrike协议的学习测试。请勿使用于任何非法用途，由此产生的后果自行承担**

感谢好兄弟[@H4de5](https://github.com/H4de5-7)提供的windows部分代码支持

## 使用方法
本项目基于[darkr4y/geacon](https://github.com/darkr4y/geacon)进行改进，具体使用方法可参考原项目
编译时可添加-ldflags "-H windowsgui -s -w"减小程序体积并取消黑框，同样可以使用[go-strip](https://github.com/boy-hack/go-strip)项目删除符号表等数据

## 实现功能
支持跨平台使用,可在linux及macOS上执行简单命令(没有macOS所以是理论上可以执行)  
已通过本地windows7/10,winserver 2012与ubuntu22.04的测试,**暂只支持CobaltStrike4.0**，对高版本的支持可以通过修改metadata部分内容实现(大概)

### c2profile
实现了对c2profile的部分支持 
支持对服务端客户端数据的编码以及prepend append，编码算法支持base64,base64url,netbios,netbiosu,mask

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
make token很怪，用LOGON32_LOGON_BATCH输什么都密码错误，用LOGON32_LOGON_NEW_CREDENTIALS输啥都对拿回来的token用不了

### 后渗透功能
支持内存加载PowerShell module，支持使用反射DLL注入或go语言内存执行C#

## 完善
由于调试服务端时总是报错行号对不上，代码的绝大多数是通过静态分析以及搜索资料等形式实现的，并不能保证对CS协议的完整还原  
同时，作者的windows水平低下，因此对令牌窃取，hash传递方面一窍不通，对内网级联等操作也未认真分析(搞不动了)，欢迎各路神仙交流讨论以及提交PR

## TODO
- ~~实现令牌窃取等功能~~
- 实现内网级联端口转发代理等功能
- 实现stager(从来不用，并没有这个打算)
- 实现DNSbeacon(好像有人实现了，从来不用，并没有这个打算)

## reference
本项目开发过程中参考了如下优秀项目  
[mai1zhi2/SharpBeacon](https://github.com/mai1zhi2/SharpBeacon)  
[darkr4y/geacon](https://github.com/darkr4y/geacon)  
[WBGlIl/ReBeacon_Src](https://github.com/WBGlIl/ReBeacon_Src)