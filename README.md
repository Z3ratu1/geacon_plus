# geacon_plus
golang实现的CobaltStrike beacon

**该项目仅用于对CobaltStrike协议的学习测试，请勿使用于任何非法用途，由此产生的后果自行承担**

请不要将该项目上传vt等平台以延长其存活时间

## 使用方法
本项目基于[darkr4y/geacon](https://github.com/darkr4y/geacon)进行改进，具体使用方法可参考原项目

## 实现功能
支持跨平台使用,可在linux及macOS上执行简单命令(没有macOS所以是理论上可以执行)  
已通过本地windows10与ubuntu22.04的测试,暂只支持CobaltStrike4.0，对高版本的支持可以通过修改metadata部分内容实现(大概)

### c2profile
实现了对c2profile的部分支持，较为完整的实现了与服务端的通信协议  
支持对服务端客户端数据的编码以及prepend append，编码算法支持base64,base64url,netbios,netbiosu,mask

### 文件管理
实现了mv,cp,mkdir,rm,upload,download,fileBrowse  
以标准格式返回数据，支持CS图形化界面交互

### 进程管理
实现了listProcess和kill,同样支持图形化交互

### 命令执行
实现了shell和execute，使用本地shell执行命令

### 进程注入
仅支持windows平台
支持dll注入，支持screenshot,portscan,netview等CobaltStrike RDI任务

## 完善
由于调试服务端时总是报错行号对不上，代码的绝大多数是通过静态分析以及搜索资料等形式实现的，并不能保证对CS协议的完整还原  
同时，作者的windows水平低下，因此对令牌窃取，hash传递方面一窍不通，对内网级联等操作也未认真分析(搞不动了)，欢迎各路神仙交流讨论以及提交PR

## TODO
- 实现令牌窃取等功能
- 实现内网级联端口转发等功能
- 实现stager(从来不用，并没有这个打算)
- 实现DNSbeacon(好像有人实现了，从来不用，并没有这个打算)

## reference
本项目开发过程中参考了如下优秀项目  
[mai1zhi2/SharpBeacon](https://github.com/mai1zhi2/SharpBeacon)  
[darkr4y/geacon](https://github.com/darkr4y/geacon)

后续就着鸡哥的文章补充功能吧
[\[原创\]魔改CobaltStrike：beacon浅析(下)](https://bbs.pediy.com/thread-268418.htm)