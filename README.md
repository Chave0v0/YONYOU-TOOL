# YONYOU-TOOL

用于用友漏洞一键利用。

学习用友漏洞期间一时兴起，写一款工具记录学习。

工具开发期间，感谢 **SpringKill** 师傅指点。

## 免责声明

本工具仅适用于安全研究学习，严禁使用本工具发起网络黑客攻击，造成法律后果，请使用者自负。

## 支持漏洞

```
ActionHandlerServlet 反序列化 (ActionHandlerServlet)
Lfw_Core_Rpc 文件上传 (Lfw_Core_Rpc_Upload)
```

后续根据学习进度佛系更新完善poc。

## 使用说明

java -jar 启动。

```
java -jar YONYOU-TOOL-[version].jar
```

目前实现功能模块：漏洞探测、一键getshell、命令执行、文件上传。

![image-20240803011214957](assets/image-20240803011214957.png)

### 漏洞探测

以 **ActionHandlerServlet 反序列化** 漏洞为例。

选择漏洞，填写必要信息，点击探测，可自行在 dnslog 平台查看结果。

![image-20240803011544819](assets/image-20240803011544819.png)

### 一键getshell

支持一键 getshell。目前 getshell 方式均以打入内存马方式实现，同时注入回显、冰蝎、哥斯拉。

```
Filter 内存马连接地址：http://x.x.x.x/...网站目录.../*
--------------------------------------------------------------------------------------------
回显
添加请求头
x-client-referer:http://www.baidu.com/
x-client-data:testzxcv
testzxcv:<base64编码后命令>
--------------------------------------------------------------------------------------------
冰蝎
添加请求头
x-client-referer:http://www.baidu.com/
x-client-data:behinder
密码
chaveyyds
--------------------------------------------------------------------------------------------
哥斯拉
添加请求头
x-client-referer:http://www.baidu.com/
x-client-data:godzilla
密钥
chaveyyds
密码
pass
```

以 **Lfw_Core_Rpc 文件上传** 漏洞为例。

选择漏洞，输入目标url，点击 getshell。

![image-20240803012708205](assets/image-20240803012708205.png)

根据连接信息连接利用即可。

![image-20240803013644223](assets/image-20240803013644223.png)

![image-20240803020919351](assets/image-20240803020919351.png)

![image-20240803013956646](assets/image-20240803013956646.png)

### 命令执行

以 **ActionServletHandler 反序列化** 漏洞为例。

进入 **命令执行** 模块，输入命令，点击执行即可，目前该漏洞已支持 **CC6** 与 **freemarker.template.utility.Execute** 两种命令执行。

![image-20240803012445202](assets/image-20240803012445202.png)

### 文件上传

以 **Lfw_Core_Rpc 文件上传** 漏洞为例。

选择漏洞，进入文件上传模块，输入文件名，文件内容，点击上传即可。

![image-20240803014217507](assets/image-20240803014217507.png)

![image-20240803014246830](assets/image-20240803014246830.png)

## 更新记录

### 20240724

- v1.0 版本发布，命令行工具版本。
- 支持漏洞 **ActionServletHandler 反序列化** 探测利用。

### 20240803

- v2.0 版本发布，实现图形化。
- 新增命令执行回显模块。
- 新增文件上传模块。
- 支持漏洞 **Lfw_Core_Rpc 文件上传** 探测利用。

## 最后

开发过程中参考相关漏洞利用工具：

- https://github.com/wafinfo/NCTOOls

- https://github.com/R4gd0ll/I-Wanna-Get-All

工具以记录自己学习为主，本人佛系更新。

工具开源，有需要可自行在 com.chave.vuln 包内添加漏洞 poc。