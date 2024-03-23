仅使用SSHv2 协议
为了确保系统的完整性，应当将SSH服务配置为仅接受SSHv2连接。
Protocol 2

关闭或者延迟压缩
SSH可以使用gzip算法压缩数据，如果压缩软件中存在漏洞，就可能影响到系统。
要将压缩延迟到身份认证后，则需要修改为：
Compression delayed

显示最后一次登录的日期和时间
这通常是现代系统中的默认设置，但是检查其是否正确配置仍然很重要。通过打印最后一次登录的日期和时间，用户可以意识到未经授权的账户登录事件，这将对进一步调查无法识别的访问提供帮助。
PrintLastLog yes

结束空闲的SSH会话
无限期地将SSH会话保持打开状态不是一个好方法，因为用户可能离开他们的工作站，这给了一个未授权用户在无人看管的工作站上执行命令的好机会。最好的办法是在短时间内终止空闲的SSH会话，不给他人留机会。
选项和选项相互配合，例如要在十五分钟（900秒）后关闭不活动的会话，修改配置文件如下：
ClientAliveInterval 900
ClientAliveCountMax 0

#使用DenyUsers来禁止某些用户，比如这样修改配置文件：
DenyUsers root 

禁用空密码
确保任何SSH连接都需要一个非空的密码字符串（这并不会影响SSH密钥认证登录模式）。
PermitEmptyPasswords no

更改默认 SSH 端口
SSH 服务器默认使用端口 22 来创建连接，因此，理论上，将端口 22 用于 SSH 服务器会使您的服务器更容易受到黑客的攻击。我们将为 SSH 服务器设置端口 5333。可以使用任何未使用的端口。
sudo ufw allow 5333/tcp

打开/etc/ssh/sshd_config文件。
sudo nano /etc/ssh/sshd_config
#并更改SSH端口
port 5333
重新启动 SSH 服务器以应用新配置。
sudo systemctl restart sshd

注销您的服务器并使用端口 5333 重新登录。
$ ssh admin@[IP-address] -i [path-to-private-key] -p 5333

禁用空密码
确保任何SSH连接都需要一个非空的密码字符串（这并不会影响SSH密钥认证登录模式）。
PermitEmptyPasswords no
使用公钥/私钥对代替密码使用公钥/私钥对访问 SSH 服务器比使用基于密码的身份验证更安全。受密码保护的 SSH 服务器更容易受到暴力攻击。 
打开/etc/ssh/sshd_config文件。
sudo nano /etc/ssh/sshd_config
并将PasswordAuthentication选项设置为no。
PasswordAuthentication no
重新启动 SSH 服务器以应用更改。
sudo systemctl restart sshd

禁用基于受信主机的无密码登录
文件是一种控制系统间信任的关系的方法，如果一个系统信任另一个系统，则这个系统不需要密码就允许来自受信认系统的登录。这是一个旧的配置，应当在SSH配置中明确禁用。
IgnoreRhosts yes

Keepalive/超时设置
在 Webdock Perfect Server 堆栈上，我们默认使用以下设置保持连接处于活动状态。但是，如果您不想保持连接处于活动状态并自动超时，则可以删除这些行。在原生 Ubuntu 安装中，连接将在一两分钟不活动后自动断开。
打开 SSH 配置文件。
sudo nano /etc/ssh/sshd_config
#并设置TCPKeepAlive、ClientAliveInterval和ClientAliveCountMax选项的值。
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3
设置有限的密码重试次数
设置有限的密码尝试次数是防止 SSH 服务器遭受暴力攻击的好方法。此外，fail2ban 会自动为 SSH 执行此操作。 SSH 服务器提供配置来设置每个连接允许的身份验证尝试次数。打开 SSH 配置文件。
sudo nano /etc/ssh/sshd_config
#并设置MaxAuthTries选项的值。
MaxAuthTries 3
禁用 root 登录
使用 root 用户访问 SSH 服务器并不是一个好的做法。始终使用非特权用户账户访问 SSH 服务器。
打开配置文件。
sudo nano /etc/ssh/sshd_config
#使用PermitRootLogin选项禁用 root 登录。
PermitRootLogin no

禁用基于已知主机的访问
文件用于标识服务器，当用户启动SSH连接时，SSH会将服务器指纹与文件中存储的指纹进行比较，来确保用户连接到的是正确的系统。这个配置与配置相互配合，确保与远程主机连接时需要密码（通过设置该选项，来保证每一次连接都将远程主机视为“非信任”主机）。
IgnoreUserKnownHosts yes

禁用基于主机的身份认证
这个功能类似于基于受信主机的认证，但是仅用于SSH-2，在我的经验里这个功能很少使用，应当设置为。
禁用基于基于主机的身份认证，请修改配置文件如下：
HostBasedAuthentication no

禁用X11Forwarding
X11Forwarding允许通过SSH会话远程执行程序，并在客户端显式图形界面。如果没有特殊需求，则应将其禁用。
X11Forwarding no

将服务绑定到指定IP
默认情况下，SSH会监听本机上配置的所有IP地址，指定SSH绑定在特定的IP，最好是在专用VLAN中的地址。
ListenAddress 10.0.0.5

保护SSH密钥
保护主机私钥
你应该保护主机私钥防止未授权的访问，如果私钥泄露，则主机可能会被假冒，因此所有的私钥文件都应设置为仅允许root用户访问（对应权限为0600）。
使用命令列出文件夹下所有的私钥文件：
ls -l /etc/ssh/*key

使用命令设置私钥文件权限：
chmod 0600 /etc/ssh/*key
大多数情况下，私钥文件存储在文件夹下，但是也有可能存储在其他目录中，通过以下命令可以检索配置文件中设置的存储位置：
grep -i hostkey /etc/ssh/sshd_config

保护主机公钥
虽然公钥不如私钥那么重要，但你还是应该对其进行保护，因为如果公钥被篡改，则可能会使SSH服务无法正常工作或者拒绝服务，因此需要配置权限仅允许root账户对其进行修改（对应权限为0644）。
使用命令列出目录下所有的公钥文件：
ls -l /etc/ssh/*pub

使用命令修改公钥文件权限：
chmod 0644 /etc/ssh/*pub
通常情况下公钥和私钥存放在同一目录下，或者使用上一节的方法查找存放路径。
检查用户特定的配置文件
用户可能会在无意间将自己的home目录或者其他某些文件设置成全局可写（比如777权限），在这种情况下，其他用户将有权修改用户特定的配置，并以其他用户的身份登录到服务器。可以通过使用选项来检查home目录的配置。
设置ssh在接收登录之前是否检查用户home目录和rhosts文件的权限和所有权，为yes必需保证存放公钥的文件夹的拥有者与登陆用户名是相同的。

确保启用严格模式，请修改配置文件如下：
StrictModes yes
建议使用此方法，尤其是对于有大量用户的系统。
防止特权升级
SSH通过创建一个无特权的子进程来接收传入的连接，实现权限分离。用户身份验证后，SSH将使用该用户的权限创建另一个进程。

在我所了解的系统中，这个选项默认都是开启的，但是为了保险起见，建议还是手动修改配置文件，显式指定该配置：
UsePrivilegeSeparation sandbox
使用可以增加其他限制。
使用密钥进行身份验证
该功能并不一定在所有系统上都可用，但是使用SSH密钥身份验证有很多优点。密钥验证比人类可以轻松记住的任何密码都要强大的多，同时还提供了无需密码的身份验证，使用更加便利。

启用密钥身份验证，请修改配置文件如下：
PubkeyAuthentication yes
该选项在大多数系统上默认为。
更多有关SSH密钥身份验证的信息，请参考 How to Setup SSH Key Authentication。

禁用不使用的身份验证方法
Linux管理员知道优秀的安全实践是停止并删除所有用不到的服务，同样，你也应该禁用SSH中不使用的其他任何身份验证方法。
在这里，我将向你展示禁用所有身份验证的方法，但是请注意：不要全部禁用它们，请保留需要的。

禁用 GSSAPI 认证
通过“通用安全服务应用程序接口”（GSSAPI），可以使用高级配置和其他身份验证方法（除口令、密钥认证方式之外的），如果你不使用此功能，则请修改配置文件如下：
GSSAPIAuthentication no
禁用Kerberos认证

同样，如果不需要则禁用：
KerberosAuthentication no

禁用口令认证
如果配置了更高级的认证方式，则可禁用口令认证：
PasswordAuthentication no

禁用密钥认证
如果你使用了其他身份认证方式，则可以禁用密钥身份认证。相比其他办法，使用密钥认证是风险较小的办法。如需禁用，修改配置文件如下：
PubkeyAuthentication no

使用符合FIPS 140-2标准的密码
使用符合FIPS 140-2的规范，避免使用弱加密算法，请修改配置文件如下：
Ciphers aes128-ctr,aes192-ctr,aes256-ctr
这样的设置限制了可用于SSH的加密方式，因此应用前需确认任何可能会用到的老旧客户端、脚本或应用程序的兼容性。
“FIPS 140-2” 为美国国家标准和技术委员会发布的针对密码模块的安全需求标准，作为联邦信息处理标准在政府机构广泛采用。

使用符合FIPS 140-2标准的MAC
与上一小节相同，使用符合FIPS 140-2的规范，避免使用弱加密哈希算法：
MACs hmac-sha2-256,hmac-sha2-512
配置主机防火墙过滤传入的SSH连接
检查传入SSH连接也是保护SSH的好方法，可以仅允许特定的IP或子网连接到系统，下面将演示通过iptables、firewalld和 Uncomplicated Firewall (UFW)配置防火墙的方法。

使用iptables过滤SSH连接
允许特定IP连接：
iptables -I INPUT -p tcp -s <指定的IP> --dport 22 -j ACCEPT

允许特定的子网：
iptables -I INPUT -p tcp -s <指定子网> --dport 22 -j ACCEPT
通过Firewalld过滤SSH连接

允许特定IP连接SSH：
firewall-cmd --permanent --zone=public --add-rich-rule=' rule family="ipv4"   source address="<指定IP>"   port protocol="tcp" port="22" accept'
允许特定子网：
firewall-cmd --permanent --zone=public --add-rich-rule='   rule family="ipv4"   source address="<指定子网>"   port protocol="tcp" port="22" accept'

设置一个Banner
以我的经验来看，这样做弊大于利，虽然修改Banner（连接提示信息）可以阻止一些脚本小子，但是数经验丰富的老鸟可能会将其视为一种挑衅，因此如果确实要增加Banner，请考虑消息的语气。
Banner /etc/issue
编辑文件，即可添加连接到SSH后的提示信息。
