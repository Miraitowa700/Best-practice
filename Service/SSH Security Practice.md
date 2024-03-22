更改默认 SSH 端口
SSH 服务器默认使用端口 22 来创建连接，这一点大家都知道。因此，理论上，将端口 22 用于 SSH 服务器会使您的服务器更容易受到黑客的攻击。在本指南中，我们将为 SSH 服务器设置端口 5333。您可以使用任何未使用的端口。
请注意：请确保在关闭旧端口之前打开新端口。
警告：更改 SSH 端口将破坏我们的 Web SSH 终端功能，该功能假定 SSH 在默认端口上。
如果我们安装了 ufw 的 Webdock 完美服务器堆栈，请打开端口 5333。
sudo ufw allow 5333/tcp

打开/etc/ssh/sshd_config文件。
sudo nano /etc/ssh/sshd_config

并更改SSH端口
port 5333

请注意：每次更改配置文件时，都需要重新启动 SSH 服务器才能应用更改。
重新启动 SSH 服务器以应用新配置。
sudo systemctl restart sshd

注销您的服务器并使用端口 5333 重新登录。
$ ssh admin@[IP-address] -i [path-to-private-key] -p 5333

使用公钥/私钥对代替密码
请注意：这已经是 Ubuntu 中以及 Webdock 服务器上的默认安装。您可以在 Webdock 的 Shell 用户屏幕上启用密码身份验证（不推荐）。使用公钥/私钥对访问 SSH 服务器比使用基于密码的身份验证更安全。受密码保护的 SSH 服务器更容易受到暴力攻击。 
打开/etc/ssh/sshd_config文件。
sudo nano /etc/ssh/sshd_config


并将PasswordAuthentication选项设置为no。
PasswordAuthentication no

重新启动 SSH 服务器以应用更改。
sudo systemctl restart sshd

只允许单个IP登录
SSH 服务器的默认配置允许 SSH 服务器接受来自任何 IP 地址的连接。限制您的 SSH 服务器仅接受来自您信任的 IP 地址的连接。您可以通过将防火墙配置为仅接受从特定 IP 到服务器上特定端口的连接来实现此目的。
请注意：确保您的可信 IP 地址是静态的。否则您的可信 IP 可能会发生变化，您将无法访问您的服务器。
警告：限制为单个 IP 将破坏我们的 Web SSH 终端功能。您可以允许 157.90.77.137 和 2a01:4f8:141:4398::607，它们应保留通过 Web SSH 的访问权限（截至 2021 年末），但这些 IP 可能随时更改。在我们使用 UFW 且您的 IP 为 192.168.0.200 并且 SSH 在默认端口 22 上的 Webdock Perfect Server 堆栈上，您将执行：
sudo ufw allow from 192.16.0.200 to any port 22
Keepalive/超时设置
在 Webdock Perfect Server 堆栈上，我们默认使用以下设置保持连接处于活动状态。但是，如果您不想保持连接处于活动状态并自动超时，则可以删除这些行。在原生 Ubuntu 安装中，连接将在一两分钟不活动后自动断开。
打开 SSH 配置文件。
sudo nano /etc/ssh/sshd_config

并设置TCPKeepAlive、ClientAliveInterval和ClientAliveCountMax选项的值。
TCPKeepAlive yes
ClientAliveInterval 60
ClientAliveCountMax 3


在断开连接之前，SSH 服务器将在 60 秒不活动后检查客户端的状态，并发送空数据包以保持连接处于活动状态。如果没有收到响应，服务器将在终止连接之前重复此过程两次。
重新启动 SSH 服务器以应用更改。
 sudo systemctl restart sshd

设置有限的密码重试次数
设置有限的密码尝试次数是防止 SSH 服务器遭受暴力攻击的好方法。此外，fail2ban 会自动为 SSH 执行此操作。 SSH 服务器提供配置来设置每个连接允许的身份验证尝试次数。打开 SSH 配置文件。
sudo nano /etc/ssh/sshd_config
并设置MaxAuthTries选项的值。
MaxAuthTries 3

SSH 服务器只允许每个连接尝试 3 次登录。
重新启动 SSH 服务器以应用更改。
sudo systemctl restart sshd
禁用 root 登录
使用 root 用户访问 SSH 服务器并不是一个好的做法。始终使用非特权用户账户访问 SSH 服务器。
打开配置文件。
sudo nano /etc/ssh/sshd_config
并使用PermitRootLogin选项禁用 root 登录。
PermitRootLogin no

现在 root 登录已被禁用，SSH 服务器只能由非 root 用户访问。
重新启动 SSH 服务器以应用更改。
sudo systemctl restart sshd
