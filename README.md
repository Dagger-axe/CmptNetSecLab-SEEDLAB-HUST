该实验由以下三个主要板块构成：TCP协议漏洞利用、DNS攻击、VPN实现。

## TCP协议漏洞利用

+ 用netwox进行TCP SYN-Flooding攻击
+ 用scapy进行TCP SYN-Flooding攻击
+ 用C程序进行TCP SYN-Flooding攻击
+ 用netwox进行TCP Reset攻击
+ 用scapy进行TCP Reset手动攻击
+ 用scapy进行TCP Reset自动攻击
+ 用netwox进行TCP会话劫持攻击（包括注入普通命令和反向Shell）
+ 用scapy进行TCP会话劫持手动攻击（包括注入普通命令和反向Shell）
+ 用scapy进行TCP会话劫持自动攻击（包括注入普通命令和反向Shell）

## DNS攻击

+ 实验环境配置（用户机、DNS服务器配置，验证www.example.com是否正确解析为所配置的IP地址）
+ 用netwox进行DNS用户响应欺骗攻击
+ 用netwox进行DNS缓存中毒攻击
+ 用scapy进行DNS缓存中毒攻击（包括授权域和附加域的毒化）
+ 远程DNS缓存中毒攻击实验环境配置（包括本地DNS服务器和攻击者机器的配置）
+ 远程DNS缓存中毒攻击（攻击流程设计与代码实现、验证）

## VPN实现

实现一个支持客户端与服务端双向认证的允许多个连接的VPN（包括client和server），在该实验中该VPN被称为MiniVPN。