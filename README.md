#ethn
p2p的vpn

服务端程序：
>ethns --ip [服务器ip] --port [服务器端口] --key [ethnc的登陆码]

客户端程序：
>ethnc [ethnc.conf配置文件]

ethnc.conf配置示例：
>server_host:x.y.m.n 	服务器的ip为x.y.m.n

>server_port:55555		服务器的端口为55555

>server_key:mmmmm		服务器的接入key为mmmmm

>ethn_key:nnnnn			客户端之间的通信key为nnnnn

>ethn_mac:*				由系统自动生成mac（ethnc会将生成的mac重新写入ethnc.conf）

>ethn_ip:172.16.16.1		本客户端的ip为172.16.16.1

>ethn_mask:255.255.255.0	本客户端的子网掩码为255.255.255.0

>ethn_mtu:1400			生成接口的mtu为1400

>sleep_from:*			-

>sleep_to:*				-

>forward:0				禁止wan口的数据只通过服务器转发

项目博客：http://blog.jing.pw
