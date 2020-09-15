Dnasp的定义

Dnasp是Debian上一键安装轻量级的PHP环境的脚本！支持Nginx Apache PHP Sqlite proftpd，可选安装Dnate代理，可选安装Snmp监控；

Dnasp的来由

123systems的10刀虽然便宜但是内存不给力，所以大家丢的比较多，也造成现在硬盘速度和带宽良好。本一键安装包的目的是创建一个nasp环境，安装proftpd,dnate代理。安装后的环境跑博客（typecho）、文章（akcms）、论坛（punbb）还有一个sockets代理，内存占用和速度还是非常不错的。
特别声明：本脚本hack的actgod的一键包。删除了mysql wordpress；增加了sqlite punbb akcms proftpd dnate；调整了apache2进程数等信息；更换phpmyadmin为navicat管理数据库的http通道文件；自动下载探针。

 

Dnasp的优点

更新频率快：自用脚本，经常性增加新功能；
安装速度快：全部使用Debian源安装，5分钟安装完毕；
脚本性能高：专为小内存VPS调优，123systems、buyvm、ramhost
定制度高：脚本是写来自己用的，用途包括虚拟主机，Socks 5代理，所以其他的杂项功能一概没有。
安全度高。所有程序均是通过debian官方stable源安装。debian本身就是以安全稳定资源消耗小闻名，stable的软件更是经过非常严格的测试，所以不用担心本一键包有任何后门和私货。
Dnasp的使用示例

三条命令即可开始typecho

wget http://debian-anmpz.googlecode.com/svn/trunk/dnasp.sh
bash dnasp.sh stable
bash dnasp.sh typecho blog.99288.net.cn

Dnasp的文档

下载地址：http://debian-anmpz.googlecode.com/svn/trunk/dnasp.sh

命令清单：

bash dnasp.sh system # 优化系统，删除不需要组件，dropbear替代sshd
bash dnasp.sh exim4 # 更轻量级邮件系统
bash dnasp.sh php # 安装php，包含php5-gd，php5-curl，php5-sqlite。
bash dnasp.sh apache #安装apache2，包含基本模块，默认最大进程数为8，可调整
bash dnasp.sh stable # 安装上面所有，软件是debian官方stable源（squeeze），版本较旧
bash dnasp.sh vhost yourdomain # 一键安装静态虚拟主机，方便直接上传网站程序。
bash dnasp.sh dhost yourdomain # 一键安装动态虚拟主机，方便直接上传网站程序。
bash dnasp.sh typecho yourdomain # 安装typecho
bash dnasp.sh ssh 用户名 密码 #生成仅供ssh代理上网，不能登录shell进行vps操作的帐号
bash dnasp.sh addapache 3 8 #调整apache进程数，3是启动时的进程数，8为允许最大进程数，请根据vps配置更改
bash dnasp.sh sshport 22022 #更改ssh端口号22022，建议更改10000以上端口。重启后生效。
bash dnasp.sh eaccelerator # 安装php加速器，建议256m内存以上vps才安装

增加命令：(2012-05-21)

bash dnasp.sh snmp #安装snmp支持，方便远程监控

bash dnasp.sh proftpd youdomain #安装proftpd,支持FTP上传；youdomain为WEB管理FTP用

bash dnasp.sh dnate IP port #安装Sockets 5代理

bash dnasp.sh status domain #安装nginx状态监控

bash dnasp.sh phost youdomain IP #安装nginx反向代理

bash dnasp.sh safephp #禁用php危险函数

bash dnasp.sh upotime #更新服务器时间源。

自用命令，可选安装：

 
bash dnasp.sh change_id id domain.com #更改目录权限 ID为sqlite映射的ID domain.com是绑定的域名。

bash dnasp.sh varnish #安装varnish缓存；

bash dnasp.sh akcms domain #安装akcms；意义不大，akcms自带在线安装。

bash dnasp.sh punbb domain #安装punbb；自用，已带中文、code、附件等插件。论坛小巧，受众不大。

bash dnasp.sh wiki domain #安装mediawiki；自用，更换了皮肤，安装了常用插件。受众也不大，据说收录没有hdwiki好

bash dnasp.sh pmwiki domain #安装pmwiki;轻量级wiki程序，更适合内部存储用。
