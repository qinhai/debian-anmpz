#!/bin/bash
#NAMP for 123systems.net Debian 6.0 X86

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        executable=$1
        shift
        while [ -n "$1" ]
        do
            DEBIAN_FRONTEND=noninteractive apt-get -q -y --force-yes install "$1"
            print_info "$1 installed for $executable"
            shift
        done
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/debian_version ]
    then
        die "Distribution is not supported"
    fi
}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}

 function install_uptime {
	dpkg-reconfigure tzdata
	check_install ntpdate ntpdate
	ntpdate time-b.nist.gov
}

function get_domain_name() {
    # Getting rid of the lowest part.
    domain=${1%.*}
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    case "$lowest" in
    com|net|org|gov|edu|co)
        domain=${domain%.*}
        ;;
    esac
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    [ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_dash {
    check_install dash dash
    rm -f /bin/sh
    ln -s dash /bin/sh
}

function install_dropbear {
    check_install dropbear dropbear
    check_install /usr/sbin/xinetd xinetd

    # Disable SSH
    touch /etc/ssh/sshd_not_to_be_run
    /etc/init.d/ssh stop

    # Enable dropbear to start. We are going to use xinetd as it is just
    # easier to configure and might be used for other things.
    cat > /etc/xinetd.d/dropbear <<END
service dropbear
{
socket_type = stream
only_from = 0.0.0.0
wait = no
user = root
protocol = tcp
server = /usr/sbin/dropbear
server_args = -i
disable = no
port = 22
type = unlisted
}
END

    /etc/init.d/xinetd restart
}

function install_exim4 {
    
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        /etc/init.d/exim4 restart
    fi
}

function install_mysql {
    # Install the MySQL packages
    check_install mysqld mysql-server
    check_install mysql mysql-client

    # all the related files.
    /etc/init.d/mysql stop
    rm -f /var/lib/mysql/ib*
    cat > /etc/mysql/conf.d/osiris.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_size = 0
skip-innodb
END
    /etc/init.d/mysql start

    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
    chmod 600 ~/.my.cnf
}

function install_snmpd {	
	if [ $(id -u) != "0" ]; then
		echo "Error: You must be root to run this script, please use root to install lnmp"
		exit 1
	fi

	apt-get -q -y --force-yes install snmpd
	sed -i s/'^agentAddress  udp:127.0.0.1:161'/'#agentAddress  udp:127.0.0.1:161'/g /etc/snmp/snmpd.conf
	sed -i s/'#agentAddress udp:161,udp6:[::1]:161'/'agentAddress udp:161,udp6:[::1]:161'/g /etc/snmp/snmpd.conf
	sed -i s/'# createUser authOnlyUser MD5 "remember to change this password"'/'createUser JianKong MD5 pwosiris'/g /etc/snmp/snmpd.conf
	sed -i s/'^authOnlyUser'/'JianKong'/g /etc/snmp/snmpd.conf
	echo "Restarting SNMPD......"
	/etc/init.d/snmpd restart
	iptables -A INPUT -i eth0 -p udp -s 60.195.249.83 --dport 161 -j ACCEPT
	iptables -A INPUT -i eth0 -p udp -s 60.195.252.107 --dport 161 -j ACCEPT
	iptables -A INPUT -i eth0 -p udp -s 60.195.252.110 --dport 161 -j ACCEPT
	clear
}

function install_php {
    apt-get -q -y --force-yes install php5-cli php5-mysql php5-gd
  }

function install_apache {
	apt-get -q -y --force-yes install libapache2-mod-php5 libapache2-mod-rpaf
	cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.old
	cat > /etc/apache2/apache2.conf <<EXNDDQW
LockFile ${APACHE_LOCK_DIR}/accept.lock
PidFile ${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15
<IfModule mpm_prefork_module>
StartServers       1
MinSpareServers    1
MaxSpareServers    5
MaxClients        10
    MaxRequestsPerChild   0
</IfModule>
<IfModule mpm_worker_module>
StartServers       1
MinSpareThreads    1
MaxSpareThreads    4
    ThreadLimit          64
    ThreadsPerChild      25
MaxClients        10
    MaxRequestsPerChild   0
</IfModule>
<IfModule mpm_event_module>
StartServers       1
MaxClients        10
MinSpareThreads    1
MaxSpareThreads    4
    ThreadLimit          64
    ThreadsPerChild      25
    MaxRequestsPerChild   0
</IfModule>
User ${APACHE_RUN_USER}
Group ${APACHE_RUN_GROUP}
AccessFileName .htaccess
<Files ~ "^\.ht">
    Order allow,deny
    Deny from all
    Satisfy all
</Files>
DefaultType text/plain
HostnameLookups Off
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn
Include mods-enabled/*.load
Include mods-enabled/*.conf
Include httpd.conf
Include ports.conf
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" 209.141.35.207_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
Include conf.d/
Include sites-enabled/*.conf
EXNDDQW

echo "rewrite headers expires" | a2enmod
echo "alias auth_basic authn_file authz_default authz_groupfile authz_host authz_user autoindex cgi env negotiation status" | a2dismod
rm /etc/apache2/sites-enabled/000-default
/etc/init.d/apache2 restart
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    /etc/init.d/inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*                  -/var/log/cron
mail.*                  -/var/log/mail
END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
		/etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    /etc/init.d/inetutils-syslogd start
}

function install_eaccelerator {

apt-get -y --force-yes install build-essential php5-dev bzip2
cd /tmp
wget http://bart.eaccelerator.net/source/0.9.6.1/eaccelerator-0.9.6.1.tar.bz2
tar xvfj eaccelerator-0.9.6.1.tar.bz2
cd eaccelerator-0.9.6.1
phpize
./configure --enable-eaccelerator=shared --with-php-config=/usr/bin/php-config --without-eaccelerator-use-inode
make
make install

cat >> /etc/php5/apache2/php.ini<<end
extension=eaccelerator.so
[eaccelerator]
eaccelerator.shm_size=8
eaccelerator.cache_dir=/tmp/eaccelerator
eaccelerator.enable=1
eaccelerator.optimizer=1
eaccelerator.check_mtime=1
eaccelerator.debug=0
eaccelerator.filter=""
eaccelerator.shm_max=0
eaccelerator.shm_ttl=0
eaccelerator.shm_prune_period=0
eaccelerator.shm_only=0
eaccelerator.compress=1
eaccelerator.compress_level=9
end

mkdir /tmp/eaccelerator
chmod 777 /tmp/eaccelerator


sed -i '2a chmod 777 /tmp/eaccelerator'  /etc/rc.local
sed -i '2a mkdir /tmp/eaccelerator'  /etc/rc.local
/etc/init.d/apache2 restart
}

function install_dhost {
    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi
	mkdir "/var/www/$1"
    mkdir "/var/www/$1"
	useradd -g www-data -d /var/www/$1 -s /sbin/nologin $1
	chown -R $1:www-data "/var/www/$1"
	chmod -R 775 "/var/www/$1"
	passwd $1

	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_mysql.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php


# Setting up Nginx mapping
if [ -f /etc/init.d/nginx ]
then
    cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server
	{
		listen       80;
		server_name $1 www.$1;
		index index.html index.htm index.php default.html default.htm default.php;
		root  /var/www/$1;

		location / {
			try_files \$uri @apache;
			}

		location @apache {
			internal;
			proxy_pass http://127.0.0.1:168;
			include proxy.conf;
			}

		location ~ .*\.(php|php5)?$
			{
				proxy_pass http://127.0.0.1:168;
				include proxy.conf;
			}

		location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|ico)$
			{
				expires      30d;
			}

		location ~ .*\.(js|css)?$
			{
				expires      12h;
			}

		$al
	}
END


    /etc/init.d/nginx reload
   
	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to 06-01@163.com!"
		ServerAdmin="06-01@163.com"
	else
	echo "==========================="
	echo Server Administrator Email="$ServerAdmin"
	echo "==========================="
	fi
	cat >/etc/apache2/conf.d/$1.conf<<eof
<VirtualHost *:168>
ServerAdmin $ServerAdmin
php_admin_value open_basedir "/var/www/$1:/tmp/:/var/tmp/:/proc/"
DocumentRoot /var/www/$1
ServerName $1
ServerAlias www.$1
ErrorLog /var/log/apache2/$1_error.log
CustomLog /var/log/apache2/$1_access.log combined
</VirtualHost>
eof
fi
	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to 06-01@163.com!"
		ServerAdmin="06-01@163.com"
	else
	echo "==========================="
	echo Server Administrator Email="$ServerAdmin"
	echo "==========================="
	fi
	cat >/etc/apache2/conf.d/$1.conf<<eof
<VirtualHost *:80>
ServerAdmin $ServerAdmin
php_admin_value open_basedir "/var/www/$1:/tmp/:/var/tmp/:/proc/"
DocumentRoot /var/www/$1
ServerName $1
ServerAlias www.$1
ErrorLog /var/log/apache2/$1_error.log
CustomLog /var/log/apache2/$1_access.log combined
</VirtualHost>
eof
/etc/init.d/apache2 restart
}

function install_typecho {
    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
		rm -rf /tmp/build
    wget -O - "http://typecho.googlecode.com/files/0.8(10.8.15)-release.tar.gz" | \
        tar zxf - -C /tmp/
    mv /tmp/build/ "/var/www/$1"
    rm -rf /tmp/build
 	chown -R www-data "/var/www/$1"
	chmod -R 755 "/var/www/$1"

	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_mysql.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php


    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`

    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql

    # Setting up Nginx mapping

    cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server
	{
		listen       80;
		server_name $1;
		index index.html index.htm index.php default.html default.htm default.php;
		root  /var/www/$1;

		location / {
			try_files \$uri @apache;
			}

		location @apache {
			internal;
			proxy_pass http://127.0.0.1:168;
			include proxy.conf;
			}

		location ~ .*\.(php|php5)?$
			{
				proxy_pass http://127.0.0.1:168;
				include proxy.conf;
			}

		location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|ico)$
			{
				expires      30d;
			}

		location ~ .*\.(js|css)?$
			{
				expires      12h;
			}

		$al
	}
END

cat >> "/root/$1.mysql.txt" <<END
[wordpress_myqsl]
dbname = $dbname
username = $userid
password = $passwd
END
    /etc/init.d/nginx reload


	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to 06-01@163.com!"
		ServerAdmin="06-01@163.com"
	else
	echo "==========================="
	echo Server Administrator Email="$ServerAdmin"
	echo "==========================="
	fi
	cat >/etc/apache2/conf.d/$1.conf<<eof
<VirtualHost *:168>
ServerAdmin $ServerAdmin
php_admin_value open_basedir "/var/www/$1:/tmp/:/var/tmp/:/proc/"
DocumentRoot /var/www/$1
ServerName $1
ServerAlias www.$1
</VirtualHost>
#ErrorLog /var/log/apache2/$1_error.log
#CustomLog /var/log/apache2/$1_access.log combined
eof

/etc/init.d/apache2 restart

	cat >> "/root/$1.mysql.txt" <<END
[typycho_myqsl]
dbname = $dbname
username = $userid
password = $passwd
END

	echo "mysql dataname:" $dbname
	echo "mysql username:" $userid
	echo "mysql passwd:" $passwd
}

#install dnate
function install_dnate {
	check_install dnate dante-server
	cat > /etc/dnate.conf <<END
internal: $1 port = $2
#internal 表示进口ip设置。这里可以是网卡名，也可以是vps外网ip。port是设置端口，这里端口是1080
#如 internal: $1 port = $2 也是可以的

external: $1
#出口ip设置，同理，可以是网卡名，也可以是ip

method: username none
#认证方式，这里username none表示无需认证

##method: pam
#另一种认证方式。可以通过相关模块实现mysql认证。这里默认是通过系统用户认证。具体下面再说。

#user.privileged: root
user.notprivileged: nobody
#logoutput: stderr
logoutput: /var/log/danted.log
#日志

##下面的相关规则，可以不用管
client pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
log: connect disconnect
}
pass {
from: 0.0.0.0/0 to: 0.0.0.0/0 port gt 1023
command: bind
log: connect disconnect
}
pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
command: connect udpassociate
log: connect disconnect
}
pass {
from: 0.0.0.0/0 to: 0.0.0.0/0
command: bindreply udpreply
log: connect error
}
block {
from: 0.0.0.0/0 to: 0.0.0.0/0
log: connect error
}
END
sed -i "/exit 0/idanted -f /etc/dnate.conf &" /etc/rc.local >> /etc/rc.local
}

function install_wordpress_cn {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
    mkdir /tmp/wordpress.$$
    wget -O - http://cn.wordpress.org/wordpress-3.3.1-zh_CN.tar.gz | \
        tar zxf - -C /tmp/wordpress.$$
    mv /tmp/wordpress.$$/wordpress "/var/www/$1"
    rm -rf /tmp/wordpress.$$
    chown -R www-data "/var/www/$1"
	chmod -R 755 "/var/www/$1"

	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_mysql.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php



    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`
    cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
    sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
        "/var/www/$1/wp-config.php"
	sed -i "31a define(\'WP_CACHE\', true);"  "/var/www/$1/wp-config.php"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql

   

cat >> "/root/$1.mysql.txt" <<END
[wordpress_myqsl]
dbname = $dbname
username = $userid
password = $passwd
END
	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to 06-01@163.com!"
		ServerAdmin="06-01@163.com"
	else
	echo "==========================="
	echo Server Administrator Email="$ServerAdmin"
	echo "==========================="
	fi
	cat >/etc/apache2/conf.d/$1.conf<<eof
<VirtualHost *:80>
ServerAdmin $ServerAdmin
php_admin_value open_basedir "/var/www/$1:/tmp/:/var/tmp/:/proc/"
DocumentRoot /var/www/$1
ServerName $1
ServerAlias www.$1
#ErrorLog /var/log/apache2/$1_error.log
#CustomLog /var/log/apache2/$1_access.log combined
</VirtualHost>
eof
/etc/init.d/apache2 restart
}


function print_info {
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

function print_warn {
    echo -n -e '\e[1;33m'
    echo -n $1
    echo -e '\e[0m'
}

function check_version {
	cat /etc/issue | grep "Linux 5"

if [ $? -ne 0 ]; then
    cat > /etc/init.d/vzquota  << EndFunc
#!/bin/sh
### BEGIN INIT INFO
# Provides:                 vzquota
# Required-Start:
# Required-Stop:
# Should-Start:             $local_fs $syslog
# Should-Stop:              $local_fs $syslog
# Default-Start:            0 1 2 3 4 5 6
# Default-Stop:
# Short-Description:        Fixed(?) vzquota init script
### END INIT INFO
EndFunc
fi
}


function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    check_remove /sbin/portmap portmap

    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    #check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        /etc/init.d/sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function update_cn {
    #  deb http://ftp.de.debian.org/debian wheezy main
    #  deb http://ftp.de.debian.org/debian squeeze main
cp	/etc/apt/sources.list /etc/apt/sources.list.backup
cat > /etc/apt/sources.list <<END
deb http://mirrors.163.com/debian squeeze main non-free contrib
deb http://mirrors.163.com/debian squeeze-proposed-updates main contrib non-free
deb http://mirrors.163.com/debian-security squeeze/updates main contrib non-free

deb-src http://mirrors.163.com/debian squeeze main non-free contrib
deb-src http://mirrors.163.com/debian squeeze-proposed-updates main contrib non-free
deb-src http://mirrors.163.com/debian-security squeeze/updates main contrib non-free
END
    apt-get -q -y update
		apt-get -y install libc6 perl libdb2 debconf
		apt-get -y install apt apt-utils dselect dpkg
}

function update_us {
cp	/etc/apt/sources.list /etc/apt/sources.list.backup
cat > /etc/apt/sources.list <<END
# sources.list generated by apt-spy v3.1
#
# Generated using:
#
# apt-spy \
#       -d stable \
#       -a North-America
#
#deb ftp://ftp.mx.debian.org/debian/ stable main #contrib non-free
#deb-src ftp://ftp.mx.debian.org/debian/ stable main #contrib non-free
#deb http://security.debian.org/ stable/updates main
deb ftp://debian.mirror.iweb.ca/debian/ stable main #contrib non-free
deb-src ftp://debian.mirror.iweb.ca/debian/ stable main #contrib non-free
deb http://security.debian.org/ stable/updates main
END
    apt-get -q -y update
		apt-get -y install libc6 perl libdb2 debconf
		apt-get -y install apt apt-utils dselect dpkg
    #~ apt-get -q -y upgrade
}

function safe_php {
	sed -i s/'disable_functions ='/'disable_functions = system,exec,passthru,escapeshellcmd,pcntl_exec,shell_exec,set_time_limit,'/g /etc/php5/apache2/php.ini
	sed -i s/'memory_limit = 128M'/'memory_limit = 32M'/g /etc/php5/apache2/php.ini
	invoke-rc.d/apache2 restart
}


function install_vsftpd {
	if [ $(id -u) != "0" ]; then
		echo "Error: You must be root to run this script, please use root to install lnmp"
		exit 1
	fi

	apt-get -q -y --force-yes install vsftpd

	sed -i s/'anonymous_enable=YES'/'#anonymous_enable=YES'/g /etc/vsftpd.conf

	cat >>/etc/vsftpd.conf<<EOF
local_enable=YES
write_enable=YES
#ascii_upload_enable=YES
#ascii_download_enable=YES
local_umask=022
pam_service_name=vsftpd
#userlist_enable=YES
#tcp_wrappers=YES
#user_config_dir=/etc/vsftpd/vconf
#guest_enable=YES
#guest_username=www
#virtual_use_local_privs=YES
pasv_enable=YES
pasv_max_port=30100
pasv_min_port=30000
chroot_local_user=YES
ftp_username=www-data
pasv_promiscuous=YES
EOF

	cat >>/etc/shells<<EOF
/sbin/nologin
EOF

echo "Restarting vsftpd......"
/etc/init.d/vsftpd restart
clear
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
exim4)
    install_exim4
	;;
mysql)
    install_mysql
	;;

php)
    install_php
	;;
safephp)
	safe_php
	;;
apache)
    install_apache
	;;
vsftpd)
	install_vsftpd
	;;
systemus)
    check_version
    remove_unneeded
    update_us
    install_dash
    install_syslogd
    install_dropbear
    ;;
systemcn)
    check_version
    remove_unneeded
    update_cn
    install_dash
    install_syslogd
    install_dropbear
    ;;
typecho)
    install_typecho $2
    ;;
dhost)
    install_dhost $2
    ;;

status)
    install_status $2
    ;;
snmpd)
    install_snmpd
    ;;
wordpress)
    install_wordpress_cn $2
    ;;
us)
    check_version
    remove_unneeded
    update_us
    install_dash
    install_syslogd
    install_dropbear
    #install_exim4
    install_mysql
    install_nginx
    install_php
    safe_php
    install_vsftpd
    install_apache
    ;;
cn)
		check_version
		remove_unneeded
		update_cn
    install_dash
    install_syslogd
    install_dropbear
    install_exim4
    install_mysql
    install_nginx
    install_php
    safe_php
	install_vsftpd
		install_apache
		;;

eaccelerator)
    install_eaccelerator
    ;;
sshport)
cat > /etc/xinetd.d/dropbear <<END
service dropbear
{
socket_type = stream
only_from = 0.0.0.0
wait = no
user = root
protocol = tcp
server = /usr/sbin/dropbear
server_args = -i
disable = no
port = $2
type = unlisted
}
END
echo "Please reboot.."
		;;
addapache)
cat > /etc/apache2/apache2.conf <<EXNDDQW
LockFile \${APACHE_LOCK_DIR}/accept.lock
PidFile \${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15
<IfModule mpm_prefork_module>
    StartServers          $2
    MinSpareServers       2
    MaxSpareServers       3
    MaxClients            $3
    MaxRequestsPerChild   10000
</IfModule>
User \${APACHE_RUN_USER}
Group \${APACHE_RUN_GROUP}
AccessFileName .htaccess
DefaultType text/plain
HostnameLookups Off
ErrorLog \${APACHE_LOG_DIR}/error.log
LogLevel warn
Include mods-enabled/*.load
Include mods-enabled/*.conf
Include httpd.conf
Include ports.conf
LogFormat "%v:%p %h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" vhost_combined
LogFormat "%h %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" combined
LogFormat "%h %l %u %t \"%r\" %>s %O" common
LogFormat "%{Referer}i -> %U" referer
LogFormat "%{User-agent}i" agent
Include conf.d/
Include sites-enabled/
EXNDDQW
/etc/init.d/apache2 restart
;;
ssh)
    cat >> /etc/shells <<END
/sbin/nologin
END
useradd $2 -s /sbin/nologin
echo $2:$3 | chpasswd
    ;;
dnate)
    install_dnate $2 $3
	;;
uptime)
	install_uptime
	;;
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in systemcn systemus uptime exim4 mysql php status snmpd vsftpd safephp wordpress typecho ssh  cn us dhost eaccelerator dnate apache addapache sshport phpmyadmin
    do
        echo '  -' $option
    done
    ;;
esac
