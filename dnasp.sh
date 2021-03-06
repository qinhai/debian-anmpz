#!/bin/bash
#NAP for 123systems.net Debian 6.0 X86

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
    invoke-rc.d ssh stop

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

    invoke-rc.d xinetd restart
}

function install_exim4 {
    check_install mail exim4
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        invoke-rc.d exim4 restart
    fi
}



function install_nginx {
    check_install nginx nginx
    
    # Need to increase the bucket size for Debian 5.
	if [ ! -d /etc/nginx ];
        then
        mkdir /etc/nginx
	fi
	if [ ! -d /etc/nginx/conf.d ];
        then
        mkdir /etc/nginx/conf.d
	fi
    cat > /etc/nginx/conf.d/osiris.conf <<END
client_max_body_size 20m;
server_names_hash_bucket_size 64;
END
    sed -i s/'^worker_processes [0-9];'/'worker_processes 1;'/g /etc/nginx/nginx.conf
	invoke-rc.d nginx restart
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
	cat > /etc/nginx/proxy.conf <<EXND
proxy_connect_timeout 30s;
proxy_send_timeout   90;
proxy_read_timeout   90;
proxy_buffer_size    32k;
proxy_buffers     4 32k;
proxy_busy_buffers_size 64k;
proxy_redirect     off;
proxy_hide_header  Vary;
proxy_set_header   Accept-Encoding '';
proxy_set_header   Host   \$host;
proxy_set_header   Referer \$http_referer;
proxy_set_header   Cookie \$http_cookie;
proxy_set_header   X-Real-IP  \$remote_addr;
proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
EXND
}

function install_php {
    apt-get -q -y --force-yes install php5-cli php5-sqlite php5-gd php5-curl sqlite3
  }
	
function install_apache {
apt-get -q -y --force-yes install apache2 libapache2-mod-php5 libapache2-mod-rpaf
	sed -i s/'NameVirtualHost \*:80'/'NameVirtualHost \*:168'/g /etc/apache2/ports.conf 
	sed -i s/'Listen 80'/'Listen 127.0.0.1:168'/g /etc/apache2/ports.conf 
	cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.old
	cat > /etc/apache2/apache2.conf <<EXNDDQW
LockFile \${APACHE_LOCK_DIR}/accept.lock
PidFile \${APACHE_PID_FILE}
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 15
<IfModule mpm_prefork_module>
    StartServers          1
    MinSpareServers       2
    MaxSpareServers       2
    MaxClients            3
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

echo "rewrite headers expires authz_host" | a2enmod
echo "alias auth_basic authn_file authz_default authz_groupfile authz_user autoindex cgi env negotiation status" | a2dismod
rm /etc/apache2/sites-enabled/000-default
/etc/init.d/apache2 restart
/etc/init.d/nginx restart

}
###############change 19:16 2012/5/20 by osiris add proftpd  ###################
function install_proftpd {
#################### site a website to manage the FTP ###############
    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` dhost <hostname>"
    fi
	mkdir "/var/www/$1"
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	mv tz.php index.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_sqlite.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/ftpd.db
	wget -P "/var/www/$1" http://www.adminer.org/latest.php

 	chown -R www-data:www-data "/var/www/$1"
	chmod -R 775 "/var/www/$1"

# Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
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


    invoke-rc.d nginx reload
	
	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to webmaster@example.com!"
		ServerAdmin="webmaster@example.com"
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
ErrorLog /var/log/apache2/$1_error.log
CustomLog /var/log/apache2/$1_access.log combined
</VirtualHost>
eof
/etc/init.d/apache2 restart	

#################### site a website to manage the FTP ###############


apt-get -q -y --force-yes install proftpd-basic proftpd-mod-sqlite

	#The index config files.
	cp /etc/proftpd/proftpd.conf /etc/proftpd/proftpd.conf.old
	cat > /etc/proftpd/proftpd.conf <<EXNDDQW
Include /etc/proftpd/modules.conf
UseIPv6                         off
IdentLookups                    off
ServerName                      "Debian"
ServerType                      standalone
DeferWelcome                    off
MultilineRFC2228                on
DefaultServer                   on
ShowSymlinks                    on
TimeoutNoTransfer               600
TimeoutStalled                  600
TimeoutIdle                     1200
DisplayLogin                    welcome.msg
DisplayChdir                    .message true
ListOptions                     "-l"
DenyFilter                      \*.*/
DefaultRoot                    ~
Port                            21
<IfModule mod_dynmasq.c>
</IfModule>
MaxInstances                    30
User                            \${APACHE_RUN_USER}
Group                           \${APACHE_RUN_GROUP}
Umask                           022  022
AllowOverwrite                  on
TransferLog /var/log/proftpd/xferlog
SystemLog   /var/log/proftpd/proftpd.log
<IfModule mod_quotatab.c>
QuotaEngine off
</IfModule>
<IfModule mod_ratio.c>
Ratios off
</IfModule>
<IfModule mod_delay.c>
DelayEngine on
</IfModule>
<IfModule mod_ctrls.c>
ControlsEngine        off
ControlsMaxClients    2
ControlsLog           /var/log/proftpd/controls.log
ControlsInterval      5
ControlsSocket        /var/run/proftpd/proftpd.sock
</IfModule>
<IfModule mod_ctrls_admin.c>
AdminControlsEngine off
</IfModule>
Include /etc/proftpd/sql.conf
EXNDDQW


	cp /etc/proftpd/sql.conf /etc/proftpd/sql.conf.old
	cat > /etc/proftpd/sql.conf <<END
<IfModule mod_sql.c>
SQLBackend sqlite3
SQLConnectInfo /var/www/$1/ftpd.db
SQLAuthTypes Plaintext
SQLUserInfo users user_name user_passwd uid gid home_dir NULL
RequireValidShell off
SQLGroupInfo groups group_name gid members
SQLAuthenticate users
SQLMinUserUID 30
SQLDefaultUID 33
SQLDefaultGID 33
</IfModule>
END

	cp /etc/proftpd/modules.conf /etc/proftpd/modules.conf.old
	cat > /etc/proftpd/modules.conf <<END
ModulePath /usr/lib/proftpd
ModuleControlsACLs insmod,rmmod allow user root
ModuleControlsACLs lsmod allow user *
LoadModule mod_ctrls_admin.c
LoadModule mod_tls.c
LoadModule mod_sql.c
LoadModule mod_sql_sqlite.c
LoadModule mod_radius.c
LoadModule mod_quotatab.c
LoadModule mod_quotatab_file.c
LoadModule mod_quotatab_radius.c
LoadModule mod_wrap.c
LoadModule mod_rewrite.c
LoadModule mod_load.c
LoadModule mod_ban.c
LoadModule mod_wrap2.c
LoadModule mod_wrap2_file.c
LoadModule mod_dynmasq.c
LoadModule mod_vroot.c
LoadModule mod_exec.c
LoadModule mod_shaper.c
LoadModule mod_ratio.c
LoadModule mod_site_misc.c
LoadModule mod_sftp.c
LoadModule mod_sftp_pam.c
LoadModule mod_facl.c
LoadModule mod_unique_id.c
LoadModule mod_ifsession.c
END


/etc/init.d/pureftpd  restart
}

###############change 19:16 2012/5/20 by osiris add proftpd  ###################


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

# update time

 function install_uptime {
	dpkg-reconfigure tzdata
	check_install ntpdate ntpdate
	ntpdate time-b.nist.gov
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

function install_phost {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    mkdir "/var/www/$1"
	useradd -g www-data -d /var/www/$1 -s /sbin/nologin $1
	chown -R $1:www-data "/var/www/$1"
	chmod -R 775 "/var/www/$1"
	passwd $1
      # Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
    server {
        listen       80;
	server_name  $1 www.$1;
	access_log /var/www/$1/access.log;
	error_log /var/www/$1/error.log;

        location / {
	    proxy_pass   http://$2;
	    include proxy.conf;
	}
    }
END
    /etc/init.d/nginx reload
}

function install_status {
    cat > "/etc/nginx/conf.d/$1.conf" <<END
	server
	{
	listen  80 default;
	server_name  $1;

	location / {
	stub_status on;
	access_log   off;
	}
	}
END
    /etc/init.d/nginx reload
}

function safe_php {
	sed -i s/'disable_functions ='/'disable_functions = system,exec,passthru,escapeshellcmd,pcntl_exec,shell_exec,set_time_limit,'/g /etc/php5/apache2/php.ini
	sed -i s/'memory_limit = 128M'/'memory_limit = 32M'/g /etc/php5/apache2/php.ini
	invoke-rc.d/apache2 restart
}
function change_id {
	chown -R $1:www-data "/var/www/$2"
	chmod -R 775 "/var/www/$2"	
}
##### end by osiris 2:04 2012/5/23####


function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    invoke-rc.d inetutils-syslogd stop

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

    invoke-rc.d inetutils-syslogd start
}

function install_eaccelerator {

apt-get -y --force-yes install build-essential php5-dev bzip2
cd /tmp
wget http://nchc.dl.sourceforge.net/project/eaccelerator/eaccelerator/eAccelerator%200.9.6.1/eaccelerator-0.9.6.1.zip
unzip eaccelerator-0.9.6.1.zip
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

function install_vhost {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

	if [ ! -d /var/www ];
        then
        mkdir /var/www
fi
    mkdir "/var/www/$1"
    chown -R www-data "/var/www/$1"
		chmod -R 755 "/var/www/$1"

      # Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    location / {
        index index.html index.htm;
    }
}
END
    invoke-rc.d nginx reload
	
	cat > "/var/www/$1/index.html" <<END
Hello world!
		----$2
END
    invoke-rc.d nginx reload	
}

function install_dhost {
    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` dhost <hostname>"
    fi
	mkdir "/var/www/$1"
 	chown -R www-data "/var/www/$1"
	chmod -R 775 "/var/www/$1"	
	
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_sqlite.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php


# Setting up Nginx mapping
    cat > "/etc/nginx/conf.d/$1.conf" <<END
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


    invoke-rc.d nginx reload
	
	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to webmaster@example.com!"
		ServerAdmin="webmaster@example.com"
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
	chmod -R 775 "/var/www/$1"
	
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/osiris_sqlite.php
	wget -P "/var/www/$1" http://debian-anmpz.googlecode.com/files/p.php

    # Setting up Nginx mapping

    cat > "/etc/nginx/conf.d/$1.conf" <<END
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
    invoke-rc.d nginx reload
		

	ServerAdmin=""
	read -p "Please input Administrator Email Address:" ServerAdmin
	if [ "$ServerAdmin" == "" ]; then
		echo "Administrator Email Address will set to webmaster@example.com!"
		ServerAdmin="webmaster@example.com"
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
</VirtualHost>
ErrorLog /var/log/apache2/$1_error.log
CustomLog /var/log/apache2/$1_access.log combined
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
    check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function update_stable {

cp	/etc/apt/sources.list /etc/apt/sources.list.backup
cat > /etc/apt/sources.list <<END
deb http://mirror.peer1.net/debian/ squeeze main
deb-src http://mirror.peer1.net/debian/ squeeze main
deb http://mirror.peer1.net/debian/ squeeze-updates main
deb-src http://mirror.peer1.net/debian/ squeeze-updates main
deb http://mirror.peer1.net/debian-security/ squeeze/updates main
deb-src http://mirror.peer1.net/debian-security/ squeeze/updates main
deb http://nginx.org/packages/debian/ squeeze nginx
deb-src http://nginx.org/packages/debian/ squeeze nginx
END
    apt-get -q -y update
	apt-get -y install libc6 perl libdb2 debconf
	apt-get -y install apt apt-utils dselect dpkg
    #~ apt-get -q -y upgrade
}

function update_nginx {
    apt-get -q -y update
	invoke-rc.d nginx stop
	apt-get -q -y remove nginx
	apt-get -q -y --force-yes install nginx
	if [ ! -d /etc/nginx ];
        then
        mkdir /etc/nginx
	fi
	if [ ! -d /etc/nginx/conf.d ];
        then
        mkdir /etc/nginx/conf.d
	fi
    cat > /etc/nginx/conf.d/osiris.conf <<END
client_max_body_size 20m;
server_names_hash_bucket_size 64;
END
    sed -i s/'^worker_processes [0-9];'/'worker_processes 1;'/g /etc/nginx/nginx.conf
	invoke-rc.d nginx restart
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
	cat > /etc/nginx/proxy.conf <<EXND
proxy_connect_timeout 30s;
proxy_send_timeout   90;
proxy_read_timeout   90;
proxy_buffer_size    32k;
proxy_buffers     4 32k;
proxy_busy_buffers_size 64k;
proxy_redirect     off;
proxy_hide_header  Vary;
proxy_set_header   Accept-Encoding '';
proxy_set_header   Host   \$host;
proxy_set_header   Referer \$http_referer;
proxy_set_header   Cookie \$http_cookie;
proxy_set_header   X-Real-IP  \$remote_addr;
proxy_set_header   X-Forwarded-For \$proxy_add_x_forwarded_for;
EXND
invoke-rc.d nginx restart
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
nginx)
    install_nginx
	;;
php)
    install_php
	;;
apache)
    install_apache
	;;
###start osiris ###
proftpd)
    install_proftpd $2
	;;

phost)
    install_phost $2 $3
	;;
uptime)
	install_uptime
	;;
dnate)
	install_dnate $2 $3
	;;
status)
    install_status $2
    ;;
snmpd)
    install_snmpd
    ;;
safephp)
	safe_php
	;;
change_id)
	change_id $2 $3
	;;
###end osiris ###
system)
	check_version
    remove_unneeded
	update_stable
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
vhost)
    install_vhost $2
    ;;
stable)
	check_version 
	remove_unneeded
	update_stable
    install_dash
    install_syslogd
    install_dropbear
    install_exim4	
    install_nginx
    install_php
	install_apache
		;;
updatenginx)
    update_nginx
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
addnginx)
    sed -i s/'^worker_processes [0-9];'/'worker_processes iGodosiris;'/g /etc/nginx/nginx.conf
		sed -i s/iGodosiris/$2/g /etc/nginx/nginx.conf
		invoke-rc.d nginx restart
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

httpproxy)
    cat > /etc/nginx/conf.d/httpproxy.conf <<END
	server {
	listen $2;
	resolver 8.8.8.8;
	location / {
	proxy_pass http://\$http_host\$request_uri;
		}
	}
END
	invoke-rc.d nginx restart
	;;
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in phost proftpd status snmpd dnate safephp change_id system exim4 nginx php typecho ssh addnginx stable dhost vhost httpproxy eaccelerator  apache addapache sshport
    do
        echo '  -' $option
    done
    ;;
esac
