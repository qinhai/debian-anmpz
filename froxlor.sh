#!/bin/bash
#Froxlor for Debian 6.0 X86

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

function install_mysql {
    # Install the MySQL packages
    check_install mysqld mysql-server
    check_install mysql mysql-client

    # all the related files.
    invoke-rc.d mysql stop
    rm -f /var/lib/mysql/ib*
    cat > /etc/mysql/conf.d/actgod.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_size = 0
skip-innodb
skip-external-locking
loose-skip-innodb
default-storage-engine=MyISAM 
END
    invoke-rc.d mysql start

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


# Install Nginx+PHP
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
    cat > /etc/nginx/conf.d/actgod.conf <<END
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
	#add by osiris change shn
	cat >> /etc/profile <<END
ulimit -SHn 65535
END
}

function install_php {
    check_install php-cgi php5-cgi php5-cli php5-mysql php5-gd php5-curl
    cat > /etc/init.d/php-cgi <<END
#!/bin/bash
### BEGIN INIT INFO
# Provides:          php-cgi
# Required-Start:    networking
# Required-Stop:     networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the PHP FastCGI processes web server.
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin
NAME="php-cgi"
DESC="php-cgi"
PIDFILE="/var/run/www/php.pid"
FCGIPROGRAM="/usr/bin/php-cgi"
FCGISOCKET="/var/run/www/php.sock"
FCGIUSER="www-data"
FCGIGROUP="www-data"

if [ -e /etc/default/php-cgi ]
then
    source /etc/default/php-cgi
fi

[ -z "\$PHP_FCGI_CHILDREN" ] && PHP_FCGI_CHILDREN=2
[ -z "\$PHP_FCGI_MAX_REQUESTS" ] && PHP_FCGI_MAX_REQUESTS=5000

ALLOWED_ENV="PATH USER PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS FCGI_WEB_SERVER_ADDRS"

set -e

. /lib/lsb/init-functions

case "\$1" in
start)
    unset E
    for i in \${ALLOWED_ENV}; do
        E="\${E} \${i}=\${!i}"
    done
    log_daemon_msg "Starting \$DESC" \$NAME
    env - \${E} start-stop-daemon --start -x \$FCGIPROGRAM -p \$PIDFILE \\
        -c \$FCGIUSER:\$FCGIGROUP -b -m -- -b \$FCGISOCKET
    log_end_msg 0
    ;;
stop)
    log_daemon_msg "Stopping \$DESC" \$NAME
    if start-stop-daemon --quiet --stop --oknodo --retry 30 \\
        --pidfile \$PIDFILE --exec \$FCGIPROGRAM
    then
        rm -f \$PIDFILE
        log_end_msg 0
    else
        log_end_msg 1
    fi
    ;;
restart|force-reload)
    \$0 stop
    sleep 1
    \$0 start
    ;;
*)
    echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
    exit 1
    ;;
esac
exit 0
END
    chmod 755 /etc/init.d/php-cgi
    mkdir -p /var/run/www
    chown www-data:www-data /var/run/www

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php$ {
    include /etc/nginx/fastcgi_params;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    fastcgi_pass unix:/var/run/www/php.sock;
}
END
    update-rc.d php-cgi defaults
    invoke-rc.d php-cgi start
  }

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

function install_apache {
	mkdir -p /var/www/
	mkdir -p /var/www/logs/
	mkdir -p /var/customers/tmp
	chmod 1777 /var/customers/tmp
	
	apt-get -q -y --force-yes install php5-cli php5-mysql php5-gd php5-curl
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
echo "alias auth_basic authn_file authz_default authz_groupfile authz_host authz_user autoindex cgi env negotiation status userdir" | a2dismod

rm /etc/apache2/sites-enabled/000-default
/etc/init.d/apache2 restart
}

function install_pureftpd {
	apt-get install pure-ftpd-common pure-ftpd-mysql
	cat > /etc/pure-ftpd/db/mysql.conf <<END
MYSQLServer	localhost
MYSQLUser       froxlor
MYSQLPassword   Osiris1+3=/*
MYSQLDatabase   froxlor
MYSQLCrypt      any

MYSQLGetPW      SELECT password FROM ftp_users WHERE username="\L" AND login_enabled="y"
MYSQLGetUID     SELECT uid FROM ftp_users WHERE username="\L" AND login_enabled="y"
MYSQLGetGID     SELECT gid FROM ftp_users WHERE username="\L" AND login_enabled="y"
MYSQLGetDir     SELECT homedir FROM ftp_users WHERE username="\L" AND login_enabled="y"
MySQLGetQTASZ 	SELECT panel_customers.diskspace/1024 AS QuotaSize FROM panel_customers, ftp_users WHERE username = "\L" AND panel_customers.loginname = SUBSTRING_INDEX('\L', 'ftp', 1)
END
	cat > /etc/pure-ftpd/conf/MaxIdleTime <<END
15
END
	cat > /etc/pure-ftpd/conf/ChrootEveryone <<END
yes
END
	cat > /etc/pure-ftpd/conf/PAMAuthentication <<END
no
END
	cat > /etc/pure-ftpd/conf/CustomerProof <<END
1
END
	cat > /etc/pure-ftpd/conf/Bind <<END
21
END
	chmod 0640 /etc/pure-ftpd/db/mysql.conf
	/etc/init.d/pure-ftpd-mysql restart
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


function install_froxlor_nginx {

    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    wget -P "/var/www/" http://files.froxlor.org/releases/froxlor-latest.tar.gz
    tar axvf /var/www/froxlor-latest.tar.gz -C /var/www/
	chown -R www-data:www-data "/var/www/froxlor"
	chmod -R 775 "/var/www/froxlor"
	
	mkdir -P /var/customers/webs
	mkdir -P /var/customers/logs
	mkdir -p /var/customers/tmp
	chmod 755 /var/customers/*
	chmod 1777 /var/customers/tmp

	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/osiris_mysql.php
	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/p.php

	rm /var/www/froxlor/scripts/jobs/cron_tasks.php
	wget -P "/var/www/froxlor/scripts/jobs" http://debian-anmpz.googlecode.com/svn/trunk/cron_tasks.php


# Setting up Nginx mapping
if [ -f /etc/init.d/nginx ]
then
    cat > "/etc/nginx/conf.d/froxlor.conf" <<END
server {

    listen 80 default;
    server_name _;    

    location / {
        root /var/www/froxlor;
	include /etc/nginx/fastcgi_php;
        index  index.php index.html index.htm;
	if (!-e \$request_filename) {
            rewrite ^(.*)$  /index.php last;
        }
    }
}
END

cat >> "/var/spool/cron/crontabs/root" <<END
5/* * * * * php /var/www/froxlor/scripts/froxlor_master_cronjob.php --force
END


    /etc/init.d/nginx restart
    /etc/init.d/cron restart
fi
}

function install_froxlor_apache {

    check_install wget wget
	if [ ! -d /var/www ];
        then
        mkdir /var/www
	fi
    wget -P "/var/www/" http://files.froxlor.org/releases/froxlor-latest.tar.gz
    tar axvf /var/www/froxlor-latest.tar.gz -C /var/www/
	chown -R www-data:www-data "/var/www/froxlor"
	chmod -R 775 "/var/www/froxlor"

	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/tz.php
	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/osiris_mysql.php
	wget -P "/var/www/froxlor" http://debian-anmpz.googlecode.com/files/p.php

if [ -f /etc/init.d/apache2 ]
then
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
	cat >/etc/apache2/conf.d/ssl.conf<<eof
<VirtualHost *:443>
ServerAdmin $ServerAdmin
php_admin_value open_basedir "/var/www/froxlor:/tmp/:/var/tmp/:/proc/"
DocumentRoot /var/www/froxlor
ServerName *
ServerAlias www.*
ErrorLog /var/log/apache2/ssl_error.log
CustomLog /var/log/apache2/ssl_access.log combined
</VirtualHost>
eof
/etc/init.d/apache2 restart
fi
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


function update {
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
#deb http://packages.dotdeb.org squeeze php5-fpm
#deb-src http://packages.dotdeb.org squeeze php5-fpm
END
    apt-get -q -y update
	apt-get -y install libc6 perl libdb2 debconf
	apt-get -y install apt apt-utils dselect dpkg
    #~ apt-get -q -y upgrade
}

###############change 19:16 2012/5/20 by osiris add proftpd  ###################
function install_proftpd {
apt-get -q -y --force-yes install proftpd-basic proftpd-mod-mysql

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

    dbname= proftpd
    userid=proftpd
    passwd=`get_password "$userid@mysql"`
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql
	cat >> "/root/proftpd.mysql.txt" <<END
[proftpd_myqsl]
dbname = $dbname
username = $userid
password = $passwd
END
	cp /etc/proftpd/sql.conf /etc/proftpd/sql.conf.old
	cat > /etc/proftpd/sql.conf <<END
<IfModule mod_sql.c>
SQLBackend     mysql
SQLEngine on
SQLAuthenticate on
SQLAuthTypes Crypt Plaintext
SQLConnectInfo proftpd@localhost $userid $passwd
SQLUserInfo users userid passwd uid gid homedir shell
SQLGroupInfo groups groupname gid members
RequireValidShell off
SQLMinUserUID 999
SQLDefaultUID 1000
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
LoadModule mod_sql_mysql.c
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


/etc/init.d/proftpd  restart
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
	listen  80;
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
nginx)
    install_nginx
	;;
php)
    install_php
	;;
addphp)
    sed -i s/PHP_FCGI_CHILDREN=[0-9]/PHP_FCGI_CHILDREN=${2}/g /etc/init.d/php-cgi
	invoke-rc.d php-cgi restart
    ;;
system)
	check_version
    remove_unneeded
	update
    install_dash
    install_syslogd
    install_dropbear
    ;;
froxlor)
    install_froxlor_nginx
    ;;
nmp)
	check_version 
	remove_unneeded
	update
    install_dash
    #install_syslogd
    #install_dropbear
    install_exim4
    install_mysql	
    install_nginx
    install_php
    install_froxlor_nginx
		;;
amp)
	check_version 
	remove_unneeded
	update
    install_dash
    install_syslogd
    install_dropbear
    install_exim4
    install_mysql	
    install_apache
    install_froxlor_apache
		;;	
eaccelerator)
    install_eaccelerator
    ;;
addnginx)
    sed -i s/'^worker_processes [0-9];'/'worker_processes iGodactgod;'/g /etc/nginx/nginx.conf
		sed -i s/iGodactgod/$2/g /etc/nginx/nginx.conf
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

###start osiris ###
proftpd)
    install_proftpd $2
	;;

pureftpd)
    install_pureftpd
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
###end osiris ###
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in phost proftpd vsftpd status snmpd dnate safephp change_id nmp exim4 mysql nginx php wordpress typecho ssh addnginx addphp cn us dhost fhost shost vhost phost httpproxy eaccelerator sshport phpmyadmin
    do
        echo '  -' $option
    done
    ;;
esac
