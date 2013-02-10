#!/bin/bash
#CDN for 123systems.net Debian 6.0 X86

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
cat > /etc/nginx/conf.d/cdn.conf <<EXND
    server {
        listen       80;
	server_name  *;
	access_log /var/www/cdn/access.log;
	error_log /var/www/cdn/error.log;

        location / {
	    proxy_pass   http://$1;
	    include proxy.conf;
	}
    }
EXND
	#add by osiris change shn
	cat >> /etc/profile <<END
ulimit -SHn 65535
END
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
END
    apt-get -q -y update
	apt-get -y install libc6 perl libdb2 debconf
	apt-get -y install apt apt-utils dselect dpkg
    #~ apt-get -q -y upgrade
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


########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
nginx)
    install_nginx $2
	;;
system)
	check_version
    remove_unneeded
	update
    install_dash
    install_syslogd
    install_dropbear
    ;;

cdn)
	check_version 
	remove_unneeded
	update
    install_dash
    install_syslogd
    install_dropbear
    install_nginx $2
		;;
addnginx)
    sed -i s/'^worker_processes [0-9];'/'worker_processes iGodactgod;'/g /etc/nginx/nginx.conf
		sed -i s/iGodactgod/$2/g /etc/nginx/nginx.conf
		invoke-rc.d nginx restart
		;;
status)
    install_status $2
    ;;
snmpd)
    install_snmpd
    ;;
###end osiris ###
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in status snmpd addnginx cdn nginx system
    do
        echo '  -' $option
    done
    ;;
esac
