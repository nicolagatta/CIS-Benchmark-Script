#!/bin/bash

echo "1        | Initial Setup"
echo "1.1      | Filesystem Configuration"

echo "1.1.1    | Disable Unused Fiesystem "

COUNT=0
for i in cramfs freevxfs jffs2 hfs hfsplus udf msdos
do
        modprobe  -n -v $i 2>/dev/null | grep "install /bin/true" >/dev/null 2>&1 && RES="OK" || RES="NOK"
        COUNT=$(($COUNT+1))
        echo "1.1.1.$COUNT  | Ensure Mounting of $i is Disable = $RES"

done

echo "2        | Services"
echo "2.1      | Inetd Services"

dpkg -s xinetd 2>/dev/null && RES="NOK" || RES="OK"
echo "2.1.1    | Ensure xinetd is not installed  = $RES"

dpkg -s openbsd-inetd 2>/dev/null && RES="NOK" || RES="OK"
echo "2.1.2    | Ensure openbsd-inetd is not installed = $RES"

echo "2.2      | Special Purpose Services"
echo "2.2.1    | Time Synchronization"

systemctl is-enabled systemd-timesyncd | grep '^enabled$'  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "2.2.1.1  | Time Synchronization is in use = $RES"

timedatectl status | grep "NTP service: active" >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "2.2.1.2  | Ensure systemd-timesyncd is configures = $RES"

dpkg -l | grep avahi >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.2    | Ensure X Window System is not installed = $RES"

dpkg -l | grep avahi >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.3    | Ensure Avahi Server is not Installed = $RES"

dpkg -l | grep -i cups >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.4    | Ensure CUPS is not installed = $RES"

dpkg -l | grep dhcp | grep server >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.5    | Ensure DHCP Server is not installed = $RES"

dpkg -l | grep slapd >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.6    | Ensure LDAP Server is not installed = $RES"

dpkg -l | grep nfs-server >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.7    | Ensure NFS Server is not installed = $RES"

dpkg -s bind9 >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.8    | Ensure DNS Server is not installed = $RES"

dpkg -l | grep ftpd >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.9    | Ensure FTP Server is not installed = $RES"

dpkg -l | grep apache2 >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.10   | Ensure HTTP Server is not installed = $RES"

dpkg -l | grep -iE "(imap|pop3)" >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.11   | Ensure IMAP and POP Server is not installed = $RES"

dpkg -l | grep samba >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.12   | Ensure Samba Server is not installed = $RES"

dpkg -l | grep squid >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.13   | Ensure HTTP Proxy Server is not installed = $RES"

dpkg -l | grep snmpd >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.14   | Ensure SNMP Server is not installed = $RES"

ss -lntu | grep -E ':25\s' | grep -E -v '127.0.0.1'  >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.15   | Ensure Mail Server is configure local only = $RES"

dpkg -l | grep rsync >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.16   | Ensure rsync Server is not installed = $RES"

dpkg -l | grep " nis " >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.2.17   | Ensure NIS Server is not installed = $RES"


echo "2.3      | Service Clients"

dpkg -l | grep " nis " >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.1    | Ensure NIS Client is not installed = $RES"


dpkg -l | grep " rsh" >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.2    | Ensure RSH Client is not installed = $RES"

dpkg -l | grep "ii  talk" >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.3    | Ensure Talk Client is not installed = $RES"

dpkg -l | grep " telnet " >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.4    | Ensure Telnet Client is not installed = $RES"

dpkg -l | grep " ldap-utils" >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.5    | Ensure LDAP Client is not installed = $RES"

dpkg -l | grep " rcpbind" >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "2.3.6    | Ensure RPC Client is not installed = $RES"

echo "2.4      | Ensure nonessential services are removed or masked (Manual)"

echo "3        | Network Confguration"
echo "3.1      | Disable unused network protocols and devices"

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "ipv6.disable=1"  >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "3.1.1    | Disable IPv6 = $RES"

echo "3.2      | Network Parameters"

sysctl net.ipv4.conf.default.send_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.2.1.1  | Ensure packet redirect sending is disabled (ALL)= $RES"

sysctl net.ipv4.conf.all.send_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.2.1.1  | Ensure packet redirect sending is disabled (DEFAULT)= $RES"

sysctl net.ipv4.ip_forward | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.2.2    | Ensure IP Forwarding is disabled = $RES"

echo "3.3      | Network Parameters (Host and Router"

sysctl net.ipv4.conf.all.accept_source_route | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.1    | Ensure Source routed packets are not accepted (ALL)= $RES"

sysctl net.ipv4.conf.default.accept_source_route | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.1    | Ensure Source routed packets are not accepted (DEFAULT)= $RES"

sysctl net.ipv4.conf.all.accept_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.2    | Ensure ICMP Redirects are not accepted (ALL)= $RES"

sysctl net.ipv4.conf.default.accept_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.2    | Ensure ICMP Redirects are not accepted (DEFAULT)= $RES"


sysctl net.ipv4.conf.all.secure_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.3    | Ensure Secure ICMP Redirects are not accepted (ALL)= $RES"

sysctl net.ipv4.conf.default.secure_redirects | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.3    | Ensure Secure ICMP Redirects are not accepted (DEFAULT)= $RES"

sysctl net.ipv4.conf.all.log_martians | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.4    | Ensure Suspicious Packets are logged (ALL)= $RES"

sysctl net.ipv4.conf.default.log_martians | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.4    | Ensure Suspicious Packets are logged (DEFAULT)= $RES"

sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.5    | Ensure broadcast ICMP requests are ignored  = $RES"

sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.6    | Ensure bogus ICMP resposnes are ignored  = $RES"

sysctl net.ipv4.conf.all.rp_filter | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.7    | Ensure Reverse Path Filtering is enabled (ALL) = $RES"

sysctl net.ipv4.conf.default.rp_filter | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.7    | Ensure Reverse Path Filtering is enabled (DEFAULT) = $RES"

sysctl net.ipv4.tcp_syncookies | grep "= 1"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.8    | Ensure TCP SYN Cookies is enabled = $RES"

sysctl net.ipv6.conf.all.accept_ra  | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.9    | Ensure IPv6 router advertisements are not accepted (ALL)= $RES"

sysctl net.ipv6.conf.default.accept_ra  | grep "= 0"  >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.3.9    | Ensure IPv6 router advertisements are not accepted (DEFAULT)= $RES"

echo "3.4      | Uncommon Network Protocols"

COUNT=0
for i in dccp sctp rds tipc
do
        modprobe  -n -v $i 2>/dev/null | grep "install /bin/true" >/dev/null 2>&1 && RES="OK" || RES="NOK"
        COUNT=$(($COUNT+1))
        echo "3.4.$COUNT    | Ensure $i is Disable = $RES"

done

echo "3.5      | Firewall Configuration"
echo "3.5.1    | Configure UFW: Disabled by Default"
echo "3.5.2    | Configure nftables: Disabled by Default"
echo "3.5.3    | Configure iptables"
echo "3.5.3.1  | Configure iptables Software"

dpkg -s iptables | grep "ok installed" >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.5.3.1.1| Ensure iptables packages are installed = $RES"

dpkg -s nftables >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "3.5.3.1.2| Ensure nftables is not installed = $RES"

dpkg -s ufw >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "3.5.3.1.3| Ensure UFW is not installed = $RES"

iptables-save |grep ".*" >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "3.5.3.2  | Ensure IPv4 iptables is configured = $RES"

iptables -L | grep -E "(INPUT|FORWARD|OUTPUT)"  | grep "policy DROP" | wc -l  | grep "^3$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "3.5.3.2.1| Ensure default deny firewall policy = $RES"

iptables -L INPUT -n -v | grep " lo " | grep ACCEPT >/dev/null 2>&1 && RES1="OK" || RES1="NOK"
iptables -L OUTPUT -n -v | grep " lo " | grep ACCEPT > /dev/null 2>&1 && RES2="OK" || RES2="NOK"

echo "3.5.3.2.2| Ensure loopback traffic is permitted: INPUT = $RES1, OUTPUT = $RES2"

iptables -L INPUT -n -v | grep "state ESTABLISHED" | grep ACCEPT | wc -l  | grep "^3$" >/dev/null 2>&1  && RES1="OK" || RES1="NOK"
iptables -L OUTPUT -n -v | grep "state NEW,ESTABLISHED" | grep ACCEPT | wc -l  | grep "^3$" >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "3.5.3.2.3| Ensure outbound and established connections are permitted: INPUT = $RES1, OUTPUT = $RES2"

RES="OK"
for i in $(ss -4tuln | grep LIST | grep -v "127.0.0" | tr -s ' '  | cut -d ' ' -f 5 | cut -d ':' -f 2)
do
        echo "check $i"
        iptables -L INPUT -n -v | grep "dpt:$i" | grep ACCEPT >/dev/null 2>&1  || RES="NOK"
done

echo "3.5.3.2.4| Ensure firewall rules exist for all open ports = $RES"

echo "3.5.3.3  | Ensure IPv6 iptables is configured = Out of Scope"
#Configure IPv6 ip6tables
#Ensure IPv6 default deny firewall policy (Automated)
#Ensure IPv6 loopback traffic is configured (Automated)
#Ensure IPv6 outbound and established connections are configured (Manual)
#Ensure IPv6 firewall rules exist for all open ports (Manual)


echo "4        | Logging and Auditing"
echo "4.1      | Configure System Accounting (auditd)"
echo "4.1.1    | Ensure auditing is enabled"

dpkg -s auditd >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "4.1.1.1  | Ensure auditd is installed (Automated) = $RES"

systemctl is-enabled auditd |grep "enabled" >/dev/null 2>&1 && RES="OK" || RES="NOK"
echo "4.1.1.2  | Ensure auditd service is enabled (Automated) = $RES"

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit=1"  >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "4.1.1.3  | Ensure auditing for processes that start prior to auditd is enabled = $RES"

grep "^\s*linux" /boot/grub/grub.cfg | grep -v "audit_backlog_limit="  >/dev/null 2>&1 && RES="NOK" || RES="OK"
echo "4.1.1.4  | Ensure audit_backlog_limit is sufficient = $RES"

echo "4.1.2    | Configure Data Retention"

#grep max_log_file /etc/audit/auditd.conf
echo "4.1.2.1  | Ensure audit log storage size is configured"

#grep max_log_file_action /etc/audit/auditd.conf
echo "4.1.2.2  | Ensure audit logs are not automatically deleted"

#grep space_left_action /etc/audit/auditd.conf
echo "4.1.2.3  | Ensure system is disabled when audit logs are full"

auditctl -l | grep time-change | wc -l | grep "^5$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.3    | Ensure events that modify date and time information are collected = $RES"

auditctl -l | grep identity | wc -l | grep "^5$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.4    | Ensure events that modify user/group information are collected = $RES"


auditctl -l | grep system-locale | wc -l | grep "^5$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.5    | Ensure events that modify the system's network environment are collected = $RES"


auditctl -l | grep MAC-policy | wc -l | grep "^2$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.6    | Ensure events that modify the system's Mandatory Access Controls are collected = $RES"

auditctl -l | grep logins | grep "var" | grep "log " | wc -l | grep "^3$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.7    | Ensure login and logout eventss are collected = $RES"

auditctl -l | grep "var" | grep "tmp" | wc -l | grep "^3$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.8    | Ensure session initiation information is collected = $RES"

auditctl -l | grep "key=perm_mod" | wc -l | grep "^6$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.9    | Ensure discretionary access control permission modification events are collected = $RES"

auditctl -l | grep "key=access" | wc -l | grep "^4$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.10   | Ensure unsuccessful unauthorized file access attempts are collected = $RES"

auditctl -l | grep "key=privileged" | wc -l  | grep "^28$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.11   | Ensure use of privileged commands is collected = $RES"

auditctl -l | grep "key=mounts" | wc -l  | grep "^2$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.12   | Ensure successful file system mounts are collected = $RES"

auditctl -l | grep "key=delete" | wc -l  | grep "^2$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.13   | Ensure file deletion events by users are collected = $RES"

auditctl -l | grep " scope$" | wc -l  | grep "^2$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.14   | Ensure changes to system administration scope (sudoers) is collected = $RES"

auditctl -l | grep "key=actions" | wc -l  | grep "^2$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.15   | Ensure system administrator command executions (sudo) are collected = $RES"

auditctl -l |grep 'modules$' | wc -l  | grep "^4$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.1.16   | Ensure kernel module loading and unloading is collected = $RES"

echo "4.1.17   | Ensure the audit configuration is immutable (Automated)"

echo "4.2      | Configure Loggin"
echo "4.2.1    | Configure Rsyslog"

dpkg -s rsyslog >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.1.1  | Ensure Rsyslog is installed = $RES"

systemctl is-enabled rsyslog | grep '^enabled$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.1.2  | Ensure Rsyslog is enabled = $RES"

cat  /etc/rsyslog.d/50-default.conf | grep -v -E "^#" | tr -s '\n' |  wc -l | grep "^7$" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.1.3  | Ensure logging is enabled (default 7 lines) = $RES"

grep ^\s*\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf | grep ' 0640$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.1.4  | Ensure rsyslog default file permissions configured = $RES"

grep target  /etc/rsyslog.d/* | grep port | grep protocol >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.1.5  | Ensure rsyslog is configured to send logs to a remote log host = $RES"

echo "4.2.2    | Configure Journald"

grep -e '^ForwardToSyslog=yes' /etc/systemd/journald.conf >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.2.1  | Ensure journald is configured to send logs to rsyslog = $RES"

grep -e '^Compress=yes' /etc/systemd/journald.conf >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.2.2  | Ensure journald is configured to compress large log files = $RES"

grep -e '^Storage=persistent' /etc/systemd/journald.conf >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "4.2.2.3  | Ensure journald is configured to write logfiles to persistent disk = $RES"

echo "4.2.3    | Ensure permissions on all logfiles are configured"
echo "4.3      | Ensure Logrotate is configured"
echo "4.4      | Ensure Logrotate assigns appropriate permissions"

echo "5        | Access, Authentication and Authorization"
echo "5.1      | Configure time based job schedulers"


systemctl is-enabled cron | grep '^enabled$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.1    | Ensure cron daemon is enabled and running = $RES"

stat /etc/crontab  | grep '(0600/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.2    | Ensure permissions on /etc/crontab are configured = $RES"

stat /etc/cron.hourly  | grep '(0700/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.3    | Ensure permissions on /etc/cron.hourly are configured = $RES"

stat /etc/cron.daily  | grep '(0700/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.4    | Ensure permissions on /etc/cron.daily are configured = $RES"

stat /etc/cron.weekly  | grep '(0700/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.5    | Ensure permissions on /etc/cron.weekly are configured = $RES"

stat /etc/cron.monthly  | grep '(0700/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.6    | Ensure permissions on /etc/cron.monthl are configured = $RES"

stat /etc/cron.d  | grep '(0700/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.1.7    | Ensure permissions on /etc/cron.d are configured = $RES"

stat /etc/cron.deny  >/dev/null 2>&1  && RES1="NOK" || RES1="OK"
stat /etc/cron.allow  | grep '(0640/' >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "5.1.8    | Ensure cron is restricted to authorized users = $RES1 - $RES2"

stat /etc/at.deny  >/dev/null 2>&1  && RES1="NOK" || RES1="OK"
stat /etc/at.allow  | grep '(0640/' >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "5.1.9    | Ensure at is restricted to authorized users = $RES1 - $RES2"

echo "5.2      | Configure SSH"

stat /etc/ssh/sshd_config | grep '(0600/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.1    | Ensure permissions on /etc/ssh/sshd_config are configured = $RES"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' | xargs stat | grep '(0600/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.2    | Ensure permissions on SSH private host key files are configured = $RES"

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' | xargs stat | grep '(0644/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.3    | Ensure permissions on SSH public host key files are configured = $RES"

sshd -T | grep "loglevel INFO" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.4    | Ensure SSH LogLevel is appropriate = $RES"

sshd -T | grep "x11forwarding no"  >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.5    | Ensure SSH X11 forwarding is disabled = $RES"

sshd -T | grep "maxauthtries 4" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.6    | Ensure SSH MaxAuthTries is set to 4 = $RES"

sshd -T | grep "ignorerhosts yes" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.7    | Ensure SSH IgnoreRhosts is enabled = $RES"

sshd -T | grep "hostbasedauthentication no" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.8    | Ensure SSH HostbasedAuthentication is disabled = $RES"

sshd -T | grep "permitrootlogin no" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.9    | Ensure SSH root login is disabled = $RES"

sshd -T | grep "permitemptypasswords no" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.10   | Ensure SSH PermitEmptyPasswords is disabled = $RES"

sshd -T | grep "permituserenvironment no" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.11   | Ensure SSH PermitUserEnvironment is disabled = $RES"

sshd -T | grep ciphers | grep cbc >/dev/null 2>&1  && RES="NOK" || RES="OK"
echo "5.2.12   | Ensure only strong Ciphers are used = $RES"

sshd -T | grep -i "MACs" | grep -E "(128|96|64|sha1|md5|ripemd)" >/dev/null 2>&1  && RES="NOK" || RES="OK"
echo "5.2.13   | Ensure only strong MAC algorithms are used = $RES"

sshd -T | grep -i "kexalgorithms" | grep -E "(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)" >/dev/null 2>&1  && RES="NOK" || RES="OK"
echo "5.2.14   | Ensure only strong Key Exchange algorithms are used = $RES"

sshd -T | grep "clientaliveinterval 300" >/dev/null 2>&1  && RES1="OK" || RES1="NOK"
sshd -T | grep "clientalivecountmax 3" >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "5.2.15   | Ensure SSH Idle Timeout Interval is configured = $RES1 - $RES2"

sshd -T | grep "logingracetime 60" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.16   | Ensure SSH LoginGraceTime is set to one minute or less = $RES"

sshd -T | grep allowusers
sshd -T | grep allowgroups
sshd -T | grep denyusers
sshd -T | grep denygroups
echo "5.2.17   | Ensure SSH access is limited = Manual!"

sshd -T | grep "banner /etc/issue.net" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.18   | Ensure SSH warning banner is configured = $RES"

sshd -T | grep -i "usepam yes" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.19   | Ensure SSH PAM is enabled = $RES"

sshd -T | grep -i "allowtcpforwarding no"  >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.20   | Ensure SSH AllowTcpForwarding is disabled = $RES"

sshd -T | grep -i "maxstartups 10:30:100" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.21   | Ensure SSH MaxStartups is configured = $RES"

sshd -T | grep -i "maxsessions 10"  >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.2.22   | Ensure SSH MaxSessions is limited = $RES"


echo "5.3      | Configure PAM"

grep '^minlen = 14' /etc/security/pwquality.conf  >/dev/null 2>&1  && RES1="OK" || RES1="NOK"
grep '^minclass = 3' /etc/security/pwquality.conf  >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
grep "pam_pwquality" /etc/pam.d/common-password | grep "retry=3"  >/dev/null 2>&1  && RES3="OK" || RES3="NOK"
echo "5.3.1    | Ensure password creation requirements are configured= $RES1 - $RES2 - $RES3"

grep "pam_tally2" /etc/pam.d/common-auth | grep "required" | grep "deny=5"  >/dev/null 2>&1  && RES1="OK" || RES1="NOK"
grep -E "pam_(tally2|deny)\.so" /etc/pam.d/common-account | wc -l | grep '^2$'  >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "5.3.2    | Ensure lockout for failed password attempts is configured= $RES1 - $RES"

grep "pam_pwhistory.so" /etc/pam.d/common-password | grep "remember=5" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.3.3    | Ensure password reuse is limited = $RES"

grep "pam_unix.so" /etc/pam.d/common-password | grep "sha512" >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.3.4    | Ensure password hashing algorithm is SHA-512 =$RES"

echo "5.4      | User Accounts and Environment = $RES"
echo "5.4.1    | Set Shadow Password Suite Parameters"

grep "^PASS_MAX_DAYS"  /etc/login.defs  | grep  '[^0-9]365$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.4.1.1  | Ensure password expiration is 365 days or less = $RES "

grep "^PASS_MIN_DAYS"  /etc/login.defs  | grep  '[^0-9]1$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.4.1.2  | Ensure minimum days between password changes is configured = $RES"

grep "^PASS_WARN_AGE"  /etc/login.defs  | grep  '[^0-9]7$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.4.1.3  | Ensure password expiration warning days is 7 or more = $RES"

echo "5.4.1.4  | Ensure inactive password lock is 30 days or less = NA"
echo "5.4.1.5  | Ensure all users last password change date is in the past = NA"

awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"' && $7!="'"$(which nologin)"'" && $7!="/bin/false") {print}' /etc/passwd | wc -l | grep '^0$'>/dev/null 2>&1  && RES1="OK" || RES1="NOK"
awk -F: '($1!="root" && $1!~/^\+/ && $3<'"$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs)"') {print $1}' /etc/passwd | xargs -I '{}' passwd -S '{}' | awk '($2!="L" && $2!="LK") {print $1}' | wc -l | grep '^0$' >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "5.4.2    | Ensure system accounts are secured = $RES1 - $RES2"

grep "^root:" /etc/passwd | cut -f4 -d: | grep '^0$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.4.3    | Ensure default group for the root account is GID 0 = $RES"

grep "^UMASK"  /etc/login.defs  | grep  '[^0-9]027$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "5.4.4    | Ensure default user umask is 027 or more restrictive = $RES"

echo "5.4.5    | ensure default user shell timeout is 900 seconds or less (Automated)"
echo "5.5      | Ensure root login is restricted to system console (Manual)"
echo "5.6      | Ensure access to the su command is restricted (Automated)"
echo "6        | System Maintenance"
echo "6.1      | System File Permissions"
echo "6.1.1    | Audit system file permissions (Manual)"

stat /etc/passwd | grep '(0644/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.2    | Ensure permissions on /etc/passwd are configured = $RES"

stat /etc/gshadow- | grep '(0640/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.3    | Ensure permissions on /etc/gshadow- are configured = $RES"

stat /etc/shadow | grep '(0640/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.4    | Ensure permissions on /etc/shadow are configured = $RES"

stat /etc/group | grep '(0644/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.5    | Ensure permissions on /etc/group are configured = $RES"

stat /etc/passwd- | grep '(0644/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.6    | Ensure permissions on /etc/passwd- are configured = $RES"

stat /etc/shadow- | grep '(0640/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.7    | Ensure permissions on /etc/shadow- are configured = $RES"

stat /etc/group | grep '(0644/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.8    | Ensure permissions on /etc/group are configured = $RES"

stat /etc/gshadow | grep '(0640/' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.9    | Ensure permissions on /etc/gshadow are configured = $RES"

echo "6.1.10   | Ensure no world writable files exist (Manual)"

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser | wc -l | grep '^0$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.11   | Ensure no unowned files or directories exist = $RES"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup  | wc -l | grep '^0$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.12   | Ensure no ungrouped files or directories exist = $RES"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 | wc -l | grep '^16$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.13   | Audit SUID executables = $RES"

df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 | wc -l | grep '^13$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.1.14   | Audit SGID executables = $RES"

echo "6.2      | User and Group Settings"
awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow | wc -l | grep '^0$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.2.1    | Ensure password fields are not empty = $RES"


awk -F: '($3 == 0) { print $1 }' /etc/passwd | grep "^root$"| wc -l | grep '^1$' >/dev/null 2>&1  && RES="OK" || RES="NOK"
echo "6.2.2    | Ensure root is the only UID 0 account = $RES"


RES="OK"
if echo $PATH | grep -q "::" ; then
        RES="NOK"
fi
if echo $PATH | grep -q ":$" ; then
        RES="NOK"
fi
for x in $(echo $PATH | tr ":" " ") ;
do
        if [ -d "$x" ] ; then
                ls -ldH "$x" | awk ' $9 == "." {print "PATH contains current working directory (.)"} $3 != "root" {print $9, "is not owned by root"} substr($1,6,1) != "-" {print $9, "is group writable"} substr($1,9,1) != "-" {print $9, "is world writable"}'
        else
                RES="NOK"
        fi
done

RES="OK"
echo "6.2.3    | Ensure root PATH Integrity = $RES"



grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read -r user dir; do
        if [ ! -d "$dir" ]; then
                RES="NOK"
        fi
done

echo "6.2.4    | Ensure all users home directories exist = $RES"


RES="OK"
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                dirperm=$(ls -ld $dir | cut -f1 -d" ")
                if [ $(echo $dirperm | cut -c6) != "-" ]; then
                        echo "Group Write permission set on the home directory ($dir) of user $user"
                        RES="NOK"
                fi
                if [ $(echo $dirperm | cut -c8) != "-" ]; then
                        echo "Other Read permission set on the home directory ($dir) of user $user"
                        RES="NOK"
                fi
                if [ $(echo $dirperm | cut -c9) != "-" ]; then
                        echo "Other Write permission set on the home directory ($dir) of user $user"
                        RES="NOK"
                fi
                if [ $(echo $dirperm | cut -c10) != "-" ]; then
                        echo "Other Execute permission set on the home directory ($dir) of user $user"
                        RES="NOK"
                fi
        fi
done

echo "6.2.5    | Ensure users home directories permissions are 750 or more restrictive = $RES"

RES="OK"
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                owner=$(stat -L -c "%U" "$dir")
                if [ "$owner" != "$user" ]; then
                        echo "The home directory ($dir) of user $user is owned by $owner."
                        RES="NOK"
                fi
        fi
done

echo "6.2.6    | Ensure users own their home directories = $RES"

RES="OK"
grep -E -v '^(halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                for file in $dir/.[A-Za-z0-9]*; do
                        if [ ! -h "$file" -a -f "$file" ]; then
                                fileperm=$(ls -ld $file | cut -f1 -d" ")
                                if [ $(echo $fileperm | cut -c6) != "-" ]; then
                                        echo "Group Write permission set on file $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c9) != "-" ]; then
                                        echo "Other Write permission set on file $file"
                                        RES="NOK"
                                fi
                        fi
                done
        fi
done

echo "6.2.7    | Ensure users dot files are not group or world writable = $RES"


RES="OK"
grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
                        echo ".forward file $dir/.forward exists"
                        RES="NOK"
                fi
        fi
done

echo "6.2.8    | Ensure no users have .forward files = $RES"

RES="OK"
grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
                        echo ".netrc file $dir/.netrc exists"
                        RES="NOK"
                fi
        fi
done

echo "6.2.9    | Ensure no users have .netrc files = $RES"


RES="OK"
grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                for file in $dir/.netrc; do
                        if [ ! -h "$file" -a -f "$file" ]; then
                                fileperm=$(ls -ld $file | cut -f1 -d" ")
                                if [ $(echo $fileperm | cut -c5) != "-" ]; then
                                        echo "Group Read set on $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c6) != "-" ]; then
                                        echo "Group Write set on $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c7) != "-" ]; then
                                        echo "Group Execute set on $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c8) != "-" ]; then
                                        echo "Other Read set on $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c9) != "-" ]; then
                                        echo "Other Write set on $file"
                                        RES="NOK"
                                fi
                                if [ $(echo $fileperm | cut -c10) != "-" ]; then
                                        echo "Other Execute set on $file"
                                        RES="NOK"
                                fi
                        fi
                done
        fi
done
echo "6.2.10   | Ensure users .netrc Files are not group or world accessible = $RES"


RES="OK"
grep -E -v '^(root|halt|sync|shutdown)' /etc/passwd | awk -F: '($7 != "'"$(which nologin)"'" && $7 != "/bin/false") { print $1 " " $6 }' | while read user dir; do
        if [ ! -d "$dir" ]; then
                echo "The home directory ($dir) of user $user does not exist."
                RES="NOK"
        else
                for file in $dir/.rhosts; do
                        if [ ! -h "$file" -a -f "$file" ]; then
                                echo ".rhosts file in $dir"
                                RES="NOK"
                        fi
                done
        fi
done

echo "6.2.11   | Ensure no users have .rhosts files = $RES"


RES="OK"
for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
        grep -q -P "^.*?:[^:]*:$i:" /etc/group
        if [ $? -ne 0 ]; then
                echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
                RES="NOK"
        fi
done
echo "6.2.12   | Ensure all groups in /etc/passwd exist in /etc/group = $RES"


RES="OK"
cut -f3 -d":" /etc/passwd | sort -n | uniq -c | while read x ; do
        [ -z "$x" ] && break
        set - $x
        if [ $1 -gt 1 ]; then
                users=$(awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs)
                echo "Duplicate UID ($2): $users"
                RES="NOK"
        fi
done

echo "6.2.13   | Ensure no duplicate UIDs exist = $RES"


RES="OK"
cut -d: -f3 /etc/group | sort | uniq -d | while read x ; do
        echo "Duplicate GID ($x) in /etc/group"
        RES="NOK"
done

echo "6.2.14   | Ensure no duplicate GIDs exist = $RES"

RES="OK"
cut -d: -f1 /etc/passwd | sort | uniq -d | while read x; do
        echo "Duplicate login name ${x} in /etc/passwd"
        RES="NOK"
done

echo "6.2.15   | Ensure no duplicate user names exist = $RES"


RES="OK"
cut -d: -f1 /etc/group | sort | uniq -d | while read x; do
        echo "Duplicate group name ${x} in /etc/group"
        RES="NOK"
done
echo "6.2.16   | Ensure no duplicate group names exist = $RES"


grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group | wc -l | grep '^0$' >/dev/null 2>&1  && RES1="OK" || RES1="NOK"
awk -F: '($4 == "<shadow-gid>") { print }' /etc/passwd | wc -l | grep '^0$' >/dev/null 2>&1  && RES2="OK" || RES2="NOK"
echo "6.2.17   | Ensure shadow group is empty = $RES1 - $RES2"
