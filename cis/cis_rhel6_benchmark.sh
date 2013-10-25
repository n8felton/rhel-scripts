#!/bin/bash
# Based on CIS Red Hat Enterprise Linux 6 Benchmark v1.2.0 - 06-25-2013
# https://benchmarks.cisecurity.org/downloads/show-single/?file=rhel6.120

# Detect and remove legacy services (CIS 2.1)
for service in telnet-server telnet rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd; do
	rpm -q $service && yum erase $service
done
unset service

for service in chargen-dgram chargen-stream daytime-dgram daytime-stream echo-dgram echo-stream tcpmux-server; do
	chkconfig --list $service | grep on && chkconfig $service off && chkconfig --list $service
done
unset service

# 3.1 Set Daemon umask
grep umask /etc/sysconfig/init || echo umask 027 >> /etc/sysconfig/init

# 3.3 Disable Avahi Server
chkconfig --list avahi-daemon | grep on && chkconfig avahi-daemon off && chkconfig --list avahi-daemon

# 3.4 Disable Print Server - CUPS
chkconfig --list cups | grep on && chkconfig cups off && chkconfig --list cups

# 3.5 Remove DHCP Server
rpm -q dhcp && yum erase dhcp

# 3.7 Remove LDAP
rpm -q openldap-servers && yum erase openldap-servers
rpm -q openldap-clients && yum erase openldap-clients

# 3.9 Remove DNS Server
rpm -q bind && yum erase bind

# 3.10 Remove FTP Server
rpm -q vsftpd && yum erase vsftpd

# 3.11 Remove HTTP Server
rpm -q httpd && yum erase httpd

# 3.12 Remove Dovecot (IMAP and POP3 services)
rpm -q dovecot && yum erase dovecot

# 3.13 Remove Samba
rpm -q samba && yum erase samba

# 3.14 Remove HTTP Proxy Server
rpm -q squid && yum erase squid

# 3.15 Remove SNMP Server
rpm -q net-snmp && yum erase net-snmp

# 6.2 Configure SSH
# 6.2.1 Set SSH Protocol to 2
sed -ri'' 's/^#*Protocol.*$/Protocol 2/g' /etc/ssh/sshd_config && grep "^#*Protocol" /etc/ssh/sshd_config

# 6.2.2 Set LogLevel to INFO
sed -ri'' 's/^#*LogLevel.*$/LogLevel INFO/g' /etc/ssh/sshd_config && grep "^#*LogLevel" /etc/ssh/sshd_config

# 6.2.3 6.2.3 Set Permissions on /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

# 6.2.4 Disable SSH X11 Forwarding
sed -ri'' 's/^#*X11Forwarding.*$/X11Forwarding no/g' /etc/ssh/sshd_config && grep "^#*X11Forwarding" /etc/ssh/sshd_config

# 6.2.5 Set SSH MaxAuthTries to 4 or Less
sed -ri'' 's/^#*MaxAuthTries.*$/MaxAuthTries 5/g' /etc/ssh/sshd_config && grep "^#*MaxAuthTries" /etc/ssh/sshd_config

# 6.2.6 Set SSH IgnoreRhosts to Yes
sed -ri'' 's/^#*IgnoreRhosts.*$/IgnoreRhosts yes/g' /etc/ssh/sshd_config && grep "^#*IgnoreRhosts" /etc/ssh/sshd_config

# 6.2.7 Set SSH HostbasedAuthentication to No
sed -ri'' 's/^#*HostbasedAuthentication.*$/HostbasedAuthentication no/g' /etc/ssh/sshd_config && grep "^#*HostbasedAuthentication" /etc/ssh/sshd_config

# 6.2.8 Disable SSH Root Login
sed -ri'' 's/^#*PermitRootLogin.*$/PermitRootLogin no/g' /etc/ssh/sshd_config && grep "^#*PermitRootLogin" /etc/ssh/sshd_config

# 6.2.9 Set SSH PermitEmptyPasswords to No
sed -ri'' 's/^#*PermitEmptyPasswords.*$/PermitEmptyPasswords no/g' /etc/ssh/sshd_config && grep "^#*PermitEmptyPasswords" /etc/ssh/sshd_config

# 6.2.10 Do Not Allow Users to Set Environment Options
sed -ri'' 's/^#*PermitUserEnvironment.*$/PermitUserEnvironment no/g' /etc/ssh/sshd_config && grep "^#*PermitUserEnvironment" /etc/ssh/sshd_config

# 6.2.11 Use Only Approved Cipher in Counter Mode
grep Ciphers /etc/ssh/sshd_config || echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config

# 6.2.12 Set Idle Timeout Interval for User Login
sed -ri'' 's/^#*ClientAliveInterval.*$/ClientAliveInterval 1800/g' /etc/ssh/sshd_config && grep "^#*ClientAliveInterval" /etc/ssh/sshd_config
sed -ri'' 's/^#*ClientAliveCountMax.*$/ClientAliveCountMax 0/g' /etc/ssh/sshd_config && grep "^#*ClientAliveCountMax" /etc/ssh/sshd_config

# 6.2.14 Set SSH Banner
sed -ri'' 's_^#*Banner.*$_Banner /etc/issue.net_g' /etc/ssh/sshd_config && grep "^#*Banner" /etc/ssh/sshd_config
curl http://people.rit.edu/nlfdss/issue.net -o /etc/issue.net -#

# 9.1.2 Verify Permissions on /etc/passwd
/bin/chmod 644 /etc/passwd

# 9.1.3 Verify Permissions on /etc/shadow
/bin/chmod 000 /etc/shadow

# 9.1.4 Verify Permissions on /etc/gshadow
/bin/chmod 000 /etc/gshadow

# 9.1.5 Verify Permissions on /etc/group
/bin/chmod 644 /etc/group

# 9.1.6 Verify User/Group Ownership on /etc/passwd
/bin/chown root:root /etc/passwd

# 9.1.7 Verify User/Group Ownership on /etc/shadow
/bin/chown root:root /etc/shadow

# 9.1.8 Verify User/Group Ownership on /etc/gshadow
/bin/chown root:root /etc/gshadow

# 9.1.9 Verify User/Group Ownership on /etc/group
/bin/chown root:root /etc/group
