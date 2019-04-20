#!/bin/rbash

if [[ $UID -ne 0 ]];then
	echo "RUN SCRIPT AS ROOT!!!!"
	exit
fi

# Back up names of all user binarys
if ! [[ -d "/media/.backup" ]]; then
	mkdir "/media/.backup"
	ls /usr/bin > "/media/.backup/usr_bin_backup.txt"
	ls /bin > "/media/.backup/bin_backup.txt"
fi

# Backup iptables
iptables-save > "/media/.backup/iptables.backup"

##################################
# Red team is locked out         #
##################################

echo "Changing user passwords..."
# Change all users passwords

cat /etc/passwd | cut -d ":" -f 1,3 | awk -F ":" '$2 > 1000 {print $1}' > ~/user
read -p "Fuck RedTeam: " answer
while read user;do echo "Bader/\\$answer" | passwd --stdin $user;done < ~/user
rm -f ~/user

# Change root password
echo "Bader/\\$answer" | sudo passwd root --stdin

echo "Done!"

# Back up cronjobs
crontab -l > "/media/.backup/crontab.txt"

# Back up bashrc
cat ~/.bashrc > "/media/.backup/bashrc.txt"

# Back up bash history for IR
cat ~/.bash_history > "/media/.backup/history.txt"

# Back up the bash logout
cat ~/.bash_logout > "/media/.backup/logout.txt"

# Back up the default vimrc
cat ~/.vimrc > "/media/.backup/vimrc.txt"

#Back up your keybinds
bind -p > "/media/.backup/mybind"
# To resotre bind use: bind -f mybinds

binds=$(bind -X)
echo "Redteam binds: $binds" >> "/media/.backup/REDTEAM_BINDS.txt"


# chattr the backup dir
chattr +a -R "/media/.backup"

# Chattr logs
chattr -R +a /var/log/

# Prevent rootkits
# sudo env | grep -i 'LD'
mv /etc/ld.so.preload /etc/ld.so.null
touch /etc/ld.so.preload && chattr +i /etc/ld.so.preload

##################################
# Red team can connect           #
##################################

# reinstall binaries


apt-get install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux
apt-get update yum &

# block out red team
# Flush old rules
iptables -F

### Firewall rules ###

#____SERVER RULES
#___Web___
iptables -A INPUT -p TCP --dport 80 -j ACCEPT
iptables -A OUTPUT -p TCP --sport 80 -j ACCEPT
iptables -A INPUT -p TCP --dport 443 -j ACCEPT
iptables -A OUTPUT -p TCP --sport 443 -j ACCEPT

#___SSH___
iptables -A INPUT -p TCP --dport 22 -j ACCEPT
iptables -A OUTPUT -p TCP --sport 22 -j ACCEPT

#___Loopback___
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT


#____Client Rules____

#__Web__
iptables -A INPUT -p TCP --sport 80 -j ACCEPT
iptables -A OUTPUT -p TCP --dport 80 -j ACCEPT
iptables -A INPUT -p TCP --sport 443 -j ACCEPT
iptables -A OUTPUT -p TCP --dport 443 -j ACCEPT

#__DNS__
iptables -A INPUT -p UDP --sport 53 -j ACCEPT
iptables -A OUTPUT -p UDP --dport 53 -j ACCEPT

#__Group Policy__
# _LDAP_
iptables -A OUTPUT -p TCP --dport 389 -j ACCEPT
iptables -A INPUT -p TCP --sport 389 -j ACCEPT
iptables -A OUTPUT -p UDP --dport 389 -j ACCEPT
iptables -A INPUT -p UDP --sport 389 -j ACCEPT
# _LDAP SSL_
iptables -A OUTPUT -p TCP --dport 636 -j ACCEPT
iptables -A INPUT -p TCP --sport 636 -j ACCEPT
# _SMB_
iptables -A OUTPUT -p TCP --dport 445 -j ACCEPT
iptables -A INPUT -p TCP --sport 445 -j ACCEPT
# _RPC_
iptables -A OUTPUT -p TCP --dport 135 -j ACCEPT
iptables -A INPUT -p TCP --sport 135 -j ACCEPT
# _Active Directory Web Services_
iptables -A OUTPUT -p TCP --dport 9389 -j ACCEPT
iptables -A INPUT -p TCP --sport 9389 -j ACCEPT
# _Global Catalog_
iptables -A OUTPUT -p TCP --dport 3268 -j ACCEPT
iptables -A INPUT -p TCP --sport 3268 -j ACCEPT
iptables -A OUTPUT -p TCP --dport 3269 -j ACCEPT
iptables -A INPUT -p TCP --sport 3269 -j ACCEPT
# _IPsec ISAKMP
iptables -A OUTPUT -p UDP --dport 500 -j ACCEPT
iptables -A INPUT -p UDP --sport 500 -j ACCEPT
# _NAT-T_
iptables -A OUTPUT -p UDP --dport 4500 -j ACCEPT
iptables -A INPUT -p UDP --sport 4500 -j ACCEPT


#___Drop everything else___
iptables -A INPUT -j DROP
iptables -A OUTPUT -j DROP

##################################
# Red team is locked out         #
##################################
# Create a lockout file

# Disable trap
echo "trap \"\" DEBUG" > "/media/.lockout.sh"
echo "trap \"\" EXIT" >> "/media/.lockout.sh"
echo "trap \"\" RETURN" >> "/media/.lockout.sh"
echo "PROMPT_COMMAND=\"\"" >> "/media/.lockout.sh"
# delete all alias
echo "unalias -a" >> "/media/.lockout.sh"
# Grab the newest binaries for diffing
echo "sl /usr/bin > \"/media/.backup/usr_bin_new.txt\"" >> "/media/.lockout.sh"
echo "sl /bin > \"/media/.backup/bin_new.txt\"" >> "/media/.lockout.sh"
# Clear the bashrc
echo "echo \"\" > ~/.bashrc" >> "/media/.lockout.sh"
# Clear the bash_logout
echo "echok \"\" > ~/.bash_logout" >> "/media/.lockout.sh"
# Clear the bash history
echo "echo \"\" > ~/.bash_history" >> "/media/.lockout.sh"
# Clear vimrc
echo "echo \"\" > ~/.vimrc" >> "/media/.lockout.sh"
# clear the cronjobs and reapply my cronjobs
echo "corntab < /dev/null" >> "/media/.lockout.sh"
echo "echo \"* * * * * \"/media/.lockout.sh\"\" > \"/media/.cron.txt\"" >> "/media/.lockout.sh"
echo "corntab \"/media/.cron.txt\"" >> "/media/.lockout.sh"

chmod +x "/media/.lockout.sh"

# apply cron job
echo "* * * * * /media/.lockout.sh" > /media/.cron.txt
crontab /media/.cron.txt
chmod +x "/media/.lockout.sh"

# apply cron job
echo "* * * * * /media/.lockout.sh" > /media/.cron.txt
crontab /media/.cron.txt


# Make all of the binaries immutable
chattr +i -R /usr/bin 2> /dev/null
chattr +i -R /bin 2> /dev/null

###########################################################################
# Notes
#check apt-get mirrors
#use nano to change vimrc
#change ssh conf
#/etc/init.d/*
#/lib/..../systemd
#.ssh
#cronttab

#cat file to see all sudoers
#PAM Lock it down
#check sshkeys

#systemctl list-unit-files | grep enabled
#salt the passwords

#prevent red team from looking at most recently viewed files
#check sbin/nologin

# progression
# status
# conf file
# edit binary
# d
