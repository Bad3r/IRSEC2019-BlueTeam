#!/bin/bash
# Blue Teaming Linux Hardening Script 
# Author: G666gle

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

# Install iptables
echo "Installing iptables..."
yum install -y iptables 
echo "Done!"

echo "More stuff..."
yum install -y cronie 


# Backup iptables
iptables-save > "/media/.backup/iptables.backup"

# block out red team
iptables -F 
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

##################################
# Red team is locked out         #
##################################

echo "Red team No No."

echo "Changing user passwords..."
# Change all users passwords
cat /etc/passwd | cut -d ":" -f 1,3 | awk -F ":" '$2 > 1000 {print $1}' > ~/user
read -p "Fuck RedTeam: " answer
while read user;do echo "Bader/\\$answer" | passwd --stdin $user;done < ~/user
rm -f ~/user
# Change root password
echo "Bader/\\$answer" | sudo passwd root --stdin
echo "Done!"

echo "RIP Harambe"

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


# Chattr logs
chattr -R +a /var/log/

# Prevent rootkits
# sudo env | grep -i 'LD'
mv /etc/ld.so.preload /etc/ld.so.null
touch /etc/ld.so.preload && chattr +i /etc/ld.so.preload

# Restore iptables
iptables-restore < "/media/.backup/iptables.backup"

# chattr the backup dir
chattr +i -R "/media/.backup"
chattr -i "/media/.backup/iptables.backup"

##################################
# Red team can connect           #
##################################

echo "Red team Yes Yes"

# reinstall binaries
# apt-get update
# for ubuntu
# apt-get install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux
# for fedora/centos
yum reinstall -y coreutils lsof net-tools procps openssh-server iptables
yum install -y wireshark &

# block out red team
iptables -F 
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

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
echo "echo \"* * * * * \"/media/.lockout.sh\"\" > \"/media/.backup/cron.txt\"" >> "/media/.lockout.sh"
echo "corntab \"/media/.backup/cron.txt\"" >> "/media/.lockout.sh"

chmod +x "/media/.lockout.sh"

# apply cron job 
echo "* * * * * /media/.lockout.sh" > /media/.backup/.txt
crontab /media/.backup/.txt

# Change the names of all of the binaries
# for FILE in *;do
# 	if [[ "$FILE" != "mv" ]];then
# 		mv /usr/bin/"$FILE" /usr/bin/"$FILE"_duck
# 	fi
# done
mv /usr/bin/crontab /usr/bin/corntab
mv /usr/bin/wget /usr/bin/tegw
mv /usr/bin/curl /usr/bin/lruc
mv /usr/bin/ls /usr/bin/sl
mv /usr/bin/cd /usr/bin/dc
mv /usr/bin/nc /usr/bin/cn

mv /sbin/xtables-multi /sbin/lshkl

# for FILE in *;do
# 	if [[ "$FILE" != "mv" ]];then
# 		mv /bin/"$FILE" /bin/"$FILE"_duck
# 	fi
# done
mv /bin/crontab /bin/corntab
mv /bin/nc /bin/cn
mv /bin/ls /bin/sl
mv /bin/cd /bin/dc
mv /bin/curl /bin/lruc
mv /bin/wget /bin/tegw
cd

# Make all of the binaries immutable
chattr +i -R /usr/bin 2> /dev/null
chattr +i -R /bin 2> /dev/null

# Firewall rules
# use lshkl

# Restore iptables
iptables-restore < /media/.backup/iptables.backup

##################################
# Red team can connect           #
##################################



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
