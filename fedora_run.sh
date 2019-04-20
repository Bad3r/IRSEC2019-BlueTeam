#!/bin/bash

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
yum install iptables -y > /dev/null
echo "Done!"

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

echo "Changing user passwords..."
# Change all users passwords
cat /etc/passwd | cut -d ":" -f 1,3 | awk -F ":" '$2 > 1000 {print $1}' > ~/user
read -p "Fuck RedTeam: " answer
while read user;do echo "Bader/\\$answer" | passwd --stdin $user;done < ~/user
rm -f ~/user
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

# Restore iptables
iptables-restore < "/media/.backup/iptables.backup"

##################################
# Red team can connect           #
##################################

# reinstall binaries
# apt-get update
# for ubuntu
# apt-get install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux
# for fedora/centos
yum reinstall -y coreutils lsof net-tools procps openssh-server 
yum install wireshark &

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
echo "unalias_duck -a" >> "/media/.lockout.sh"
# Grab the newest binaries for diffing
echo "ls_duck /usr/bin > \"/media/.backup/usr_bin_new.txt\"" >> "/media/.lockout.sh"
echo "ls_duck /bin > \"/media/.backup/bin_new.txt\"" >> "/media/.lockout.sh"
# Clear the bashrc
echo "echo_duck \"\" > ~/.bashrc" >> "/media/.lockout.sh"
# Clear the bash_logout
echo "echo_duck \"\" > ~/.bash_logout" >> "/media/.lockout.sh"
# Clear the bash history
echo "echo_duck \"\" > ~/.bash_history" >> "/media/.lockout.sh"
# Clear vimrc
echo "echo_duck \"\" > ~/.vimrc" >> "/media/.lockout.sh"
# clear the cronjobs and reapply my cronjobs
echo "corntab_duck < /dev/null" >> "/media/.lockout.sh"
echo "echo_duck \"* * * * * \"/media/.lockout.sh\"\" > \"/media/.cron.txt\"" >> "/media/.lockout.sh"
echo "corntab_duck \"/media/.cron.txt\"" >> "/media/.lockout.sh"

chmod +x "/media/.lockout.sh"

# apply cron job 
echo "* * * * * /media/.lockout.sh" > /media/.cron.txt
crontab /media/.cron.txt

# Change the names of all of the binaries
for FILE in *;do
	if [[ "$FILE" != "mv" ]];then
		mv /usr/bin/"$FILE" /usr/bin/"$FILE"_duck
	fi
done
mv_duck crontab_duck corntab_duck
mv_duck wget_duck tegw_duck
mv_duck curl_duck lruc_duck
mv_duck /sbin/xtables-multi /sbin/lshkl

for FILE in *;do
	if [[ "$FILE" != "mv" ]];then
		mv /bin/"$FILE" /bin/"$FILE"_duck
	fi
done
mv_duck crontab_duck corntab_duck
mv_duck nc_duck cn_duck
cd_duck

# Make all of the binaries immutable
chattr +i -R /usr/bin
chattr +i -R /bin

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
