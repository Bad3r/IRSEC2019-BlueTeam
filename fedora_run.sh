#!/bin/bash

# Backup iptables
iptables-save > ~/backup/iptables.backup

# block out red team
sudo iptables -F 
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

##################################
# Red team is locked out         #
##################################

# Change all users passwords
passwd principal
passwd chaperone
passwd deejay
passwd kid_with_sweatpants
passwd prom_king
passwd prom_queen
passwd dbadmin

# Back up names of all user binarys 
if ! [[ -d ~/backup ]]; then
	mkdir ~/backup
	ls /usr/bin > ~/backup/usr_bin_backup.txt
	ls /bin > ~/backup/bin_backup.txt
fi

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# Need to hide all files make a directory that is a space

# Back up cronjobs
crontab -l > ~/backup/crontab.txt

# Back up bashrc
cat ~/.bashrc > ~/backup/bashrc.txt

# Back up bash history for IR
cat ~/.bash_history > ~/backup/history.txt

# Back up the bash logout
cat ~/.bash_logout > ~/backup/logout.txt

# Back up the default vimrc
cat ~/.vimrc > ~/backup/vimrc.txt

#Back up your keybinds
bind -p > ~/backup/mybind
# To resotre bind use: bind -f mybinds

binds=$(bind -X)
echo "Redteam binds: $binds" >> ~/backup/REDTEAM_BINDS.txt


# chattr the backup dir
sudo chattr +a -R ~/backup

# Chattr logs
sudo chattr -R +a /var/log/
sudo chattr -R -a /var/log/apt/
sudo chattr -a /var/log/lastlog
sudo chattr -a /var/log/dpkg.log

# Prevent rootkits
#sudo env | grep -i 'LD'
sudo mv /etc/ld.so.preload /etc/ld.so.null
sudo touch /etc/ld.so.preload && sudo chattr +i /etc/ld.so.preload

# Restore iptables
iptables-restore < ~/backup/iptables.backup

##################################
# Red team can connect           #
##################################

# reinstall binaries
sudo apt-get update
# for ubuntu
#sudo apt-get install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux
# for fedora/centos
sudo yum reinstall -y coreutils lsof net-tools procps openssh-server make automake gcc gcc-c++ kernel-devel
sudo yum update &

# block out red team
sudo iptables -F 
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP

##################################
# Red team is locked out         #
##################################

# Create a lockout file

# Disable trap
echo "trap \"\" DEBUG" > ~/lockout.sh
echo "trap \"\" EXIT" >> ~/lockout.sh
echo "trap \"\" RETURN" >> ~/lockout.sh
echo "PROMPT_COMMAND=\"\"" >> ~/lockout.sh
# delete all alias
echo "unalias_duck -a" >> ~/lockout.sh
# Grab the newest binaries for diffing
echo "ls_duck /usr/bin > ~/backup/usr_bin_new.txt" >> ~/lockout.sh
echo "ls_duck /bin > ~/backup/bin_new.txt" >> ~/lockout.sh
# Clear the bashrc
echo "echo_duck \"\" > ~/.bashrc" >> ~/lockout.sh
# Clear the bash_logout
echo "echo_duck \"\" > ~/.bash_logout" >> ~/lockout.sh
# Clear the bash history
echo "echo_duck \"\" > ~/.bash_history" >> ~/lockout.sh
# Clear vimrc
echo "echo_duck \"\" > ~/.vimrc" >> ~/lockout.sh
# clear the cronjobs and reapply my cronjobs
echo "corntab_duck < /dev/null" >> ~/lockout.sh
echo "echo_duck \"* * * * * ~/lockout.sh\" > ~/cron.txt" >> ~/lockout.sh
ehco "corntab_duck ~/cron.txt" >> ~/lockout.sh

sudo chmod +x ~/lockout.sh

# apply cron job 
echo "* * * * * ~/lockout.sh" > ~/cron.txt
crontab ~/cron.txt

# Change the names of all of the binaries
cd /usr/bin
for FILENAME in *;do mv $FILENAME $FILENAME_duck;done
mv_duck crontab_duck corntab_duck
mv_duck wget_duck tegw_duck
mv_duck curl_duck lruc_duck
mv_duck /sbin/xtables-multi /sbin/lshkl

cd_duck /bin
for FILENAME in *;do mv $FILENAME $FILENAME_duck;done
mv_duck crontab_duck corntab_duck
mv_duck nc_duck cn_duck
cd_duck

# Make all of the binaries immutable
sudo chattr +i -R /usr/bin
sudo chattr +i -R /bin

# Firewall rules
# use lshkl

# Restore iptables
iptables-restore < ~/backup/iptables.backup

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
#go through all the users and change password
