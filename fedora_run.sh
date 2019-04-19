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
sudo passwd principal
sudo passwd chaperone
sudo passwd deejay
sudo passwd kid_with_sweatpants
sudo passwd prom_king
sudo passwd prom_queen
sudo passwd dbadmin

# Back up names of all user binarys 
if ! [[ -d ~/backup ]]; then
	mkdir ~/backup
	ls /usr/bin > ~/backup/usr_bin_backup.txt
	ls /bin > ~/backup/bin_backup.txt
fi

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

# Restore iptables
iptables-restore < ~/backup/iptables.backup

# chattr the backup dir
sudo chattr +a -R ~/backup


##################################
# Red team can connect           #
##################################

# reinstall binaries
sudo apt-get update
sudo apt-get install -y --reinstall coreutils openssh-server net-tools build-essential libssl-dev procps lsof tmux
sudo yum reinstall -y coreutils lsof net-tools procps

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
echo "unalias -a" >> ~/lockout.sh
#check to see if new binaries have been added
echo "ls /usr/bin > ~/backup/usr_bin_new.txt" >> ~/lockout.sh
echo "ls /bin > ~/backup/bin_new.txt" >> ~/lockout.sh
# Clear the bashrc
echo "echo \"\" > ~/.bashrc" >> ~/lockout.sh
# Clear the bash_logout
echo "echo \"\" > ~/.bash_logout" >> ~/lockout.sh
# Clear the bash history
echo "echo \"\" > ~/.bash_history" >> ~/lockout.sh
# Clear vimrc
echo "echo \"\" > ~/.vimrc" >> ~/lockout.sh
# clear the cronjobs and reapply my cronjobs
echo "crontab < /dev/null" >> ~/lockout.sh
echo "echo \"* * * * * ~/lockout.sh\" > ~/cron.txt" >> ~/lockout.sh
ehco "crontab ~/cron.txt" >> ~/lockout.sh
sudo chmod +x ~/lockout.sh

# apply cron job 
echo "* * * * * ~/lockout.sh" > ~/cron.txt
crontab ~/cron.txt

# Change the names of all of the binaries
cd /usr/bin
for FILENAME in *;do mv $FILENAME $FILENAME_duck;done
cd /bin
for FILENAME in *;do mv $FILENAME $FILENAME_duck;done
cd

# Make all of the binaries immutable
sudo chattr +i -R /usr/bin
sudo chattr +i -R /bin

# change crontab to corntab

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
