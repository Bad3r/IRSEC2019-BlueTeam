#! /bin/bash

# If not root, break and require root
if [ `whoami` != root ]; then
  echo "Script requires root to run"
  exit
fi
echo "Changing user passwords..."
# Change all users passwords
cat /etc/passwd | cut -d ":" -f 1,3 | awk -F ":" '$2 > 1000 {print $1}' > ~/user
read -p "Fuck RedTeam: " answer
while read user;do echo "Bader/\\$answer" | passwd --stdin $user;done < ~/user
rm -f ~/user
# Change root password
echo "Bader/\\$answer" | sudo passwd root --stdin
echo "Done!"


echo "checking... for csw"
CSW=/opt/csw
BAD=$HOME/badstuff
SSH=/etc/ssh

mkdir $BAD

if [ -d $CSW ]; then
  echo "exists!"
  mv -r $CSW $BAD/

echo "setting up packages.."
pkgadd -d http://get.opencsw.org/now
mv /bin/bash BAD/
export PATH=${PATH}:/opt/csw/bin
pkgutil -U
pkgutil -y -i vim curl wget top bash
echo "done, switching to bash"
/opt/csw/bin/bash

echo "setting up the firewall.."
### Firewall rules ###
r=/etc/ipf/ipf.conf

# Firewall Rules File
cat > /etc/rc.conf << EOF
ipfilter_enable="YES"
ipfilter_rules="$r"
ipmon_enables="YES"
ipmon_flags="-Ds"
EOF

# Firewall Config File
cat > $r << EOF
pass in quick log proto icmp from any to any
pass out quick log proto icmp from any to any
pass out quick log proto tcp from any to any port = 22 keep state
pass in quick log proto tcp from any port = 22 to any keep state
block out all
block in all
EOF
# Start Firewall
ipf -Fa -f $r
svcadm enable network/ipfilter
svcadm refresh network/ipfilter
ipf -E

echo "done"
