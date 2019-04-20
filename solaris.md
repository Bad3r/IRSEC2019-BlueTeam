# init:
use cli or add shortcut:
    - start -> pref. -> desktop -> keyboard -> shortcuts: gnome-terminal

    - https://thinkinginsoftware.blogspot.com
    - run script

    - if dad-son: /usr/include/pcap
    Requirements

libpcap, and the executable that you want to run on ping as /bin/ipfctl. stdin, out, and err are redirected from son to this executable.



# Misc

Solaris: where is the sudoers file?
Some would say /etc/opt/csw/sudoers, others /usr/local/etc/sudoers and I have even found it in /opt/csw/etc/sudoer. In fact I have seen people referring to /opt/sfw/etc/sudoers. The reality is that it depends on the environment.

The first thing you need to know is where is sudo command using a regular user:
'$ which sudo'
'/opt/csw/bin/sudo'

Now that we know where the bin is we need to locate the sudoers file for which you will run the below as root:
'# truss /opt/csw/bin/sudo ls 2>&1 | grep sudoers'
You will get something like:

   stat64("/opt/csw/libexec/sudoers.so", 0x08047C70) = 0 xstat(2, "/opt/csw/libexec/sudoers.so", 0x08047090) = 0 resolvepath("/opt/csw/libexec/sudoers.so", "/opt/csw/libexec/sudoers.so", 1023) = 27 open("/opt/csw/libexec/sudoers.so", O_RDONLY) = 4 stat64("/opt/csw/libexec/sudoers.so", 0x08047C70) = 0 lstat64("/etc/opt/csw/sudoers", 0x08047BD0) = 0 open64("/etc/opt/csw/sudoers", O_RDONLY) = 4 openat(-3041965, "/etc/opt/csw/sudoers.d", O_RDONLY|O_NDELAY|O_LARGEFILE) = 5

So in this case the file is /etc/opt/csw/sudoers.
