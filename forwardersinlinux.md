# How to Install Forwarding Process on Linux


**Setting up receiving with splunk on web interface:**

1. Log into the receiver as admin or an administrative equivalent. 
2. Click Settings > Forwarding and receiving. 
3. At Configure receiving, click Add new. 
4. Specify the TCP port you want the receiver to listen on (the listening port, also known as the receiving port). For example, if you enter "9997," the receiver listens for connections from forwarders on port 9997. You can specify any unused port. You can use a tool like netstat to determine what ports are available on your system. Make sure the port you select is not in use by splunkweb or splunkd. 
5. Click Save. Splunk software starts listening for incoming data on the port you specified.


**Setting up receiving with splunk using CLI:**
	cd $SPLUNK_HOME/bin

	splunk enable listen <port> -auth <username>:<password>

	(easier to manage using web interface than attempting w CLI for reading the actual logs)
 
**Deploying a heavy forwarder using web interface:**

1. Log into Splunk Web as admin on the instance that will be forwarding data. 
2. Click the Settings > Forwarding and receiving. 
3. Click Add new at Configure forwarding. 
4. Enter the hostname or IP address for the receiving Splunk instance(s), along with the receiving port specified when the receiver was configured. For example, you might enter: receivingserver.com:9997. To implement load-balanced forwarding, you can enter multiple hosts as a comma-separated list. 
5. Click Save.


**Configuring a heavy forwarder using web interface:**

1. Log into Splunk Web as admin on the instance that will be forwarding data. 
2. Click the Settings > Forwarding and receiving. 
3. Select Forwarding defaults. 
4. Select Yes to store and maintain a local copy of the indexed data on the forwarder. 
All other configuration must be done in outputs.conf.


**Installing Splunk on Linux / Setting up Forwarding and Receiving:**
use wget command to download Splunk on linux in cmd
	do not install Splunk as root user

Tar file installation command: tar xvzf splunk_package_name.tgz -C /opt?

Set up heavy forwarding using CLI -
	type:  /opt/splunkforwarder/bin sudo ./splunk enable boot-start 
					OR TYPE (depending what you save it to)
	type $SPLUNK_HOME/bin/

	splunk enable app SplunkForwarder -auth <username>:<password>



**Start heavy forwarding using CLI**
	type command: $SPLUNK_HOME/bin
			splunk add forward-server <host>:<port> -auth <username>:<password>
			(specify a receiver)

			sudo ./splunk add monitor LOG -sourcetype SOURCE_TYPE -index NAME
					(ex of this: sudo ./splunk add monitor /var/log/syslog -sourcetype linux_logs -index remotelogs)

	restart the forwarder using:
			sudo ./splunk restart

Stopping using CLI -
	type command: splunk remove forward-server <host>:<port> -auth <username>:<password>


**Tips:**
Just don’t install Splunk as root user please !!
When starting, if it makes you accept license in CLI use command:  ./splunk start —accept-license


**Other Commands:**
./splunk start
./splunk stop
./splunk restart
./splunk help
