#!/usr/bin/perl -w
#Fat Winnie v6, a Syslog Relay dedicated to receiving Snort's Syslog alerts, sending them out through SMTP, and storing them in a MySQL database.
=head
The following instruction shows how to tweak Snort in an effort to let it send out its alerts through Syslog protocol.

root@LinuxTest:~# snort -V

   ,,_     -*> Snort! <*-
  o"  )~   Version 2.9.7.0 GRE (Build 149)
   ''''    By Martin Roesch & The Snort Team: http://www.snort.org/contact#team
           Copyright (C) 2014 Cisco and/or its affiliates. All rights reserved.
           Copyright (C) 1998-2013 Sourcefire, Inc., et al.
           Using libpcap version 1.8.1
           Using PCRE version: 8.39 2016-06-14
           Using ZLIB version: 1.2.8


root@LinuxTest:~# cat /etc/rsyslog.conf|grep '*.*'|grep 514|grep -v '#'
*.*                             @192.168.0.1:514

root@LinuxTest:~# cat /etc/snort/snort_syslog.conf|grep syslog|grep -v '#'
output alert_syslog: host=192.168.0.1:514, LOG_LOCAL1 LOG_ALERT

root@LinuxTest:~# ps -aef|grep snort
root      8709     1  0 01:59 ?        00:00:02 /usr/sbin/snort -c /etc/snort/snort_syslog.conf -i eth0 -A full -D -s

P.S.: In this case, 192.168.0.1 is the remote syslogd server. Moreover, after everything above is set, rebooting the system is a must. Otherwise, the rsyslogd may not function properly.
=cut
use IO::Socket;
use DBI;
$|=1;

$debug_switch=0;     					#0 means off; 1 means on.

$syslogd_port=88;					#Syslog service listening port
$smtp_server='127.0.0.1';				#SMTP server's IP address
$smtp_port=25;
$smtp_domain='demonalex.com';				#SMTP server's domain
$smtp_sender='itsecurity@demonalex.com';		#Sender's mailbox
$smtp_receiver='itsecurity@demonalex.com';		#Receiptor's mailbox
@snort_blacklist_keywords=(				#A blacklist specializing in filtering out those false-positive alerts
#'Priority: 1',
#'Priority: 2',
'Not Suspicious Traffic',
'Classification: Potentially Bad Traffic',
'Classification: Misc activity',
'Generic Protocol Command Decode',
'BAD TRAFFIC Non-Standard IP protocol',
);
$database_name="security";				#MySQL's database name
$database_username="root";				#MySQL's account
$database_password="";					#MySQL account's password
$database_tablename="threats";				#MySQL's table name

sub sendmail($$){
	$content = shift;
	$subject = shift;
	$sock = IO::Socket::INET->new(PeerAddr => $smtp_server,
				PeerPort => $smtp_port,
				Proto => 'tcp') || die "Cannot create Socket!\n";
	$sock->send("HELO ".$smtp_domain."\r\n");
	$sock->recv($mem, 100, 0);
	$sock->send("MAIL FROM: ".$smtp_sender."\r\n");
	$sock->recv($mem, 100, 0);
	$sock->send("RCPT TO: ".$smtp_receiver."\r\n");
	$sock->recv($mem, 100, 0);
	$sock->send("DATA\r\n");
	$sock->recv($mem, 100, 0);
	$sock->send("From: ".$smtp_sender."\r\n");
	$sock->send("To: ".$smtp_receiver."\r\n");
	$subject = "Subject: ".$subject."\r\n\r\n";
	$sock->send($subject);
	$content = $content."\r\n".'.'."\r\n";
	$sock->send($content);
	$sock->recv($mem, 100, 0);
	$sock->send("QUIT\r\n");
	$sock->recv($mem, 100, 0);
	$sock->close();
	return;
}

sub snort_blacklist($){
	$original_content_1 = shift;
	foreach $snort_blacklist_keyword (@snort_blacklist_keywords){
		if($original_content_1=~/$snort_blacklist_keyword/){
			return 1;
		}
	}
	return 0;
}

sub snort_input_database($){
=head
CREATE DATABASE security;
CREATE TABLE threats (id INT NOT NULL AUTO_INCREMENT, s_time VARCHAR(20), sensor VARCHAR(20), engine VARCHAR(20), threat VARCHAR(200), classification VARCHAR(50), priority INT, protocol VARCHAR(11), srcip VARCHAR(20), srcport INT, dstip VARCHAR(20), dstport INT, PRIMARY KEY (id));
mysql> desc threats;
+----------------+--------------+------+-----+---------+----------------+
| Field          | Type         | Null | Key | Default | Extra          |
+----------------+--------------+------+-----+---------+----------------+
| id             | int(11)      | NO   | PRI | NULL    | auto_increment |
| s_time         | varchar(20)  | YES  |     | NULL    |                |
| sensor         | varchar(20)  | YES  |     | NULL    |                |
| engine         | varchar(20)  | YES  |     | NULL    |                |
| threat         | varchar(200) | YES  |     | NULL    |                |
| classification | varchar(50)  | YES  |     | NULL    |                |
| priority       | int(11)      | YES  |     | NULL    |                |
| protocol       | varchar(11)  | YES  |     | NULL    |                |
| srcip          | varchar(20)  | YES  |     | NULL    |                |
| srcport        | int(11)      | YES  |     | NULL    |                |
| dstip          | varchar(20)  | YES  |     | NULL    |                |
| dstport        | int(11)      | YES  |     | NULL    |                |
+----------------+--------------+------+-----+---------+----------------+
12 rows in set (0.00 sec)
=cut
	$database_content_for_snort = shift;
	#<38>Dec 30 12:51:22 LinuxTest snort[2466]: [1:2009358:5] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.172.222:39200 -> 192.168.1.189:80
	#<38>Dec 30 16:37:49 LinuxTest snort[2466]: [1:469:3] ICMP PING NMAP [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 192.168.172.222 -> 192.168.1.189	
	if ($database_content_for_snort=~/<(.*)>(.{15}) (.*) snort\[(.*)\] (.*) \[Classification: (.*)\] \[Priority: (.*)\] \{(.*)\} (.*):(.*) -> (.*):(.*)/){
		$s_time=$2;
		$sensor=$3;
		$engine="snort";
		$threat=$5;
		$classification=$6;
		$priority=$7;
		$protocol=$8;
		$srcip=$9;
		$srcport=$10;
		$dstip=$11;
		$dstport=$12;
	}elsif ($database_content_for_snort=~/<(.*)>(.{15}) (.*) snort\[(.*)\] (.*) \[Classification: (.*)\] \[Priority: (.*)\] \{(.*)\} (.*) -> (.*)/){
		$s_time=$2;
		$sensor=$3;
		$engine="snort";
		$threat=$5;
		$classification=$6;
		$priority=$7;
		$protocol=$8;
		$srcip=$9;
		$srcport=0;
		$dstip=$10;
		$dstport=0;	
	}else{
		return 0;
	}
	$dbh = DBI->connect("DBI:mysql:database=".$database_name.";host=localhost", $database_username, $database_password, {'RaiseError' => 1});
	#$dbh->do("INSERT INTO ".$database_tablename." VALUES (1, \"Dec 30 12:51:22\", \"LinuxTest\", \"snort\", \"ET SCAN Nmap Scripting Engine User-Agent Detected \(Nmap Scripting Engine\)\", \"Web Application Attack\", 1, \"TCP\", \"192.168.172.222\", 39200, \"192.168.1.189\", 80)");
	$query="INSERT INTO ".$database_tablename." \(s_time, sensor, engine, threat, classification, priority, protocol, srcip, srcport, dstip, dstport\) VALUES \(\"".$s_time."\", \"".$sensor."\", \"".$engine."\", \"".$threat."\", \"".$classification."\", ".$priority.", \"".$protocol."\", \"".$srcip."\", ".$srcport.", \"".$dstip."\", ".$dstport."\)";
	print $query."\n" if ($debug_switch==1);						#debug
	$dbh->do($query);
	$dbh->disconnect();
	return 1;
}

sub snort_filter($){
	$syslog_content_for_snort = shift;
	if(($syslog_content_for_snort=~/snort(.*): \[(.*)\] (.*) \[Classification:/) && (snort_blacklist($syslog_content_for_snort)==0)){
		$alert=$3;
		open(DEBUGFILE, ">>/root/debug") if ($debug_switch==1);
		print DEBUGFILE "whole:\n".$syslog_content_for_snort."\n" if ($debug_switch==1);
		if(($syslog_content_for_snort=~/(.*)<38>(.*)/) && (length($1) != 0)){			#Remove the issue just as the bad sample below
			$syslog_content_for_snort=~s/(.*)<38>(.*)/<38>$2/;
			print DEBUGFILE "header:\n".$1."\n" if ($debug_switch==1);
			print DEBUGFILE "body:\n".$syslog_content_for_snort."\n" if ($debug_switch==1);
		}else{
			print DEBUGFILE "header:\n"."\n" if ($debug_switch==1);
			print DEBUGFILE "body:\n".$syslog_content_for_snort."\n" if ($debug_switch==1);
		}
		print DEBUGFILE "\n------------------------------------------\n" if ($debug_switch==1);
		close(DEBUGFILE) if ($debug_switch==1);
		&sendmail($syslog_content_for_snort, $alert);
		&snort_input_database($syslog_content_for_snort);
		print $syslog_content_for_snort."\n" if ($debug_switch==1);									#debug
		#Samples:
		#<38>Dec 30 12:51:22 LinuxTest snort[2466]: [1:2009358:5] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.172.222:39200 -> 192.168.1.189:80
		#<38>Dec 30 16:37:49 LinuxTest snort[2466]: [1:469:3] ICMP PING NMAP [Classification: Attempted Information Leak] [Priority: 2] {ICMP} 192.168.172.222 -> 192.168.1.189
		#Bad samples:
		#<30>Jan  2 14:25:34 LinuxTest rc.local[2148]: <30>Jan  2 14:25:34 LinuxTest rc.local[2148]: <30>Jan  2 14:25:34 LinuxTest rc.local[2148]: <30>Jan  2 14:25:34 LinuxTest rc.local[2148]: <30>Jan  2 14:25:33 LinuxTest rc.local[2148]: <38>Jan  2 14:25:33 LinuxTest snort[2855]: [1:2009358:5] ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine) [Classification: Web Application Attack] [Priority: 1] {TCP} 192.168.172.222:54870 -> 192.168.1.189:80

	}
	return;
}

#Main Function
$syslogd = IO::Socket::INET->new(Proto=>'udp', LocalPort=>$syslogd_port) || die "Cannot create Socket!\n";
while (1) {
	undef($syslog_content);
	$syslogd->recv($syslog_content, 10000, 0);
	open(DEBUGFILE, ">>/root/debug") if ($debug_switch==1);
	print DEBUGFILE "\n------------------------------------------\n" if ($debug_switch==1);
	print DEBUGFILE "original:\n".$syslog_content."\n" if ($debug_switch==1);
	close(DEBUGFILE) if ($debug_switch==1);
	&snort_filter($syslog_content);
}
$syslogd->close();
