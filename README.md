# fatwinnie
Fat Winnie, a Syslog Relay dedicated to receiving Snort's Syslog alerts, sending them out through SMTP, and storing them in a MySQL database.



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



The commands below presents the structure of the MySQL database being used.

mysql> CREATE DATABASE security;

mysql> CREATE TABLE threats (id INT NOT NULL AUTO_INCREMENT, s_time VARCHAR(20), sensor VARCHAR(20), engine VARCHAR(20), threat VARCHAR(200), classification VARCHAR(50), priority INT, protocol VARCHAR(11), srcip VARCHAR(20), srcport INT, dstip VARCHAR(20), dstport INT, PRIMARY KEY (id));

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
