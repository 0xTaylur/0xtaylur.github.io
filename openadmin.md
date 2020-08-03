# OpenAdmin - Hack The Box

![image]({{0xtaylur.github.io}}/assets/openadmin/card.png)

## Summary
OpenAdmin is an easy linux box that starts off using an RCE exploit for the OpenNetAdmin service on port 80. Then, I get credentials from a database config that can be used to SSH into the box. I find another web application with a SHA512 hash in the code for a login page. After looking at the webpage I find an encrypted SSH key that needs to be cracked. Once I get the last shell I can run nano as root with sudo and get a root shell.

### Enumeration

A short nmap scan reveals two ports: 22 for SSH, and 80 for http.
![image]({{0xtaylur.github.io}}/assets/openadmin/nmap.png)

The default Ubuntu page is shown when I checkout the webserver.
![image]({{0xtaylur.github.io}}/assets/openadmin/port80.png)

Running a gobuster scan reveals 3 hidden directories.
![image]({{0xtaylur.github.io}}/assets/openadmin/gobuster.png

These 3 directories are static webpages, but I notice a login page on the`/music` page.

### Initial Shell

