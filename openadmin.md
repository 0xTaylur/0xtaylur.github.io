# OpenAdmin - Hack The Box

![image]({{0xtaylur.github.io}}/assets/openadmin/card.png)

## Summary
OpenAdmin is an easy linux box that starts off using an RCE exploit for the OpenNetAdmin service on port 80. Then, I get credentials from a database config that can be used to SSH into the box. I find another web application with a SHA512 hash in the code for a login page. After looking at the webpage I find an encrypted SSH key that needs to be cracked. Once I get the last shell I can run nano as root with sudo and get a root shell.