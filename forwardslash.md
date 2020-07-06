# Forwardslash - Hack The Box

![image]({{0xtaylur.github.io}}/assets/forwardslash/card.png)

## Summary
Forwardslash is a hard linux box that starts off with basic enumerations of vhosts, files, and directories. Using burp to perform a Server-Side Request Forgery (SSRF) vulnerability to access a protected dev directory that can only be accessed through localhost. Once I find credentials and get a shell, I exploit a backup program owned by user `pain` to find more credentials. Finally, I solve a crypto challenge to get root.

