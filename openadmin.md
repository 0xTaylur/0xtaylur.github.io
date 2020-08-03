# OpenAdmin - Hack The Box

![image]({{0xtaylur.github.io}}/assets/openadmin/card.png)

## Summary
OpenAdmin is an easy linux box that includes a small amount of enumeration before discovering an exploit on an OpenNetAdmin servive that'll get me a low user shell. Next, I dig through the internals of the webserver and find credentials to another user. I discover a webpage that has a SSH key of another user that needs to be cracked. The privilege escalation uses nano to grant me access to the root user.