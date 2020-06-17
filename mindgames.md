# TryHackMe Mindgames Writeup

### Challenge Link: [Mindgames] (https://tryhackme.com/room/mindgames)

Mindgames is a hard rated box on TryHackMe. We're tasked with enumerating, gaining initial access, then a somewhat tricky privilege escalation.

## Recon

There wasn't that much enumeration to do since we only found 2 ports open from our NMAP scan.

```markdown
# Nmap 7.80 scan initiated Tue Jun 16 23:26:12 2020 as: nmap -sC -sV -o nmap 10.10.119.23
Nmap scan report for 10.10.119.23
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

We see that port 80 is open, so I decided to run a GoBuster scan to see if we could find anything.