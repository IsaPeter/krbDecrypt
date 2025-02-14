#!/usr/bin/env python3
# NOTE: this script was created for educational purposes to assist learning about kerberos tickets.  
#   Likely to have a few bugs that cause it to fail to decrypt some TGT or Service tickets.
#
# Recommended Instructions:
#   Obtain valid kerberos tickets using Rubeus or mimikatz "sekurlsa::tickets /export"
#   Optionally convert tickets to ccache format using kekeo "misc::convert ccache <ticketName.kirbi>"
#   Obtain appropriate aes256 key using dcsync (krbtgt for TGT or usually target computer account for Service Ticket)
#   Run this script to decrypt:
#     ./decryptKerbTicket.py -k 5c7ee0b8f0ffeedbeefdeadbeeff1eefc7d313620feedbeefdeadbeefafd601e -t ./Administrator@TESTLAB.LOCAL_krbtgt~TESTLAB.LOCAL@TESTLAB.LOCAL.ccaches 
#     ./decryptKerbTicket.py -k 64aed4bbdac65342c94cf8db9522ca5a73a3f3fb4b6fdd4b7b332a6e98d10760 -t ./ASK_cifs-box1.testlab.local.kirbi

import struct, argparse, sys
from binascii import unhexlify,hexlify
from datetime import datetime

from pyasn1.codec.der import encoder, decoder
from pyasn1.type.univ import noValue

from impacket.krb5.ccache import CCache
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.constants import EncryptionTypes
from impacket.krb5.pac import PACTYPE, VALIDATION_INFO

from impacket.krb5.asn1 import AP_REQ, AS_REP, TGS_REQ, Authenticator, TGS_REP, seq_set, seq_set_iter, PA_FOR_USER_ENC, \
    Ticket as TicketAsn1, EncTGSRepPart, EncTicketPart, AD_IF_RELEVANT, Ticket as TicketAsn1, KRB_CRED, EncKrbCredPart
from impacket.krb5.ccache import CCache, Header, Credential, Times, CountedOctetString, Principal, Ticket
from impacket.krb5.keytab import KeyBlock
from impacket.krb5 import types

class SecurityIdentifiers():
    """Implemented from: https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers"""
    def __init__(self):
        self.secid = {"1" : "Dialup",
                      "113" : "Local Account",
                      "114" : "Local Admin",
                      "2" : "Network",
                      "3" : "Batch",
                      "4" : "Interactive",
                      "6" : "Service",
                      "7" : "Anonymous Logon",
                      "8" : "Proxy",
                      "9" : "Enterprise Domain Controllers",
                      "10" : "Self",
                      "11" : "Authenticated Users",
                      "12" : "Restricted Code",
                      "13" : "Terminal Server User",
                      "14" : "Remote Interactive Logon","15" : "This Organization","17" : "IUSR","18" : "System (LocalSystem)","19" : "NT Authority(LocalService)","20" : "Network Service","500" : "Administrator","501" : "Guest","502" : "KRBTGT","512" : "Domain Admins","513" : "Domain Users","514" : "Domain Guests","515" : "Domain Computers","516" : "Domain Controllers","517" : "Cert Publishers","518" : "Schema Admins","519" : "Enterprise Admins","520" : "Group Policy Creator Owners","521" : "Read-only Domain Controllers","522" : "Clonable Controllers","525" : "Protected Users","526" : "Key Admins","527" : "Enterprise Key Admins","544" : "Administrators","545" : "Users","546" : "Guests","547" : "Power Users","548" : "Account Operators","549" : "Server Operators","550" : "Print Operators","551" : "Backup Operators","552" : "Replicators","553" : "RAS and IAS Servers","554" : "Pre-Windows 2000 Compatible Access","555" : "Remote Desktop Users","557" : "Incoming Forest Trust Builders","558" : "Performance Monitor Users","559" : "Performance Log Users","560" : "Windows Authorization Access Group","561" : "Terminal Server License Servers","562" : "Distributed COM Users","568" : "IIS_IUSRS","569" : "Cryptographic Operators","571" : "Allowed RODC Password Replication Group","572" : "Denied RODC Password Replication Group","573" : "Event Log Readers","574" : "Certificate Service DCOM Access","575" : "RDS Remote Access Servers","576" : "RDS Endpoint Servers","577" : "RDS Management Servers","578" : "Hyper-V Administrators","579" : "Access Control Assistance Operators","580" : "Remote Management Users",}
    def translate(self,rid):
        if str(rid) in self.secid:
            return self.secid[str(rid)]
        else:
            return None


class UACPropertyFlags():
    """Implemented from: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties"""
    def __init__(self):
        self.flags = {
            1 : "SCRIPT",
            2 : "ACCOUNTDISABLE",
            8 : "HOMEDIR_REQUIRED",
            16 : "LOCKOUT",
            32 : "PASSWD_NOTREQD",
            64 : "PASSWD_CANT_CHANGE",
            128 : "ENCRYPTED_TEXT_PWD_ALLOWED",
            256 : "TEMP_DUPLICATE_ACCOUNT",
            512 : "NORMAL_ACCOUNT",
            2048 : "INTERDOMAIN_TRUST_ACCOUNT",
            4096 : "WORKSTATION_TRUST_ACCOUNT",
            8192 : "SERVER_TRUST_ACCOUNT",
            65536 : "DONT_EXPIRE_PASSWORD",
            131072 : "MNS_LOGON_ACCOUNT",
            262144 : "SMARTCARD_REQUIRED",
            524288 : "TRUSTED_FOR_DELEGATION",
            1048576 : "NOT_DELEGATED",
            2097152 : "USE_DES_KEY_ONLY",
            4194304 : "DONT_REQ_PREAUTH",
            8388608 : "PASSWORD_EXPIRED",
            16777216 : "TRUSTED_TO_AUTH_FOR_DELEGATION",
            67108864 : "PARTIAL_SECRETS_ACCOUNT"
        }
    def translate(self, number):
        keys = list(self.flags.keys())
        # Create a revese key list
        keys.reverse()
        flags = []
        counter = 0
        for k in keys:
            if counter + k <= number:
                flags.append(self.flags[k])
                counter += k
        return ', '.join(flags)        
        


class KerberosTicketInfo():
    def __init__(self):
        self.client = ""
        self.server = ""
        self.domain_name = ""
        self.signed_user = ""
        self.ticket_type = "" # TGT / TGS
        self.enc_type_number = None
        self.enc_type = ""
        self.username = ""
        self.auth_time = None
        self.start_time = None
        self.end_time = None
        self.renew = None
        self.pac = {"EffectiveName" : "",
                    "FullName" : "",
                    "LogonScript" : "",
                    "ProfilePath" : "",
                    "HomeDirectory" : "",
                    "HomeDirectoryDrive" : "",
                    "LogonCount" : "",
                    "BadPasswordCount" : "",
                    "UserId" : "",
                    "UserSid": "" ,
                    "PrimaryGroupId" : "",
                    "GroupCount" : "",
                    "GroupIds" : "",
                    "UserFlags" : "",
                    "UserSessionKey" : "",
                    "LogonServer" : "",
                    "LogonDomainName" : "",
                    "LogonDomainId" : "",
                    "LMKey" : "",
                    "UserAccountControl" : "",
                    "SubAuthStatus" : "",
                    "LastSuccessfulILogon" : "",
                    "LastFailedILogon" : "",
                    "FailedILogonCount" : "",
                    "Reserved3" : "",
                    "SidCount" : "",
                    "ExtraSids" : "",
                    "ResourceGroupDomainSid" : "",
                    "ResourceGroupCount" : "",
                    "ResourceGroupIds" : ""}
        
        # Implemented from: https://www.iana.org/assignments/kerberos-parameters/kerberos-parameters.xhtml#kerberos-parameters-1
        self.enc_type_dict = {
            1 : "des-cbc-crc",
            2 : "des-cbc-md4",
            3 : "des-cbc-md5",
            5 : "des3-cbc-md5",
            7 : "des3-cbc-sha1",
            9 : "dsaWithSHA1-CmsOID",
            10 : "md5WithRSAEncryption-CmsOID",
            11 : "sha1WithRSAEncryption-CmsOID",
            12 : "rc2CBC-EnvOID",
            13 : "rsaEncryption-EnvOID",
            14 : "rsaES-OAEP-ENV-OID",
            15 : "des-ede3-cbc-Env-OID",
            16 : "des3-cbc-sha1-kd",
            17 : "aes128-cts-hmac-sha1-96",
            18 : "aes256-cts-hmac-sha1-96",
            19 : "aes128-cts-hmac-sha256-128",
            20 : "aes256-cts-hmac-sha384-192",
            23 : "rc4-hmac ",
            24 : "rc4-hmac-exp",
            25 : "camellia128-cts-cmac",
            26 : "camellia256-cts-cmac",
        }

    # set the encryption type from a dictionary defined in the init
    def set_enc_type_by_number(self, enc_number):
        if type(1) == type(enc_number):
            self.enc_type_number = enc_number
        else:
            try:
                self.enc_type_number = int(enc_number)
            except Exception as e:
                print("[!] ", e)
                sys.exit(1)
        
        self.enc_type = self.enc_type_dict[self.enc_type_number]
    
    # Set the client srting and calculate the username an d the domain 
    def set_client(self, client_string):
        self.client = client_string
        if "@" in client_string:
            parts = client_string.split("@",1)
            self.username = parts[0]
            self.domain_name = parts[1]

    # Set the server string and determined the signed user and the type of the ticket
    def set_server(self, server_string):
        self.server = server_string
        if "/" in server_string:
            self.signed_user = server_string.split("/")[0]
            if self.signed_user.lower() == "krbtgt":
                self.ticket_type = "TGT"
            else:
                self.ticket_type = "TGS" 

    def convert_from_epoch(self, epoch):
        datetime_obj=datetime.fromtimestamp(epoch)
        datetime_string=datetime_obj.strftime("%Y.%m.%d %H:%M:%S" )
        return datetime_string
    
    def load_credentials_data(self, credentials):
        # Set the time values
        self.auth_time = self.convert_from_epoch(credentials[0].header["time"]["authtime"])
        self.start_time =  self.convert_from_epoch(credentials[0].header["time"]["starttime"])
        self.end_time =  self.convert_from_epoch(credentials[0].header["time"]["endtime"])
        self.renew =  self.convert_from_epoch(credentials[0].header["time"]["renew_till"])

    def get_data_dict(self):
        return {"client": self.client,
                "server" : self.server,
                "domain_name" : self.domain_name,
                "signed_user": self.signed_user,
                "ticket_type" : self.ticket_type,
                "enc_type_number" : self.enc_type_number,
                "enc_type" : self.enc_type,
                "username" : self.username, 
                "auth_time" : self.auth_time,
                "start_time" : self.start_time,
                "end_time" : self.end_time,
                "renew":self.renew,
                "pac":self.pac}

    def load_from_data_dict(self, data_dict):
        for k,v in data_dict.items():
            if k in self.__dict__:
                if v != None and v != "":
                    self.__dict__[k] = v

    def print_auth_data(self):
        print("[+] AUTHORIZATION DATA:\n")

        print("Client:\t\t",self.client)
        print("Server:\t\t",self.server)
        print("Domain Name:\t",self.domain_name)
        print("Signet User:\t",self.signed_user)
        print("Ticket Type:\t",self.ticket_type)
        print("Encryption:\t",self.enc_type)
        print("Username:\t", self.username)
        print("Auth Time:\t", self.auth_time)
        print("Start Time:\t", self.start_time)
        print("End Time:\t", self.end_time)
        print("Renew Time:\t", self.renew)
        print("\n")

    def print_pac_data(self):
        print("[+] PAC DATA:\n")
        for k,v in self.pac.items():
            # Convert domain id to user friendly and readable.
            if k == "LogonDomainId":
                sub_authority = v["SubAuthority"]
                domain_sid = "S-1-5-"+"-".join([str(s) for s in sub_authority])
                delimeter = " "*(25-(len("DomainSid:")+1))
                print("DomainSid:",delimeter,domain_sid)
            # Convert group ID's to a list
            elif k == "GroupIds":
                gids = [g["RelativeId"] for g in v]
                delimeter = " "*(25-(len("GroupIds:")+1))
                print("GroupIds:",delimeter,gids)
                ident = SecurityIdentifiers()
                friendly_gids = [ident.translate(g)+" ("+str(g)+")" for g in gids]
                delimeter = " "*(25-(len("FriendlyGID:")+1))
                print("FriendlyGID:",delimeter,', '.join(friendly_gids))
            elif k == "LastSuccessfulILogon":
                delimeter = " "*(25-(len(k)+2))
                print("LastSuccessfulILogon:",delimeter,v["dwLowDateTime"])
            elif k == "LastFailedILogon":
                delimeter = " "*(25-(len(k)+2))
                print("LastFailedILogon:",delimeter,v["dwLowDateTime"])
            elif k == "UserAccountControl":
                delimeter = " "*(25-(len(k)+2))
                uac = UACPropertyFlags()
                a = uac.translate(int(v))
                print("UserAccountControl:",delimeter,a)
            elif k == "ExtraSids":
                delimeter = " "*(25-(len(k)+2))
                sid = "S-1-5-"
                sidlist = [] 
                for ex in self.pac["ExtraSids"]:
                    lista = ex["Sid"]["SubAuthority"]
                    sidlist.append(sid+"-".join([ str(l) for l in lista]))
                print("ExtraSids:",delimeter,', '.join(sidlist))
            elif k == "UserSid":
                sub_authority = self.pac["LogonDomainId"]["SubAuthority"]
                domain_sid = "S-1-5-"+"-".join([str(s) for s in sub_authority])
                delimeter = " "*(25-(len(k)+2))
                usid = domain_sid +"-" + str(self.pac["UserId"])
                print("UserSid:",delimeter,usid)
            else:
                delimeter = " "*(25-(len(k)+1))

                if v == '':
                    print(f"{k}:{delimeter}","N/A")
                else:
                    print(f"{k}:{delimeter}",v)


# KrbCredCCache Class copied from: https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/krbcredccache.py 
# Needed to support kirbi2ccache() function
class KrbCredCCache(CCache):
    """
    This is just the impacket ccache, but with an extra function to create it from
    a Krb Cred Ticket and ticket data
    """
    def fromKrbCredTicket(self, ticket, ticketdata):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = '\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)


        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(ticketdata, 'prealm', 'pname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)

        encASRepPart = ticketdata

        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)

        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0

        credential['key'] = KeyBlock()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = str(encASRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])

        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till']))

        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags

        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(ticket.clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = ''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

def p(x):
    return struct.pack('<L',x)

# https://msdn.microsoft.com/en-us/library/cc237954.aspx
def processPacInfoBuffer(pacData):
    dword = 8 # 4 bytes
    bufferList = []
    for i in range(0,32,dword):
        bufferStr = pacData[i:i+dword]
        bufferInt = int(bufferStr,16)
        bufferStr = hexlify(p(bufferInt))
        bufferInt = int(bufferStr,16)
        bufferList.append(bufferInt)
    return bufferList

def processTicket(ticket, key, verbose):
    ticketCreds = ticket.credentials[0]

    # Create a new calss to organize and use the given informations
    info = KerberosTicketInfo()

    # obtain the ciphertext
    cipherText = ticketCreds.ticket['data']
    
    # TGT/TGS tickets contain the SPN that they are applied to (e.g. krbtgt/testlab.local@testlab.local), which will change the location of the PAC 
    spnLength = len(ticketCreds['server'].realm['data'])

    for i in ticketCreds['server'].toPrincipal().components:
        spnLength += len(i)

    decryptOffset = 128 + (2 * spnLength) # 2x is due to hexlified formatting
    decryptOffset -= 8 # python3 fix for CountedOctetString
    encryptedTicket = hexlify(cipherText)[decryptOffset:]
    
    # Add the client and the server values into the class instead
    info.set_client(ticketCreds['client'].prettyPrint().decode())
    info.set_server(ticketCreds['server'].prettyPrint().decode())
    
    #print("\tClient: " + ticketCreds['client'].prettyPrint().decode())
    #print("\tServer: " + ticketCreds['server'].prettyPrint().decode())

    print("[+] DECRYPTING TICKET")
    encType = ticketCreds['key']['keytype'] # determine encryption type that ticket is using

    # Add the encryption type to the info
    info.set_enc_type_by_number(encType)

    # create encryption key based on type that ticket uses
    try:
        if encType == EncryptionTypes.aes256_cts_hmac_sha1_96.value:
            key = Key(encType, unhexlify(key))
        elif encType == EncryptionTypes.aes128_cts_hmac_sha1_96.value:
            key = Key(encType, unhexlify(key))
        elif encType == EncryptionTypes.rc4_hmac.value:
            key = Key(encType, unhexlify(key))
        else:
            raise Exception('Unsupported enctype 0x%x' % encType)
    except Exception as e:
        print("[!] Error creating encryption key\n[!] Make sure you specified the correct key, your ticket is using type: " + str(encType))
        print(e)
        sys.exit(1)
    cipher = _enctype_table[encType]

    try:
        decryptedText = cipher.decrypt(key, 2, unhexlify(encryptedTicket))
    except Exception as e:
        print("[!] Error \"" + str(e) + "\" occured while decrypting ticket.  Attempting quick fix...")
        try:
            encryptedTicket = hexlify(cipherText)[decryptOffset+4:]
            decryptedText = cipher.decrypt(key, 2, unhexlify(encryptedTicket))
            print("[+] Decryption successful, quick fix worked")
        except Exception as e2:
            print("[!] Error \"" + str(e2) + "\" Quick fix failed. Make sure that correct decryption key is specified")
            sys.exit(1)
    


    decodedEncTicketPart = decoder.decode(decryptedText)[0]
    
    
    pacData = decodedEncTicketPart['field-9'][0]['field-1']
    decAuthData = decoder.decode(pacData)[0][0]['field-1']
    pacBuffers = PACTYPE(decAuthData.asOctets())
    pacBuffer = pacBuffers['Buffers']
    pacBufferHex = hexlify(pacBuffer)

    pacInfoList = processPacInfoBuffer(pacBufferHex)
    authDataType = pacInfoList[0]
    authDataLength = pacInfoList[1]
    authDataOffset = pacInfoList[2]
    authDataEnd = (authDataLength * 2) - 40 # subtract out the getData() part
    offsetStart = 24 + authDataOffset*2
    authDataHex = pacBufferHex[offsetStart:offsetStart+authDataEnd]

    
    if authDataType != 1:
        raise Exception("[!] PAC Buffer Sanity check failed.  Excpected 1, Actual " + str(authDataType))
        
    finalValidationInfo = VALIDATION_INFO()
    finalValidationInfo.fromStringReferents(unhexlify(authDataHex))
    #finalValidationInfo.dump()
    info.pac["EffectiveName"] = finalValidationInfo["Data"]["EffectiveName"]
    info.pac["FullName"] = finalValidationInfo["Data"]["FullName"]
    info.pac["LogonScript"] = finalValidationInfo["Data"]["LogonScript"]
    info.pac["ProfilePath"] = finalValidationInfo["Data"]["ProfilePath"]
    info.pac["HomeDirectory"] = finalValidationInfo["Data"]["HomeDirectory"]
    info.pac["HomeDirectoryDrive"] = finalValidationInfo["Data"]["HomeDirectoryDrive"]
    info.pac["LogonCount"] = finalValidationInfo["Data"]["LogonCount"]
    info.pac["BadPasswordCount"] = finalValidationInfo["Data"]["BadPasswordCount"]
    info.pac["UserId"] = finalValidationInfo["Data"]["UserId"]
    info.pac["PrimaryGroupId"] = finalValidationInfo["Data"]["PrimaryGroupId"]
    info.pac["GroupCount"] = finalValidationInfo["Data"]["GroupCount"]
    info.pac["GroupIds"] = finalValidationInfo["Data"]["GroupIds"]
    info.pac["UserFlags"] = finalValidationInfo["Data"]["UserFlags"]
    info.pac["UserSessionKey"] = finalValidationInfo["Data"]["UserSessionKey"]
    info.pac["LogonServer"] = finalValidationInfo["Data"]["LogonServer"]
    info.pac["LogonDomainName"] = finalValidationInfo["Data"]["LogonDomainName"]
    info.pac["LogonDomainId"] = finalValidationInfo["Data"]["LogonDomainId"]
    info.pac["LMKey"] = finalValidationInfo["Data"]["LMKey"]
    info.pac["UserAccountControl"] = finalValidationInfo["Data"]["UserAccountControl"]
    info.pac["SubAuthStatus"] = finalValidationInfo["Data"]["SubAuthStatus"]
    info.pac["LastSuccessfulILogon"] = finalValidationInfo["Data"]["LastSuccessfulILogon"]
    info.pac["LastFailedILogon"] = finalValidationInfo["Data"]["LastFailedILogon"]
    info.pac["FailedILogonCount"] = finalValidationInfo["Data"]["FailedILogonCount"]
    info.pac["Reserved3"] = finalValidationInfo["Data"]["Reserved3"]
    info.pac["SidCount"] = finalValidationInfo["Data"]["SidCount"]
    info.pac["ExtraSids"] = finalValidationInfo["Data"]["ExtraSids"]
    info.pac["ResourceGroupDomainSid"] = finalValidationInfo["Data"]["ResourceGroupDomainSid"]
    info.pac["ResourceGroupCount"] = finalValidationInfo["Data"]["ResourceGroupCount"]
    info.pac["ResourceGroupIds"] = finalValidationInfo["Data"]["ResourceGroupIds"]

    """
    print("\n\n"+"#"*100)
    print(finalValidationInfo["Data"]["EffectiveName"])
    for k in finalValidationInfo["Data"].fields.keys():
        print(k)
    """
    
    # return the kerberos info file
    return info

# kirbi2ccache function copied from https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py
def kirbi2ccache(kirbifile):
    with open(kirbifile, 'rb') as infile:
        data = infile.read()
    creds = decoder.decode(data, asn1Spec=KRB_CRED())[0]
    # This shouldn't be encrypted normally
    if creds['enc-part']['etype'] != 0:
        raise Exception('Ticket info is encrypted with cipher other than null')
    enc_part = decoder.decode(creds['enc-part']['cipher'], asn1Spec=EncKrbCredPart())[0]
    tinfo = enc_part['ticket-info']
    ccache = KrbCredCCache()
    # Enumerate all
    for i, tinfo in enumerate(tinfo):
        ccache.fromKrbCredTicket(creds['tickets'][i], tinfo)
    return ccache

def loadTicket(ticket, verbose):
    try:
        ticket = CCache.loadFile(ticket)
    except Exception as e:
        print("ERROR: unable to load specified ticket. Make sure it is in ccache format.")
        print(e)
        sys.exit(1)
    print("\n[+] TICKET LOADED SUCCESSFULLY")
    if verbose:
        print('')
        ticket.prettyPrint()

    return ticket

def parseArgs():
    parser = argparse.ArgumentParser(add_help=True, description="Attempts to decrypt kerberos TGT or Service Ticket and display authorization data")
    parser.add_argument('-t','--ticket', required=True, help='location of kerberos ticket file (ccache or kirbi format)')
    parser.add_argument('-k','--key', required = True, action="store", help='decryption key (ntlm/aes128/aes256)')
    parser.add_argument('-v','--verbose', action='store_true', help='Increase verbosity')

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        print("\nExample:\n\t./decryptKerbTicket.py -k 5c7ee0b8f0ffeedbeefdeadbeeff1eefc7d313620feedbeefdeadbeefafd601e -t ./Administrator@TESTLAB.LOCAL_krbtgt~TESTLAB.LOCAL@TESTLAB.LOCAL.ccaches")
        sys.exit(1)

    args = parser.parse_args()
    return args

def main():
    args = parseArgs()
    if (args.ticket.upper().endswith(".KIRBI")):
        ticket = kirbi2ccache(args.ticket)
    else:
        ticket = loadTicket(args.ticket, args.verbose)
    

    # Create a new Ticket Info Class
    tktinfo = KerberosTicketInfo()
    tktinfo.load_credentials_data(ticket.credentials)

    tkt = processTicket(ticket, args.key, args.verbose)
    tktinfo.load_from_data_dict(tkt.get_data_dict())
    
    tktinfo.print_auth_data()
    tktinfo.print_pac_data()
    
    

if __name__ == '__main__':
    main()
