import pathlib
import sqlite3
import Core.DPAPYCrypto.CryptoUtils
from pathlib import Path

def extractDataFirefox(filePath):
    data = None
    try:
        data = Core.DPAPYCrypto.CryptoUtils.decryptLoginsFirefox(filePath)
    except Exception as e:
        print(e)
    return data

def extractAllDataFirefox(allWindowsUsersWLocalPaths):
    atLeastOne = False
    for winUsers in allWindowsUsersWLocalPaths:
        try:
            # Edge case firefox : voir pour les autres fichiers, là on traite que logins.json mais vraiment à l'arrache
            data = extractDataFirefox(Path(winUsers.firefoxLocalPaths[0]).parent)
            writeDataFirefox(data,winUsers)
            atLeastOne = True
        except Exception as e:
            if 0:
                print(e)
    if atLeastOne:
        print("[+] All firefox data formatted and extracted")
    else:
        print("[-] No firefox data extractable for this target")
    return

def writeDataFirefox(data,winUsers,filename=""):
    fp = open(pathlib.Path(winUsers.rootLocalDirTarget / ("Firefox_logins.csv")), "a")
    for entry in data:
        fp.write(entry['url'] + "," + entry["user"] + "," + entry["password"] + "\n")
    fp.close()
    return