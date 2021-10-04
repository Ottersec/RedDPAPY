import pathlib

from Core.DPAPYCrypto.CryptoUtils import *
from Core.Dpapy import *
class LocalSearch():
    def __init__(self,options,localPath):
        self.localOutputDir = localPath
        self.allWindowsUsers = []
        if options.decryptlocalall != "":
            self.passwordpath = options.decryptlocalall
        else:
            self.passwordpath = options.decryptlocal
        self.initAllWindowsUsersFromLocalData()

    def initAllWindowsUsersFromLocalData(self):
        # Search for all local masterkey and try to decrypt it
        allLocalMasterKeyDir = locateAllMasterkeyDir(self.localOutputDir)
        for masterkeyKeyPath in allLocalMasterKeyDir:
            tempWinuser = windowsUsers()
            tempWinuser.username = pathlib.Path(masterkeyKeyPath).parent.name
            for sidPath in pathlib.Path(masterkeyKeyPath).iterdir():
                tempWinuser.SID.append(sidPath.name)
                for masterkey in pathlib.Path(sidPath).iterdir():
                    # TODO : Skip the already decrypted masterkey
                    if masterkey.name != "Preferred" and masterkey.name != "BK-TEST"\
                            and "decrypted" not in masterkey.name:
                        tempWinuser.masterkeyLocalPaths.append(masterkey)
            self.allWindowsUsers.append(tempWinuser)
        return

    def decryptAllLocalMasterKey(self):
        with open(self.passwordpath) as f:
            password_list = f.readlines()
        decryptAllMasterKeyWithPassword(self.allWindowsUsers,password_list)
        return