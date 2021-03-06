# RedDPAPY -> Tool made by the SG Red Team
Retrieve &amp; extract usefull data regarding DPAPI files :
- Chrome : History / Login Data / Visited Websites & Favorites 
- Firefox : Login & Password + History
- VCRD Credentials (Vault) : Extract login/password
- Credentials files protected by DPAPI : Extract login/password
- Masterkeys : Hashcat format & decrypted if pvk file provided

# How to install ?
```
virtualenv --python=/usr/bin/python3.9 dpapy_env
source dpapy_env/bin/activate
pip install -r requirements.txt
```

# Example
![image](https://user-images.githubusercontent.com/9429952/135977567-e7fc25cb-e5ed-4405-90c1-249b1858778d.png)

# Credits
- Jean-Michel Picod (https://github.com/jordanbtucker/dpapick) 
- Benjamin Delpy for the DPAPI research
- Alberto Solino (https://github.com/SecureAuthCorp/impacket)

Some portion of the code may be heavily inspired / borrowed from :
- https://github.com/unode/firefox_decrypt
- https://github.com/SecureAuthCorp/impacket/tree/master/examples
