#SSHscan
Firstly, this script makes use of [Paramiko](https://github.com/paramiko/paramiko "Paramiko"), so it will have to be installed before hand..

This was made to scan for 
* Weak CBC Ciphers
* Weak MAC Algorithms
* Authentication methods supported

No other requirements are needed, only Paramiko.

##Installation
```
git clone https://github.com/paramiko/paramiko.git
cd paramiko
python setup.py install
git clone https://github.com/ivanvza/sshscan.git
```

##Sample Usage
```
$ ./sshscan.py

   _____ _____  __  __ _____
  / ___// ___/ / / / // ___/ _____ ____ _ ____   ____   ___   _____
  \__ \ \__ \ / /_/ / \__ \ / ___// __ `// __ \ / __ \ / _ \ / ___/
 ___/ /___/ // __  / ___/ // /__ / /_/ // / / // / / //  __// /
/____//____//_/ /_/ /____/ \___/ \__,_//_/ /_//_/ /_/ \___//_/
                                                -@viljoenivan

Usage: sshscan.py -i <IP>

SSH configuration scanner

Options:
  -h, --help            show this help message and exit
  -i IP, --IP=IP        The hostname / IP
  -p PORT, --port=PORT  Port of the SSH
  -v                    Verbose, show all information
```

##Sample Output

```
 $ ./sshscan.py -i localhost -v


   _____ _____  __  __ _____
  / ___// ___/ / / / // ___/ _____ ____ _ ____   ____   ___   _____
  \__ \ \__ \ / /_/ / \__ \ / ___// __ `// __ \ / __ \ / _ \ / ___/
 ___/ /___/ // __  / ___/ // /__ / /_/ // / / // / / //  __// /
/____//____//_/ /_/ /____/ \___/ \__,_//_/ /_//_/ /_/ \___//_/
                                                -@viljoenivan

[Info] Connecting to: localhost:22...
[Success] Connection to localhost:22 established...

[Info] Banner: SSH-2.0-OpenSSH

[Info] Testing SSH Ciphers...
  [Weak] 3des-cbc supported
  [Rejected] 3des-cbc
  [Weak] aes128-cbc supported
  [Rejected] aes128-cbc
  [Weak] aes192-cbc supported
  [Rejected] aes192-cbc
  [Weak] aes256-cbc supported
  [Rejected] aes256-cbc
  [Accepted] arcfour supported
  [Rejected] arcfour
  [Weak] blowfish-cbc supported
  [Rejected] blowfish-cbc
  [Weak] cast128-cbc supported
  [Rejected] cast128-cbc
  [Accepted] twofish-cbc supported
  [Rejected] twofish-cbc
  [Accepted] twofish128-cbc supported
  [Rejected] twofish128-cbc
  [Accepted] twofish192-cbc supported
  [Rejected] twofish192-cbc
  [Accepted] twofish256-cbc supported
  [Rejected] twofish256-cbc
  [Accepted] cast128-12-cbc@ssh.com supported
  [Rejected] cast128-12-cbc@ssh.com
  [Accepted] des-cbc@ssh.com supported
  [Rejected] des-cbc@ssh.com
  [Accepted] seed-cbc@ssh.com supported
  [Rejected] seed-cbc@ssh.com
  [Accepted] rijndael-cbc@ssh.com supported
  [Rejected] rijndael-cbc@ssh.com

[Info] Testing SSH Mac algorithms...
  [Weak] hmac-md5 supported
  [Rejected] hmac-md5
  [Weak] hmac-md5-96 supported
  [Rejected] hmac-md5-96
  [Accepted] hmac-sha1supported
  [Rejected] hmac-sha1
  [Weak] hmac-sha1-96 supported
  [Rejected] hmac-sha1-96
  [Accepted] hmac-sha256@ssh.comsupported
  [Rejected] hmac-sha256@ssh.com
  [Accepted] hmac-sha256-96@ssh.comsupported
  [Rejected] hmac-sha256-96@ssh.com

[Info] Testing authentication methods supported...
  [Info] publickey supported
  [Warning] keyboard-interactive supported
```
