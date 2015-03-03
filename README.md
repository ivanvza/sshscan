#SSHscan

This was made to scan for 
* CBC Ciphers
* MAC Algorithms
* Kex Algorithms

Future additions:
* Determine authentication methods.

No other requirements are needed.

##Installation
```
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
  -t TARGET, --target=TARGET
                        The target hostname / IP
  -p PORT, --port=PORT  Port of the SSH
  -v                    Verbose, show all information
```

##Sample Output

```
$ ./sshscan.py -t localhost -v

       _____ _____  __  __ _____
      / ___// ___/ / / / // ___/ _____ ____ _ ____   ____   ___   _____
      \__ \ \__ \ / /_/ / \__ \ / ___// __ `// __ \ / __ \ / _ \ / ___/
     ___/ /___/ // __  / ___/ // /__ / /_/ // / / // / / //  __// /
    /____//____//_/ /_/ /____/ \___/ \__,_//_/ /_//_/ /_/ \___//_/
                                                    -@viljoenivan


[Info] Banner: SSH-2.0-OpenSSH_6.2

[Info] Evaluating SSH Ciphers...
  [Weak] 3des-cbc supported
  [Weak] aes128-cbc supported
  [Weak] aes192-cbc supported
  [Weak] aes256-cbc supported
  [Good] aes128-ctr supported
  [Good] aes192-ctr supported
  [Good] aes256-ctr supported
  [Good] aes128-gcm@openssh.com supported
  [Good] aes256-gcm@openssh.com supported
  [Good] arcfour supported
  [Good] arcfour128 supported
  [Good] arcfour256 supported
  [Weak] blowfish-cbc supported
  [Weak] cast128-cbc supported

[Info] Evaluating SSH MAC Algorithms...
  [Weak] hmac-md5 supported
  [Weak] hmac-md5-96 supported
  [Good] hmac-ripemd160 supported
  [Good] hmac-sha1 supported
  [Weak] hmac-sha1-96 supported
  [Good] hmac-sha2-256 supported
  [Good] hmac-sha2-512 supported
  [Good] umac-64 supported
  [Good] umac-128 supported
  [Good] hmac-md5-etm@openssh.com supported
  [Good] hmac-md5-96-etm@openssh.com supported
  [Good] hmac-ripemd160-etm@openssh.com supported
  [Good] hmac-sha1-etm@openssh.com supported
  [Good] hmac-sha1-96-etm@openssh.com supported
  [Good] hmac-sha2-256-etm@openssh.com supported
  [Good] hmac-sha2-512-etm@openssh.com supported
  [Good] umac-64-etm@openssh.com supported
  [Good] umac-128-etm@openssh.com supported

[Info] Evaluating SSH KEX Algorithms...
  [Good] diffie-hellman-group1-sha1 supported
  [Good] diffie-hellman-group14-sha1 supported
  [Good] diffie-hellman-group-exchange-sha1 supported
  [Good] diffie-hellman-group-exchange-sha256 supported
```
