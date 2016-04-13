#!/usr/bin/env python

import sys
import re
import socket
import optparse

options = optparse.OptionParser(usage='%prog -t <IP>', description='SSH configuration scanner')
options.add_option('-t', '--target', type='string', dest='target', help='The target hostname / IP')
options.add_option('-p', '--port', type='string', dest='port', default='22', help='Port of the SSH')
options.add_option("-v", action="store_true", dest="verbose", help="Verbose, show all information")
opts, args = options.parse_args()

class bcolours:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def banner():
    banner = bcolours.OKBLUE + """
       _____ _____  __  __ _____
      / ___// ___/ / / / // ___/ _____ ____ _ ____   ____   ___   _____
      \__ \ \__ \ / /_/ / \__ \ / ___// __ `// __ \ / __ \ / _ \ / ___/
     ___/ /___/ // __  / ___/ // /__ / /_/ // / / // / / //  __// /
    /____//____//_/ /_/ /____/ \___/ \__,_//_/ /_//_/ /_/ \___//_/
                                                    -@viljoenivan
            """ + bcolours.ENDC
    return banner

def connect(ip, port):
    try:
        sock = socket.create_connection((ip, port),5)
        return sock
    except socket.timeout:
        print(bcolours.FAIL + '[Error] Failed to connect...Timeout' + bcolours.ENDC)
        return False
    except socket.error as e:
        if e.errno == 61:
            print(bcolours.FAIL + '[Error] Connection failed! ' + e.strerror + bcolours.ENDC)
            sys.exit(3)
        else:
            print(bcolours.FAIL + '[Error] Failed to connect...' + bcolours.ENDC)
            sys.exit(3)

def get_banner(data):
    print('\n' + bcolours.OKGREEN + '[Info] Banner: ' + data + bcolours.ENDC)

def parser(full_list,weak_list,data,verbose):
    weak_found = False
    for value in full_list:
        find = data.rfind(value)
        if find >= 0:
            if value in weak_list:
                weak_found = True
                print(bcolours.FAIL + '  [Weak] ' + value + ' supported' + bcolours.ENDC)
            elif verbose:
                print('  [Good] ' + value + ' supported')
    if (weak_found == False) and (not verbose):
        print(bcolours.OKBLUE + '  [Info] Nothing found...' + bcolours.ENDC)

def parse_ciphers(data,verbose):
    ciphers = ('3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'aes128-ctr', 'aes192-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com', 'arcfour', 'arcfour128', 'arcfour256', 'blowfish-cbc', 'cast128-cbc', 'chacha20-poly1305@openssh.com')
    weak_ciphers = ('3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se')
    print('\n' + bcolours.OKGREEN + '[Info] Evaluating SSH Ciphers...' + bcolours.ENDC)
    parser(ciphers,weak_ciphers,data,verbose)

def parse_macs(data,verbose):
    macs = ('hmac-md5', 'hmac-md5-96', 'hmac-ripemd160', 'hmac-sha1', 'hmac-sha1-96', 'hmac-sha2-256', 'hmac-sha2-512', 'umac-64', 'umac-128', 'hmac-md5-etm@openssh.com', 'hmac-md5-96-etm@openssh.com', 'hmac-ripemd160-etm@openssh.com', 'hmac-sha1-etm@openssh.com', 'hmac-sha1-96-etm@openssh.com', 'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'umac-64-etm@openssh.com', 'umac-128-etm@openssh.com', 'arcfour', 'arcfour128', 'arcfour256')
    weak_macs = ('hmac-md5', 'hmac-md5-96', 'hmac-sha1-96', 'arcfour', 'arcfour128', 'arcfour256')
    print('\n' + bcolours.OKGREEN + '[Info] Evaluating SSH MAC Algorithms...' + bcolours.ENDC)
    parser(macs,weak_macs,data,verbose)

def parse_kex(data,verbose):
    kexs = ('curve25519-sha256@libssh.org', 'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group-exchange-sha256', 'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521', 'ecdsa-sha2-nistp256-cert-v01@openssh.com', 'ecdsa-sha2-nistp384-cert-v01@openssh.com', 'ecdsa-sha2-nistp521-cert-v01@openssh.com')
    #weak_kex = ('diffie-hellman-group1-sha1', 'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group14-sha1')
    weak_kex = ()
    print('\n' + bcolours.OKGREEN + '[Info] Evaluating SSH KEX Algorithms...' + bcolours.ENDC)
    parser(kexs,weak_kex,data,verbose)

def parse_compression(data,verbose):
    if ((data.rfind("zlib@openssh.com")) >= 0):
        print('\n' + bcolours.OKGREEN + '[Info] Compression is enabled...' + bcolours.ENDC)

def get_recv_data(ip,port,verbose):
    sock = connect(ip, port)
    get_banner(sock.recv(50).split('\n')[0])
    sock.send('SSH-2.0-7331SSH\r\n')
    sock_recv = sock.recv(984)
    parse_ciphers(sock_recv,verbose)
    parse_macs(sock_recv,verbose)
    parse_kex(sock_recv,verbose)
    parse_compression(sock_recv,verbose)

def close_connection(sock):
    sock.close()

def main():
    try:
        print banner()
        opts, args = options.parse_args()
        if len(sys.argv) <= 1:
            options.print_help()
            return

        target = opts.target
        port = opts.port
        verbose = opts.verbose

        if target:
            get_recv_data(target,port,verbose)
        else:
            print(bcolours.OKBLUE + '  [Warning] No target specified...' + bcolours.ENDC)
            sys.exit(0)

    except KeyboardInterrupt:
        print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
        sys.exit(3)

if __name__ == '__main__':
	main()
