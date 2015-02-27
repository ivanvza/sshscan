#!/usr/bin/env python

import os
import socket
import sys
import time
import optparse
import paramiko

class bcolours:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

#The log file paramiko is writing too.
#Uncomment it if you want to use it.
#paramiko.util.log_to_file('sshscanner.log')

options = optparse.OptionParser(usage='%prog -i <IP>', description='SSH configuration scanner')
options.add_option('-i', '--IP', type='string', dest='IP', help='The hostname / IP')
options.add_option('-p', '--port', type='string', dest='port', help='Port of the SSH')
options.add_option("-v", action="store_true", dest="verbose", help="Verbose, show all information")

ciphers = ('3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'blowfish-cbc', 'cast128-cbc', 'twofish-cbc', 'twofish128-cbc', 'twofish192-cbc', 'twofish256-cbc', 'cast128-12-cbc@ssh.com', 'des-cbc@ssh.com', 'seed-cbc@ssh.com', 'rijndael-cbc@ssh.com')
weak_ciphers = ('3des-cbc', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'blowfish-cbc', 'cast128-cbc', 'rijndael-cbc@lysator.liu.se')
macs = ('hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'hmac-sha256@ssh.com', 'hmac-sha256-96@ssh.com')
weak_macs = ('hmac-md5', 'hmac-md5-96', 'hmac-sha1-96')
auth_types = ('username', 'key')

def get_hostname(opts):
    if opts.IP:
        hostname = opts.IP
        if hostname.find('@') >= 0:
            username, hostname = hostname.split('@')
    return hostname

def get_port(opts):
    if opts.port:
        port = opts.port
    else:
        port = 22
    return port

def test_weak_ciphers(hostname, port, verbose):
    for cipher in ciphers:
        s = connect(hostname, port)
        t = paramiko_transport_start(s)
        t._preferred_ciphers = ciphers
        t.start_client()
        if cipher in weak_ciphers:
            print(bcolours.FAIL + '  [Weak] ' + cipher + ' supported' + bcolours.ENDC)
        else:
            if verbose:
                print('  [Accepted] ' + cipher + ' supported')
        if verbose:
            print(bcolours.OKBLUE + '  [Rejected] ' + cipher + bcolours.ENDC)
    close_connection(t, s)

def test_weak_macs(hostname, port, verbose):
    for mac in macs:
        s = connect(hostname, port)
        t = paramiko_transport_start(s)
        t._preferred_macs = macs
        t.start_client()
        if mac in weak_macs:
            print(bcolours.FAIL + '  [Weak] ' + mac + ' supported' + bcolours.ENDC)
        else:
            if verbose:
                print('  [Accepted] ' + mac + 'supported')
        if verbose:
            print (bcolours.OKBLUE + '  [Rejected] ' + mac + bcolours.ENDC)
    close_connection(t, s)

def grab_banner(hostname, port):
    s = connect(hostname, port)
    return s.recv(1024)

def connect(hostname, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((hostname, port))
        return sock
    except:
        print(bcolours.FAIL + '[Error] Connection failed! ' + bcolours.ENDC)
        os.exit()
        close_connection(t, sock)

def close_connection(t, sock):
    t.close()
    sock.close()

def paramiko_transport_start(sock):
    return paramiko.Transport(sock)

def auth_methods(hostname, port, verbose):
    s = connect(hostname, port)
    t = paramiko_transport_start(s)
    t.start_client()
    try:
        t.auth_none('')
    except paramiko.BadAuthenticationType, err:
        for auth_type in err.allowed_types:
            if ("password" in auth_type) or ("keyboard" in auth_type):
                print(bcolours.FAIL + '  [Warning] ' + auth_type + ' supported' + bcolours.ENDC)
            else:
                if verbose:
                    print('  [Info] ' + auth_type + ' supported')
    close_connection(t, s)

#MAIN FUNCTION
def main(opts):
    print bcolours.OKBLUE
    print "   _____ _____  __  __ _____                                       "
    print "  / ___// ___/ / / / // ___/ _____ ____ _ ____   ____   ___   _____"
    print "  \__ \ \__ \ / /_/ / \__ \ / ___// __ `// __ \ / __ \ / _ \ / ___/"
    print " ___/ /___/ // __  / ___/ // /__ / /_/ // / / // / / //  __// /    "
    print "/____//____//_/ /_/ /____/ \___/ \__,_//_/ /_//_/ /_/ \___//_/     "
    print "                                                -@viljoenivan      "
    print bcolours.ENDC

    opts, args = options.parse_args()
    if len(sys.argv) <= 1:
        options.print_help()
        return
    else:
        try:
            hostname = get_hostname(opts)
            port = int(get_port(opts))
            print(bcolours.OKGREEN + '[Info] Connecting to: ' + hostname + ':' + str(port) + "..." + bcolours.ENDC)
            connect(hostname, port)
            print(bcolours.OKGREEN + '[Success] Connection to ' + hostname + ':' + str(port) + " established..." + bcolours.ENDC)
            print('\n' + bcolours.OKGREEN + '[Info] Banner: ' + grab_banner(hostname, port) + bcolours.ENDC)
            print(bcolours.OKGREEN + '[Info] Testing SSH Ciphers...' + bcolours.ENDC)
            test_weak_ciphers(hostname, port, opts.verbose)
            print('\n' + bcolours.OKGREEN + '[Info] Testing SSH Mac algorithms...' + bcolours.ENDC)
            test_weak_macs(hostname, port, opts.verbose)
            print('\n' + bcolours.OKGREEN + '[Info] Testing authentication methods supported...' + bcolours.ENDC)
            auth_methods(hostname, port, opts.verbose)
        except:
            sys.exit()

if __name__ == '__main__':
    try:
        main(options)
    except:
        print(bcolours.OKBLUE + '  [Warning] Stopping...' + bcolours.ENDC)
