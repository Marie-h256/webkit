#!/usr/bin/python
# coding: utf-8
#open source webkit  

import sys
import os
from urllib2 import *
import socket
import time 
import urllib
from mechanize import Browser
import socks
 
# colors
R = "\033[91m"
O = "\033[0m"
G = "\033[32m"
Y = "\033[93m"

wordl = os.path.abspath("files/Wordlists/wordlist.txt") ### You can import your own wordlist #
XSS = os.path.abspath("files/Wordlists/XSS.txt")
LFI = os.path.abspath("files/Wordlists/LFI.txt")
SQL = os.path.abspath("files/Wordlists/SQL.txt")

def Dircheck(URL):

    print Y +"[+]"+ O +" Import Directory check\n"
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reqh = socket.gethostbyname(URL)
    except socket.gaierror:
        sys.exit(R + "[-]"+ O +" Invalid URL, test please remove http(s):// and slashs")
    print G +"[+]"+ O +" IP address : "+reqh
    
    time.sleep(1)
    wl = open(wordl, "r")
    words = wl.readlines()
    dir=5472
    print "====================================="
    print G + "[+]"+ O +" Testing...\n"
    for word in words:
        passw = word.strip("\n")
        try:
            link = "http://"+ URL+ "/" +passw
            req = Request(link)
            urlopen(req)
            print G + "[+]"+ O +" Directory found "+URL+"/"+passw
        except HTTPError:
            dir=dir-1
            pass
        except KeyboardInterrupt:
            print R + "[-]"+ O +" Skipping test"
            break
        sys.stdout.write(G + "[+] "+ O +str(dir)+" remaining tests\r")
        sys.stdout.flush()
        #print col.work + "[+] "+col.end +str(i)+" remaining tests\r"
        
        ## Searching robots.txt and write the results in a txt file ##

    print G + "\n[+]"+ O +" Checking robots.txt"
    br = Browser()
    RB = "http://"+URL+"/robots.txt"
    try:
        f = br.open(RB)
        res = f.read()
        rep = open("report.txt", "a")
        rep.write("Robots.txt : \n")
        rep.write(res)
        rep.close()
    except HTTPError:
        print R + "\n[-]"+ O +" Robots.txt not found"
    time.sleep(1.5)
    print G + "\n[+]"+ O +" Report save in your actual path as report.txt"


def Lficheck(URL):
    print G + "\n[+]"+ O +" Searching potential LFI vulns\n"
    wordlist = open(LFI, "r")
    lfi=311
    for i in wordlist.readlines():
        passw = i.strip("\n")
        try:
            reqlk = "http://"+URL+"/"+passw
            req = Request(reqlk)
            urlopen(req)
            print G +"[+]"+ O + " Potential vuln : "+URL+"/"+passw + "\n"
            report = open("report.txt", "a")
            report.write("\nPotential LFI :"+"\n")
            report.write(reqlk+"\n")
            report.close()
            time.sleep(1)
        except HTTPError:
            lfi=lfi-1
            pass
        except KeyboardInterrupt:
            print R + "[-]"+ O +" Skipping test "
            break
        sys.stdout.write(G + "[+] " + O + str(lfi) +" remaining tests\r")
        sys.stdout.flush()

def Xsscheck(URL):
    ## XSS scan ##

    print Y +"[*]"+ O +"Starting XXS check\n"
    wordlist = open(XSS, "r")
    xss=2368
    for i in wordlist.readlines():
        pXSS = i.strip("\n")
        try:
            reqlk = "http://"+URL+pXSS
            req = Request(reqlk)
            urlopen(req)
            print G +"[+]"+ O +" Potential XSS : "+URL+pXSS
            report = open("report.txt", "a")
            report.write("Potential XSS :"+"\n")
            report.write(reqlk+"\n")
            report.close()
        except HTTPError:
            xss=xss-1
            pass
        except URLError:
            xss=xss-1
            pass
        except httplib.InvalidURL:
            xss=xss-1
            pass
        except ValueError:
            xss=xss-1
            pass
        except httplib.BadStatusLine:
            xss=xss-1
            pass
        except KeyboardInterrupt:
            print (R + "KeyboardInterrupt" + O)
            break
        sys.stdout.write(G + "[+] "+ O + str(xss) + " remaining tests\r")
        sys.stdout.flush()

    ## Trying to extend XSS check with html forms ##

    print G + "[+]" + O + "Trying to get forms for extented xss scan"
    br = Browser()
    br.open("http://"+URL)
    for f in br.forms():
        br.select_form(nr=0)
        br.submit()
    #time.sleep(5)

def Sqlicheck(URL):
    print "====================================="

    ## Basic SQLi check ##

    print G + "[+]" + O + " Searching potential basic SQLi in your URL\n"
    wl = open(SQL, "r")
    sql=1937
    for i in wl.readlines():
        pSQL = i.strip("\n")
        try:
            reqlk = "http://"+URL+"/"+pSQL+"'"
            req = Request(reqlk)
            re = urlopen(req)
            sqlr = re.read()
            #print col.work+"[+]"+col.end+" Potential SQLi : "+URL+pSQL
            if "error in your SQL syntax" in sqlr:
                print G + "[+]"+ O + " SQLi found at : "+reqlk
                report = open("report.txt", "a")
                report.write("\nSQLi found :"+"\n")
                report.write(reqlk+"\n")
                report.close()
            elif "mysql_fetch_array()" in sqlr:
                print G + "[+]"+ O + " SQLi found at : "+reqlk
                report = open("report.txt", "a")
                report.write("\nSQLi found :"+"\n")
                report.write(reqlk+"\n")
                report.close()
            elif "mysql_fetch" in sqlr:
                print G + "[+]"+ O + " SQLi found at : "+reqlk
                report = open("report.txt", "a")
                report.write("\nSQLi found :"+"\n")
                report.write(reqlk+"\n")
                report.close()
        except HTTPError:
            sql=sql-1
            pass
        except KeyboardInterrupt:
            sys.exit(R + "\nScan finished" + O)
        sys.stdout.write(G + "[+] "+ O + str(sql) + " remaining tests\r")
        sys.stdout.flush()
        #print G + "\n[+]"+ O +" Report save in your actual path as report.txt"


## Define Proxy section ##  

s = socks.socksocket()
s.set_proxy(socks.SOCKS5, "localhost")

def Proxydircheck(URL):
    print Y +"[+]"+ O +" Import Directory check\n"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reqh = socket.gethostbyname(URL)
    except socket.gaierror:
        sys.exit(R + "[-]"+ O +" Invalid URL, test please remove http(s):// and slashs")
        print G +"[+]"+ O +" IP address : "+reqh

    time.sleep(1)
    wl = open(wordl, "r")
    words = wl.readlines()
    dir=5472
    print "====================================="
    print G + "[+]"+ O +" Testing...\n"
    for word in words:
        passw = word.strip("\n")
        try:
            link = "http://"+ URL+ "/" +passw
            req = Request(link)
            urlopen(req)
            print G + "[+]"+ O +" Directory found "+URL+"/"+passw
        except HTTPError:
            dir=dir-1
            pass
        except KeyboardInterrupt:
            print R + "[-]"+ O +" Skipping test"
            break
            sys.stdout.write(G + "[+] "+ O +str(dir)+" remaining tests\r")
            sys.stdout.flush()
            #print col.work + "[+] "+col.end +str(i)+" remaining tests\r"

        ## Searching robots.txt and write the results in a txt file ##

    print G + "\n[+]"+ O +" Checking robots.txt"
    br = Browser()
    RB = "http://"+URL+"/robots.txt"
    try:
        f = br.open(RB)
        res = f.read()
        rep = open("report.txt", "a")
        rep.write("Robots.txt : \n")
        rep.write(res)
        rep.close()
    except HTTPError:
        print R + "\n[-]"+ O +" Robots.txt not found"

    time.sleep(1.5)
    print G + "\n[+]"+ O +" Report save in your actual path as report.txt"
