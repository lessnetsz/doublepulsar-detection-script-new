#!/usr/bin/python
# -*- coding: UTF-8 -*-

import threadpool
import sys,os,re
import shutil
import time
import binascii
import socket
import argparse
import struct


    
class MS17_010_SMB:
    def __init__(self,targetFile,output,threadCount=50):
        self.TargetFile = targetFile
        self.OutputFile =  open(output,'w')
        self.ThreadCount = threadCount
        self.port = '445'
        self.timeout = 10
        # Packets
        self.negotiate_protocol_request = binascii.unhexlify("00000085ff534d4272000000001853c00000000000000000000000000000fffe00004000006200025043204e4554574f524b2050524f4752414d20312e3000024c414e4d414e312e30000257696e646f777320666f7220576f726b67726f75707320332e316100024c4d312e325830303200024c414e4d414e322e3100024e54204c4d20302e313200")
        self.session_setup_request = binascii.unhexlify("00000088ff534d4273000000001807c00000000000000000000000000000fffe000040000dff00880004110a000000000000000100000000000000d40000004b000000000000570069006e0064006f007700730020003200300030003000200032003100390035000000570069006e0064006f007700730020003200300030003000200035002e0030000000")
        self.tree_connect_request = binascii.unhexlify("00000060ff534d4275000000001807c00000000000000000000000000000fffe0008400004ff006000080001003500005c005c003100390032002e003100360038002e003100370035002e003100320038005c00490050004300240000003f3f3f3f3f00")
        self.trans2_session_setup = binascii.unhexlify("0000004eff534d4232000000001807c00000000000000000000000000008fffe000841000f0c0000000100000000000000a6d9a40000000c00420000004e0001000e000d0000000000000000000000000000")

        self.OutputFile.write('ip\tport\tsmb_vul\n')
        
    def verify(self,host):
        #print host
        global n
        try:
            # Connect to socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(float(self.timeout) if self.timeout else None)
            s.connect((host, int(self.port)))

            # Send/receive negotiate protocol request
            s.send(self.negotiate_protocol_request)
            s.recv(1024)

            # Send/receive session setup request
            s.send(self.session_setup_request)
            session_setup_response = s.recv(1024)

            # Extract user ID from session setup response
            user_id = session_setup_response[32:34]

            # Replace user ID in tree connect request packet
            modified_tree_connect_request = list(self.tree_connect_request)
            modified_tree_connect_request[32] = user_id[0]
            modified_tree_connect_request[33] = user_id[1]
            modified_tree_connect_request = "".join(modified_tree_connect_request)

            # Send tree connect request
            s.send(modified_tree_connect_request)
            tree_connect_response = s.recv(1024)

            # Extract tree ID from response
            tree_id = tree_connect_response[28:30]

            # Replace tree ID and user ID in trans2 session setup packet
            modified_trans2_session_setup = list(self.trans2_session_setup)
            modified_trans2_session_setup[28] = tree_id[0]
            modified_trans2_session_setup[29] = tree_id[1]
            modified_trans2_session_setup[32] = user_id[0]
            modified_trans2_session_setup[33] = user_id[1]
            modified_trans2_session_setup = "".join(modified_trans2_session_setup)

            # Send trans2 sessions setup request
            s.send(modified_trans2_session_setup)
            final_response = s.recv(1024)

            s.close()

            # Check for 0x51 response to indicate DOUBLEPULSAR infection
            if final_response[34] == "\x51":
                print "[+] [%s] DOUBLEPULSAR SMB IMPLANT DETECTED!!!" % host
                n += 1
                print n
                self.OutputFile.write('%s\t%s\tDOUBLEPULSAR SMB IMPLANT' % (host,self.port))
            else:
                print "[-] [%s] No presence of DOUBLEPULSAR SMB implant" % host
        except Exception,e:
            #print e
            pass

    def Run(self):
        varList = []
        f = open(self.TargetFile,'r')
        for line in f.readlines():
            line = line.strip()
            if line == '':
                continue
            varList.append(line)
        f.close()
        c = len(varList)
        if(c<1):
            return
        if(c<self.ThreadCount):
            self.ThreadCount = c
        #socket.setdefaulttimeout(60)
        pool = threadpool.ThreadPool(self.ThreadCount)
        requests = threadpool.makeRequests(self.verify,varList)
        [pool.putRequest(q) for q in requests]
        pool.wait()
        pool.dismissWorkers(self.ThreadCount,do_join=True)
        self.OutputFile.close()
        print 'Job Finished.'


def Help():
    usage = 'Usage:'+os.path.basename(sys.argv[0]) +' [ip file path]\n'
    print usage


if __name__=='__main__':
    if len(sys.argv)!=2:
        Help()
        exit()
    resultPath = 'SMB_vul_Result'
    if os.path.exists(resultPath):
        shutil.rmtree(resultPath)
    os.mkdir(resultPath)
    n = 0
    try:
        for root, dirs, files in os.walk(sys.argv[1]):
            for fName in files:
                outFile = 'SMB_vul_' + fName.split('_')[1]
                outFilePath = os.path.join(resultPath,outFile)
                #print outFilePath
                ipFile = os.path.join(root, fName)
                print ipFile
                s = MS17_010_SMB(targetFile=ipFile,output=outFilePath)
                s.Run()
                print n
                print s
                del s
                time.sleep(2)
    except Exception as e: #EOFError
            print e














