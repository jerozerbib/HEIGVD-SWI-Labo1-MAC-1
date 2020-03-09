#!/usr/bin/env python3
# -*- coding: utf-8 -*-
'''
Created on 17.02.2020

@author: Basile Botebol

inspired by https://www.thepythoncode.com/article/create-fake-access-points-scapy
            https://stackoverflow.com/questions/1265665/how-can-i-check-if-a-string-represents-an-int-without-using-try-except
            https://pythontips.com/2013/07/28/generating-a-random-string/
'''
import sys

from scapy.all import *

import os
import string
import random

#fonction qui test si une string est un int ou non
def isInt_try(v):
    try:     i = int(v)
    except:  return False
    return True

#fonction qui genere une string random entre 5 et 10 char
def random_generator(size=random.randint(5,10), chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

#fonction qui prend en parametre un SSID et envoie 100 beacon par channel
def fake_ap(ssid):
    # interface à utiliser
    iface = "wlan0mon"

    # génération random d'une MAC (fonciton built in)
    sender_mac = RandMAC()

    #on génere le beacon
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid

    #on change de canal et on envoie 100 beacon pour un SSID donné
    for it in range (1,14):
        print("Sending 100 beacons for SSID " + ssid + " on channel " + str(it))
        cmd = "iwconfig wlan0mon channel " + str(it)
        os.system(cmd)
        sendp(frame, inter=0.000001, count=100, iface=iface, verbose=0)


def main(argv):
    #on verifie que le fichier existe
    if os.path.isfile(argv[0]):
        file = open(argv[0], 'r')
        ap_list = file.readlines()
        file.close

    #si le fichier n'existe pas on verifie qu'il represente un int
    elif (isInt_try(argv[0])):
        ap_list=[]
        for i in range (1, int(argv[0])):
            ap_list.append(random_generator())

    #si aucune des deux options ne fonctionne, on envoi un message d'erreur, et on quittele programme
    else :
        print("error, give a file or number of AP to generate")
        exit()

    #une fois qu'on a une liste d'ap, on appelle la fonciton fake_ap en boucle sur notre liste
    while 1:
        for ap in ap_list:
            fake_ap(ap)


if __name__ == "__main__":
    main(sys.argv[1:])
