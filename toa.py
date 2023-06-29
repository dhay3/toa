from scapy.all import *
from scapy.layers.inet import TCP, IP
from ipaddress import ip_address
from datetime import datetime
import argparse


def toa(p):
    if p.haslayer(TCP):
        opts = p.getlayer(TCP).options
        if opts:
            for opt in opts:
                kind = opt[0]
                bd = opt[1]
                if 0xfe == kind and bd:
                    atime = p.time
                    rtime = datetime.utcfromtimestamp(int(atime))
                    sip = p.getlayer(IP).src
                    dip = p.getlayer(IP).dst
                    id = p.getlayer(IP).id
                    sport = p.getlayer(TCP).sport
                    dport = p.getlayer(TCP).dport
                    bdh = bd.hex()
                    n1 = int(bdh[4:6], 16)
                    n2 = int(bdh[6:8], 16)
                    n3 = int(bdh[8:10], 16)
                    n4 = int(bdh[10:12], 16)
                    osip = f'{n1}.{n2}.{n3}.{n4}'
                    if ip_address(osip):
                        print(f'{rtime} {id}\n{sip}:{sport} > {dip}:{dport} | {osip}')
                    else:
                        p.show()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        prog='htoa',
        usage='%(prog) <TIMEOUT>',
        add_help=False)
    parser.add_argument('timeout', type=int)
    r = sniff(timeout=parser.parse_args().timeout, prn=lambda x: toa(x))
