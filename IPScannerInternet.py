import telnetlib
import whois as ws 
from icmplib import traceroute
from icmplib import ping

print('===============================================')
print('+   SCAN IP/PREFIX/WEBSITE FROM INTERNET      +')
print('+           by: Fachri Abdilah                +')
print('===============================================\n\n\n')


def globalInet(target):
    HOST = "route-server.ip.att.net"
    user = "rviews"
    password = "rviews"

    tn = telnetlib.Telnet(HOST)

    tn.read_until(b"login: ")
    tn.write(user.encode('ascii') + b"\n")
    if password:
            tn.read_until(b"Password:")
            tn.write(password.encode('ascii') + b"\n")

    tn.write(b"show route " + target.encode('ascii') + b" | no-more\n")
    tn.write(b"ping "+ target.encode('ascii') +b" count 10\n")
    tn.write(b"exit\n")
    print(tn.read_all().decode('ascii'))


def globalInetHE(target):
    HOST = "route-server.he.net"
    password = "rviews"

    tn = telnetlib.Telnet(HOST)

    tn.read_until(b"Password: " )
    tn.write(password.encode('ascii') + b"\n")

    tn.write(b"show ip bgp " + target.encode('ascii') + b"\n\n")
    tn.write(b"exit\n")
    print(tn.read_all().decode('ascii'))

def Whoisearch(target):
    res = ws.whois(target)
    print("Domain Name : ",res.domain_name)
    print("WHOIS Server :",res.whois_server)
    print("CREATE Date :",res.creation_date)
    print("EXP Date :",res.expiration_date)
    print("UPDATE Date :",res.updated_date)
    for x in res.name_servers:
        print("NS :",x)
    print("\n\n### DETAIL PERUSAHAAN ##")
    print("Nama :",res.name)
    print("Organisasi :",res.org)
    print("Alamat :",res.address)
    print("Kota :",res.city)
    print("State :",res.state)
    print("Negara :",res.country)
    print("Kode Pos :",res.registrant_postal_code)
    print("E-mail :",res.emails)

def Tracet(target):
    hops = traceroute(target)
    print('Distance/TTL    Address    Average round-trip time')
    last_distance = 0 
    for hop in hops:
        if last_distance + 1 != hop.distance:
            print('Some gateways are not responding')

     # Mendefinisikan hasil traceroute setiap Hop
        print(f'{hop.distance}    {hop.address}    {hop.avg_rtt} ms')

        last_distance = hop.distance

def pIng(target):
    host = ping(target, count=10, interval=0.2)
    return host


#Mulai program

IpWEB = input("Masukan Alamat IP/PREFIX/WEBSITE : ")

print("\n\n### HASIL DATA WHOIS ##")
print(Whoisearch(IpWEB))

print("\n\n### HASIL PING NETWORK LOCAL ##")
print(pIng(IpWEB))

print("\n\n### HASIL TRACEROUTE NETWORK LOCAL ##")
print(Tracet(IpWEB))

print("\n\n\n####### HASIL ROUTE SERVER ATTT ##########")
print(globalInet(IpWEB))

print("\n\n\n####### HASIL ROUTE SERVER HURRICANE ##########")
print(globalInetHE(IpWEB))