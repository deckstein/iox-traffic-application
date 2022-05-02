import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib
import pandas as pd
import time
import io
import sys
import subprocess as sub
from matplotlib.ticker import FormatStrFormatter

font = {'family' : 'normal',
        'weight' : 'normal',
        'size'   : 20}

matplotlib.rc('font', **font)

myIP = sys.argv[1]

traffic = pd.DataFrame(columns=[
    'timestamp','protocol','type','src-ip',
    'dst-ip','dst-port','query-name','response-name'])

def createVisuals(traffic,myIP):
    fig = plt.figure(figsize=(35, 15), dpi= 80)
    grid = plt.GridSpec(1, 3, hspace=0.1, wspace=0.1)

    ax_bl = fig.add_subplot(grid[:, :1])
    ax_bl.yaxis.set_major_formatter(FormatStrFormatter('%g'))
    ax_bc = fig.add_subplot(grid[:, 1])
    ax_bc.yaxis.set_major_formatter(FormatStrFormatter('%g'))
    ax_br = fig.add_subplot(grid[:,-1])
    ax_br.yaxis.set_major_formatter(FormatStrFormatter('%g'))

    sns.countplot(
        x="query-name",
        data=traffic[traffic['query-name'] != 'None'],
        order = traffic['query-name'].value_counts().index,ax=ax_bl).set_title('Number of DNS Requests per Domain')
    ax_bl.set_ylabel('')    
    ax_bl.set_xlabel('')
    ax_bl.tick_params(labelrotation=90)

    sns.countplot(
        x="response-name",
        data=traffic[traffic['response-name'] != 'None'],
        order = traffic['response-name'].value_counts().index,ax=ax_bc).set_title('Number of DNS Responses per Domain')
    ax_bc.set_ylabel('')    
    ax_bc.set_xlabel('')
    ax_bc.tick_params(labelrotation=90)

    sns.countplot(x="protocol",data=traffic,ax=ax_br).set_title('Packages per Protocol')
    ax_br.set_ylabel('')    
    ax_br.set_xlabel('')

    plt.subplots_adjust(bottom=0.15)
    plt.savefig('stats.png',bbox_inches="tight")

def network_conversation(packet,traffic,myIP):
    type = source_address = source_port = destination_address = destination_port = protocol = None
    if(len(traffic) > 50):
        #traffic.to_pickle("./apptraffic.pkl")
        #print("traffic grew too big, truncating")
        createVisuals(traffic,myIP)
        traffic = traffic[-30:]

    packet = packet.rstrip()
    packetSplit = packet.split(' ')
    source_address = ".".join(packetSplit[2].split('.')[:4])
    source_port = packetSplit[2].split('.')[-1].split(":")[0]
    destination_address = ".".join(packetSplit[4].split('.')[:4])
    destination_port = packetSplit[4].split('.')[-1].split(":")[0]
    query_name = None
    response_name = None

    if('ICMP echo' in packet):
        protocol = 'ICMP'
        type = 'Ping'
        destination_port = None
        source_port = None
        #print("ping from source: "+source_address+", to dest: "+destination_address)
    elif('Flags' in packet):
        protocol = 'HTTP'
        type = 'Web-Request'
        #print("web request from source: "+source_address+", source port: "+source_port+" to destination: "+destination_address+" on port: "+destination_port)
    else:
        if(int(destination_port) == 53):
            protocol = 'DNS'
            type = 'DNS-Request'
            query_name = packetSplit[7][:-1]
        if(int(source_port) == 53):
            protocol = 'DNS'
            type = 'DNS-Request'
            response_name = packetSplit[8][:-1]

    traffic = traffic.append({
        'timestamp': time.time(),
        'protocol': protocol,
        'type': type,
        'src-ip': source_address,
        'src-port': source_port,
        'dst-ip': destination_address,
        'dst-port': destination_port,
        'query-name': query_name,
        'response-name': response_name
    },ignore_index=True)
    return traffic

while(1):
    p = sub.Popen(('tcpdump', '-n', '-s', '0', '-i', 'eth0', 'tcp', 'dst', 'port', '443', 'or', 'icmp', 'or', 'udp', 'port', '53'), stdout=sub.PIPE)
    for packet in io.TextIOWrapper(p.stdout, encoding="utf-8"):
        traffic = network_conversation(packet,traffic,myIP)
