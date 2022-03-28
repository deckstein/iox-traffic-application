import pyshark
import seaborn as sns
import matplotlib.pyplot as plt
import matplotlib
import pandas as pd
import time
import sys
from matplotlib.ticker import FormatStrFormatter
import plotly.graph_objects as go
from plotly.subplots import make_subplots

font = {'family' : 'normal',
        'weight' : 'normal',
        'size'   : 20}

matplotlib.rc('font', **font)

myIP = sys.argv[2]
cap = pyshark.LiveCapture(interface=sys.argv[1], bpf_filter='icmp or tcp or udp')

traffic = pd.DataFrame(columns=[
    'timestamp','protocol','type','src-ip','src-port',
    'dst-ip','dst-port','query-name','response-name'])

def createVisuals(traffic,myIP):
    chordDF = traffic[(traffic['src-ip'].notna()) & (traffic['dst-ip'].notna())][['src-ip','dst-ip']]
    chordDF = chordDF.groupby(['src-ip','dst-ip']).size().reset_index().rename(columns={0:'count'})
    col_values = chordDF[["src-ip", "dst-ip"]].values.ravel()
    ipcatmapping = pd.DataFrame(columns=['ip','code'])
    ipcatmapping['ip'] =  pd.unique(col_values)
    ipcatmapping['code'] = ipcatmapping.index
    ipcatmapping['in'] = 0
    ipcatmapping['out'] = 0
    ipcatmapping['label'] = None

    chordDF['dst-ipcode'] = None
    chordDF['src-ipcode'] = None
    chordDF['color'] = None

    for idx,value in chordDF.iterrows():
        chordDF.iloc[idx,chordDF.columns.get_loc('dst-ipcode')] = ipcatmapping[ipcatmapping['ip'] == chordDF.iloc[idx,chordDF.columns.get_loc('dst-ip')]]['code'].unique()
        chordDF.iloc[idx,chordDF.columns.get_loc('src-ipcode')] = ipcatmapping[ipcatmapping['ip'] == chordDF.iloc[idx,chordDF.columns.get_loc('src-ip')]]['code'].unique()
        if(chordDF.iloc[idx,chordDF.columns.get_loc('src-ip')] == myIP):
            chordDF.iloc[idx,chordDF.columns.get_loc('color')] = 'cornflowerblue'
        elif(chordDF.iloc[idx,chordDF.columns.get_loc('dst-ip')] == myIP):
            chordDF.iloc[idx,chordDF.columns.get_loc('color')] = 'coral'
        else:
            chordDF.iloc[idx,chordDF.columns.get_loc('color')] = 'grey'

    for idx,value in ipcatmapping.iterrows():
        ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('in')] = chordDF[chordDF['dst-ip'] == ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('ip')]]['count'].sum()
        ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('out')] = chordDF[chordDF['src-ip'] == ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('ip')]]['count'].sum()
        ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('label')] = ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('ip')] + ', in: '+str(ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('in')])+', out: '+str(ipcatmapping.iloc[idx,ipcatmapping.columns.get_loc('out')])        

    fig = go.Figure(data=[go.Sankey(
        node = dict(
        pad = 15,
        thickness = 15,
        line = dict(color = "black", width = 0.5),
        label =  ipcatmapping['label'],
        color =  'black'
        ),
        link = dict(
        source =  chordDF['src-ipcode'],
        target =  chordDF['dst-ipcode'],
        value =  chordDF['count'],
        label =  chordDF['dst-ipcode'],
        color =  chordDF['color']
    ))])

    fig.update_layout(
        hovermode = 'x',
        title="TCP Traffic from/to IPv4 addresses (blue: outbound / coral: inbound)",
        font=dict(size = 18, color = 'black'),
        plot_bgcolor='black',
        paper_bgcolor='white'
    )

    #fig.write_image("sankey.jpg",width=1920, height=800)
    fig.write_html("file.html")

    fig = plt.figure(figsize=(35, 15), dpi= 80)
    grid = plt.GridSpec(1, 3, hspace=0.1, wspace=0.1)

    ax_bl = fig.add_subplot(grid[:, :1])
    ax_bc = fig.add_subplot(grid[:, 1])
    ax_br = fig.add_subplot(grid[:,-1])

    sns.countplot(
        x="query-name",
        data=traffic[traffic['query-name'] != 'None'],
        order = traffic['query-name'].value_counts().index,ax=ax_bl).set_title('Number of DNS Requests per Domain')
    ax_bl.set_ylabel('')    
    ax_bl.set_xlabel('')
    ax_bl.tick_params(labelrotation=45)

    sns.countplot(
        x="response-name",
        data=traffic[traffic['response-name'] != 'None'],
        order = traffic['response-name'].value_counts().index,ax=ax_bc).set_title('Number of DNS Responses per Domain')
    ax_bc.set_ylabel('')    
    ax_bc.set_xlabel('')
    ax_bc.tick_params(labelrotation=45)

    sns.countplot(x="protocol",data=traffic,ax=ax_br).set_title('Packages per Protocol')
    ax_br.set_ylabel('')    
    ax_br.set_xlabel('')

    plt.subplots_adjust(bottom=0.15)
    plt.savefig('stats.png')

def network_conversation(packet,traffic,myIP):
    type = source_address = source_port = destination_address = destination_port = protocol =None
    if(len(traffic) > 700):
        #traffic.to_pickle("./apptraffic.pkl")
        print("traffic grew too big, truncating")
        createVisuals(traffic,myIP)
        traffic = traffic[350:]
    if(hasattr(packet,'http')):
        type = "HTTP"    
    if(hasattr(packet,'transport_layer')):
        protocol = packet.transport_layer
    if(hasattr(packet,'icmp')):
        protocol = 'ICMP'
    if(hasattr(packet,'ip')):
        if(hasattr(packet.ip,'src')):
            source_address = packet.ip.src
        if(hasattr(packet.ip,'dst')):
            destination_address = packet.ip.dst
    if(hasattr(packet,str(protocol))):
        if(hasattr(packet.protocol,'srcport')):
            source_port = packet[protocol].srcport
        if(hasattr(packet.protocol,'dstport')):
            destination_port = packet[protocol].dstport        
    traffic = traffic.append({
        'timestamp': time.time(),
        'protocol': protocol,
        'type': type,
        'src-ip': source_address,
        'src-port': source_port,
        'dst-ip': destination_address,
        'dst-port': destination_port,
        'query-name': None,
        'response-name': None
    },ignore_index=True)

    if(hasattr(packet,'dns')):
        if(hasattr(packet.dns,'qry_name')):
            traffic = traffic.append({
                'timestamp': time.time(),
                'protocol': protocol,
                'type': 'DNS-Query',
                'src-ip': source_address,
                'src-port': None,
                'dst-ip': destination_address,
                'dst-port': None,
                'query-name': packet.dns.qry_name,
                'response-name': None
            },ignore_index=True)
    if(hasattr(packet,'dns')):
        if(hasattr(packet.dns,'resp_name')):
            traffic = traffic.append({
                'timestamp': time.time(),
                'protocol': protocol,
                'type': 'DNS-Response',
                'src-ip': source_address,
                'src-port': None,
                'dst-ip': destination_address,
                'dst-port': None,
                'query-name': None,
                'response-name': packet.dns.resp_name
            },ignore_index=True)
    return traffic

while(1):
    for packet in cap.sniff_continuously(packet_count=350):
        traffic = network_conversation(packet,traffic,myIP)