import os
import time
import requests as req

hosts = ['www.cisco.com','devnetsupport.cisco.com','developer.cisco.com']
urls = [
    'https://www.cisco.com/c/en/us/products/cloud-systems-management/iox/index.html',
    'https://www.cisco.com/c/en/us/solutions/internet-of-things/edge-intelligence.html',
    'https://developer.cisco.com/'
]

count=0
while(1):
    for host in hosts:
        os.system("ping -c 5 "+host+" > /dev/null 2>&1")
    for url in urls:
        req.get(url)
    count+=1
    time.sleep(20)