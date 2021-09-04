# 11 Aug 2021 00.38
# Skrip ini bertujuan untuk automasi pengecekan apakah suatu host / IP merupakan cloudflare 
# serta melakukan check apakah support untuk melakukan domain fronting
# mass checker dari file / csv / pcap hasil capture

import requests
import sys
from requests.exceptions import ReadTimeout, Timeout, ConnectionError
import os, fnmatch
import csv
from collections import defaultdict


class colors: # You may need to change color settings
    RED = '\033[31m'
    ENDC = '\033[m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'





print(colors.BLUE + '''

  ______ _                 _  ___ _                    
 / _____) |               | |/ __) |                   
| /     | | ___  _   _  _ | | |__| | ____  ____ ____   
| |     | |/ _ \| | | |/ || |  __) |/ _  |/ ___) _  )  
| \_____| | |_| | |_| ( (_| | |  | ( ( | | |  ( (/ /   
 \______)_|\___/ \____|\____|_|  |_|\_||_|_|   \____)  
                                                       
  ______ _                _                            
 / _____) |              | |                           
| /     | | _   ____ ____| |  _ ____  ____             
| |     | || \ / _  ) ___) | / ) _  )/ ___)            
| \_____| | | ( (/ ( (___| |< ( (/ /| |                
 \______)_| |_|\____)____)_| \_)____)_|                                                         
''' + colors.ENDC)
print(colors.YELLOW +" **For Domain Fronting"+ colors.ENDC)
print(colors.RED + "                                    by;anon" + colors.ENDC)
print("")


print(" Silahkan Pilih : ")
print(" 1. Melakukan Checking dari TXT files.")
print(" 2. Melakukan Checking dari CSV files.")
print(" q untuk keluar")
opsi=input(" Pilihan :  ")

# variabel2 
expected_response = 101
control_domain = 'id-public1.sshws.net'
headers = { 'Host': control_domain, 'Upgrade': 'websocket'}
file_hosts = ""
result_success = []
num_file = 1
columns = defaultdict(list)



txtfiles= []
hostpath = 'host'
if not os.path.exists(hostpath):
    os.makedirs(hostpath)




if str(opsi) == "1":
    files = os.listdir(hostpath)
    for f in files:
        if fnmatch.fnmatch(f, '*.txt'):
            print( str(num_file),str(f))
            num_file=num_file+1
            txtfiles.append(str(f))
    
    fileselector = input("Pilih file host : ")
    print("File yang anda pilih adalah : " + txtfiles[int(fileselector)-1])
    file_hosts = str(hostpath) +"/"+ str(txtfiles[int(fileselector)-1])
    
    
    # mengimport list dari text ( menjadi list )
    with open(file_hosts) as f:
        parseddom = f.read().split()
        
    domainlist = list(set(parseddom))
    domainlist = list(filter(None, parseddom))
    
elif str(opsi) == "2":
    files = os.listdir(hostpath)
    for f in files:
        if fnmatch.fnmatch(f, '*.csv'):
            print( str(num_file),str(f))
            num_file=num_file+1
            txtfiles.append(str(f))
    
    fileselector = input("Pilih file host : ")
    print("File yang anda pilih adalah : " + txtfiles[int(fileselector)-1])
    file_hosts = str(hostpath) +"/"+ str(txtfiles[int(fileselector)-1])
    
    with open(file_hosts,'r') as csv_file:
        reader = csv.reader(csv_file)
    
        for row in reader:
            for (i,v) in enumerate(row):
                columns[i].append(v)
    parseddom=columns[9]+columns[3]
    domainlist = list(set(parseddom))
    domainlist = list(filter(None, parseddom))
    
elif str(opsi) == "q":
    exit()
else:
    exit()



print("Berhasil memuat " + colors.GREEN + str(len(domainlist)) + colors.ENDC + " host Unique dari total " + str(len(parseddom)) + " host")
print("")
input(colors.GREEN + "Tap enter untuk memulai testing ....." + colors.ENDC)
print("")

for domain in domainlist:
        try:
            r = requests.get("http://" + domain, headers=headers, timeout=0.7)
            if r.status_code == expected_response:
                print(colors.GREEN + " [ HIT ]" + colors.ENDC + " Domain: " + domain + " - is fronting domain -")
                result_success.append(str(domain))
            elif r.status_code != expected_response:
                print(colors.RED + "   FAIL : " + colors.ENDC + domain + " responded with " + str(r.status_code) + " code")
        except (Timeout, ReadTimeout, ConnectionError):
                print(colors.RED + "   FAIL : " + colors.ENDC + domain + " TIMEOUT")


print(" Jumlah host / domain yang berhasil didapatkan adalah "  + colors.GREEN + str(len(result_success)) + colors.ENDC)
if len(result_success) >= 0:
    print(" Berikut hasil yang didapatkan : ")
for result in result_success:
    print(colors.GREEN + "  " + result + colors.ENDC)
    