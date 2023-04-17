import os
import ipaddress
import datetime
import nmap
import uuid
import time
import requests
import urllib.parse
from pycvesearch import CVESearch
from multiprocessing import Pool
from constant import API_URL

def add_scan_result(id_major:str, id_cut:str, host:str, protocol:str, port:int,state:str, name:str, product:str, version:str, extra:str, cpe:str,vulnerable:str):
    new_scan = {
        "id_major":id_major,
        "id_cut": id_cut,
        "host":host,
        "protocol":protocol,
        "port":port,
        "state":state,
        "name":name,
        "product":product,
        "version":version,
        "extra":extra,
        "cpe":cpe,
        "vulnerable":vulnerable
    }
    value = requests.post(f"{API_URL}/scan/{id_major}", json=new_scan)

def find_CIDR_from_range(IPrange): #Reveive and IP range in this format : "xxx.xxx.xxx.xxx-XXX.XXX.XXX.XXX"
    IPlist = IPrange.split("-")
    startip = ipaddress.IPv4Address(IPlist[0])
    endip = ipaddress.IPv4Address(IPlist[1])
    listRange = ipaddress.summarize_address_range(startip, endip)
    CIDRlist = []
    for CIDR in listRange:
        CIDRlist.append(str(CIDR))
    return CIDRlist

def create_cpe_from_product(product, version):
    cve = CVESearch("https://cvepremium.circl.lu")
    uri = ""
    if product == "nginx":
       uri = f"f5/{product}"
    else:
        uri = f"{product}/{product}"
    x = cve.browse(uri)

    try:
        cpe22 =""
        if product == "nginx":
            cpe22 = f"cpe:/a:f5:{product}:{version}"
        else:
            cpe22 = f"cpe:/a:{product}:{product}:{version}"
        return cpe22
    except:
        return None

def get_cve_for_cpe(cpe):
    try:
        cve = CVESearch("https://cvepremium.circl.lu")
        if (cpe == ""):
            return None
        cpe23_service = cve.cpe23(cpe)
        encoded_value = urllib.parse.quote(cpe23_service.content)
        x = cve.cvefor(encoded_value[3:-6])
        compteur = 0
        returned = []
        for line in x:
            returned.append(line.get('id'))
        return returned
    except Exception as e:
        return None

def launch_scan(id_major,scan_cut_id,host, ports):
    print("start of nmap :", host)
    nm = nmap.PortScanner()
    date = datetime.datetime.now()
    nm.scan(hosts=host, ports=f"{ports}", arguments='-Pn -sV')
    for host in nm.all_hosts():
        cpe_list = []
        cve_list = []
        for proto in nm[host].all_protocols():
            for port in nm[host][proto] :
                cpe = nm[host][proto][port]['cpe']
                if (nm[host][proto][port]['cpe'] == "cpe:/o:linux:linux_kernel"):
                    cpe = create_cpe_from_product(nm[host][proto][port]['product'],nm[host][proto][port]['version'])
                    if (cpe not in cpe_list):
                        cpe_list.append(cpe)
                        cve_list = get_cve_for_cpe(cpe)         
                if ((nm[host][proto][port]['cpe'] not in cpe_list) and (nm[host][proto][port]['cpe'] != "cpe:/o:linux:linux_kernel")):
                    cpe_list.append(nm[host][proto][port]['cpe'])
                    cve_list = get_cve_for_cpe(nm[host][proto][port]['cpe'])
                if (cve_list == None):
                    add_scan_result(id_major,scan_cut_id, str(host), proto,port,nm[host]['status']['state'],nm[host]['hostnames'][0]['name'],nm[host][proto][port]['product'],nm[host][proto][port]['version'],nm[host][proto][port]['extrainfo'],cpe,str(cve_list))
                else:
                    cve_list_join = " ".join(cve_list)
                    add_scan_result(id_major,scan_cut_id, host, proto,port,nm[host]['status']['state'],nm[host]['hostnames'][0]['name'],nm[host][proto][port]['product'],nm[host][proto][port]['version'],nm[host][proto][port]['extrainfo'],cpe,cve_list_join)
    return (id_major)


while True:
    print("start of the script")
    scan = requests.get(f"{API_URL}/scan/to_launch")
    if (scan.status_code == 200):
        date_start = datetime.datetime.now()
        print(date_start)
        scan_progress = scan.json()
        scan_id = scan_progress["id_scan"]
        scan_cut_id = scan_progress["id_cut"]
        print(scan_id)
        scan_hosts = scan_progress["hosts"]
        scan_ports = scan_progress["port"]
        if(('-' in scan_hosts)):
            range_list = find_CIDR_from_range(scan_hosts)
            args_list =[]
            for cidr in range_list:
                args_list.append((scan_id, scan_cut_id, cidr,scan_ports))

            with Pool(processes=len(args_list)) as pool:
                pool.starmap(launch_scan, args_list)
        else:
            launch_scan(scan_id, scan_cut_id,scan_hosts,scan_ports)
        date2 = datetime.datetime.now()
        update_status = requests.put(f"{API_URL}/scan/{scan_cut_id}?status=done")
        date_end = datetime.datetime.now()
        print(date_end)
        print("end of script")
    else:
        print("waiting")
        date3 = datetime.datetime.now()
        time.sleep(15)
        continue
