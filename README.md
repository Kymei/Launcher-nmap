# Scan Launcher (SCAAS Project 🕵🏼):

Project that will launch the scans and push the results to API-nmap.

Check Out [Scaas](https://github.com/Kymei/API-nmap) for more informations.


### Install Packages
#### As root :
```
apt update
apt install python3 python3-pip python3-venv python-is-python3 curl git
useradd scan_launcher
git clone git@gitlab.priv.sewan.fr:rd/scaas-scan-launcher.git
chown -R scan_launcher /opt/scaas-scan-launcher
Dependencies / Virtual environment
```

#### As scan_launcher in ```/opt/scaas-scan-launcher``` :
```
python3 -m venv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

In the file constant.py update the API_URL with the SCAAS API url.

#### As root update the crontab :
```
sudo crontab -e
```

Add this line to the file:
```
@reboot /opt/scaas-scan-launcher/venv/bin/python3 /opt/scaas-scan-launcher/launch.py
```

Now you can reboot or start the python script manualy
```
/opt/scaas-scan-launcher/venv/bin/python3 /opt/scaas-scan-launcher/launch.py
```