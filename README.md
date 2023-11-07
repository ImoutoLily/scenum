# scenum
A python tool to automate some scanning and enumeration for you. `scenum` makes calls to multiple other tools, so these need to be installed as well.

## Requirements
* Python
* Nmap
* Nikto
* Smbclient
* Whatweb
* WPScan
* Gobuster

## Installation
```bash
git clone https://github.com/ImoutoLily/scenum.git
cd scenum
python scenum.py -H <IP_OR_DOMAIN> -o ./
```

To view the usage of the tool, run the following.

``` bash
python scenum.py -h
```

## Examples

``` bash
python scenum.py -H 192.168.1.54 -o ./
python scenum.py -H example.com -d /usr/share/wordlists/rockyou.txt
```

