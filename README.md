# scenum
A python tool to automate some scanning and enumeration for you. `scenum` makes calls to multiple other tools, so these need to be installed as well.

## Prerequisites
* Python >= 3.7
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
python scenum.py --help
```

## Usage
Use the `--help` or `-h` flag to view the tool's usage.
``` bash
python scenum.py -h
```

## Examples
``` bash
python scenum.py -H 192.168.1.54 -o ./
python scenum.py -H example.com -d ~/wordlists/directories.txt
```

## License
[MIT](https://github.com/ImoutoLily/scenum/blob/master/LICENSE)
