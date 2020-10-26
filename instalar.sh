#!/bin/bash

function print_ascii_art {
cat << "EOF"
   __               __                                 
  / /  __ _ _ __   / _\ ___ __ _ _ __  _ __   ___ _ __ 
 / /  / _` | '_ \  \ \ / __/ _` | '_ \| '_ \ / _ \ '__|
/ /__| (_| | | | | _\ \ (_| (_| | | | | | | |  __/ |   
\____/\__,_|_| |_| \__/\___\__,_|_| |_|_| |_|\___|_|   
                                                       

					daniel.torres@owasp.org
					https://github.com/DanielTorres1

EOF
}


print_ascii_art

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

echo -e "${GREEN} [+] Instalando herramientas disponibles en repositorio ${RESET}" 
sudo apt-get update
sudo apt-get -y install bc nbtscan nfs-common snmp finger sqlite3 sqlitebrowser python-pip nmap masscan onesixtyone whatweb libssl-dev ike-scan postgresql-client elinks smbclient bc libcurl4-openssl-dev xterm ipmitool lbd exiftool libpq-dev libpcap-dev tshark p7zip-full default-mysql-client python3-pip libssl-dev swig python3-dev gcc libcrypt-ssleay-perl metasploit-framework patator hydra enum4linux wpscan dnsutils python3-setuptools

pip3 install cryptography
pip3 install pycryptodomex

echo -e "${GREEN} [+] Instalando ofuscador de bash ${RESET}" 
npm install -g bash-obfuscate

echo -e "${GREEN} [+] Instalando webhacks ${RESET}"
git clone https://github.com/DanielTorres1/webhacks
cd webhacks
bash instalar.sh
cd ..


echo -e "${GREEN} [+] Copiando archivos ${RESET}"
mkdir /usr/share/lanscanner 2>/dev/null
cd files
cp fingerprints-domain.json /usr/share/lanscanner
cp amass-config.ini /usr/share/lanscanner
cp community.txt /usr/share/lanscanner
cp .resultados.db /usr/share/lanscanner
cp -r postExploiter /usr/share/lanscanner
cp vulnerabilidades.xml /usr/share/lanscanner 2>/dev/null

cp smb-vuln-ms17-010.nse /usr/share/nmap/scripts/
cp rtsp-url-brute.nse /usr/share/nmap/scripts/rtsp-url-brute.nse
cp rtsp.lua /usr/share/nmap/nselib/rtsp.lua
cp cve_2019_0708_bluekeep.rb /usr/share/metasploit-framework/modules/auxiliary/scanner/rdp
cd ..
echo ""


echo -e "${GREEN} [+] Copiando scripts a /usr/bin ${RESET}"
cp -r pentest /usr/bin
cp lanscanner.sh /usr/bin
cp monitor.sh /usr/bin
cp autohack.sh /usr/bin
cp generarReporte.pl /usr/bin

chmod a+x /usr/bin/generarReporte.pl
chmod a+x /usr/bin/monitor.sh
chmod a+x /usr/bin/lanscanner.sh
chmod a+x /usr/bin/autohack.sh
echo ""


echo -e "${GREEN} [+] Instalando librerias de perl ${RESET}"
sudo cpan G/GR/GROMMEL/Math-Round-0.07.tar.gz
sudo cpan U/UR/URI/File-Slurp-9999.19.tar.gz
sudo cpan M/MA/MAKAMAKA/JSON-2.90.tar.gz
sudo cpan I/IS/ISHIGAKI/JSON-4.02.tar.gz
sudo cpan G/GR/GRANTM/XML-Simple-2.25.tar.gz

echo -e "${RED}[+]${GREEN} Instalando GeoIP ${RESET}"
git clone https://github.com/DanielTorres1/geoIP
cd geoIP
bash instalar.sh
echo ""
cd ../




echo -e "${RED}[+]${GREEN} Instalando Interlace ${RESET}"
cd Interlace
python3 setup.py install
echo ""
cd ../

echo -e "${RED}[+]${GREEN} Instalando wafw00f ${RESET}"
cd wafw00f
python setup.py install
echo ""
cd ../


echo -e "${GREEN} [+] Modificando PATH ${RESET}"
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.bashrc
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.zshrc
echo ""
chmod a+x /usr/bin/pentest/*

mkdir -p /usr/share/wordlists/ 2>/dev/null
cd /usr/share/wordlists/
wget https://raw.githubusercontent.com/DanielTorres1/passwords/master/usuarios-es.txt

echo -e "${GREEN} [+] LISTO!! TODO OK"
echo -e "${RED} [i] IMPORTANTE: Para empezar a usar los scripts inicia otra terminal :V ${RED}"


