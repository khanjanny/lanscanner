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
sudo apt-get -y install bc nbtscan nfs-common snmp finger sqlite3 sqlitebrowser python-pip nmap masscan onesixtyone whatweb libssl-dev python-qt4 ike-scan postgresql-client-* elinks smbclient bc libcurl4-openssl-dev 
sudo apt-get -y install mysql-client-core-*


echo -e "${GREEN} [+] Instalando webhacks ${RESET}"
git clone https://github.com/DanielTorres1/webhacks
cd webhacks
bash instalar.sh
cd ..

echo -e "${GREEN} [+] Copiando archivos ${RESET}"
mkdir /usr/share/lanscanner 2>/dev/null
cd files
cp community.txt /usr/share/lanscanner
cp resultados.db /usr/share/lanscanner
cp -r postExploiter /usr/share/lanscanner
cp vulnerabilidades.xml /usr/share/lanscanner
cp smb-vuln-ms17-010.nse /usr/share/nmap/scripts/
cd ..
echo ""


echo -e "${GREEN} [+] Copiando scripts a /usr/bin ${RESET}"
cp -r pentest /usr/bin
cp lanscanner.sh /usr/bin
cp monitor.sh /usr/bin
cp generarReporte.pl /usr/bin

chmod a+x /usr/bin/generarReporte.pl
chmod a+x /usr/bin/monitor.sh
chmod a+x /usr/bin/lanscanner.sh
echo ""


echo -e "${GREEN} [+] Instalando librerias de perl ${RESET}"
sudo cpan G/GR/GROMMEL/Math-Round-0.07.tar.gz
sudo cpan U/UR/URI/File-Slurp-9999.19.tar.gz
sudo cpan M/MA/MAKAMAKA/JSON-2.90.tar.gz


echo -e "${RED}[+]${GREEN} Instalando GeoIP ${RESET}"
git clone https://github.com/DanielTorres1/geoIP
cd geoIP
bash instalar.sh
echo ""
cd ../

echo -e "${GREEN} [+] Modificando PATH ${RESET}"
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.bashrc
echo export PATH="$PATH:/usr/bin/pentest" >> ~/.zshrc
echo ""
chmod a+x /usr/bin/pentest/*

cd /usr/share/wordlists/
wget https://raw.githubusercontent.com/DanielTorres1/passwords/master/usuarios-es.txt

echo -e "${GREEN} [+] LISTO!! TODO OK"
echo -e "${RED} [i] IMPORTANTE: Para empezar a usar los scripts inicia otra terminal :V ${RED}"


