#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'	
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
####################################################

live_hosts=".datos/total-host-vivos.txt"
arp_list=".datos/lista-arp.txt"
smb_list=".escaneos/lista-smb.txt"
dns_list=".escaneos/lista-dns.txt"
mass_scan_list=".escaneos/lista-mass-scan.txt"
ping_list=".escaneos/lista-ping.txt"
smbclient_list=".escaneos/lista-smbclient.txt"
port_scan_num="n"
vuln="n"
rdp="n"


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
	find vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py
	mv enumeracion/* .enumeracion2 2>/dev/null
	mv vulnerabilidades/* .vulnerabilidades2 2>/dev/null		 	
	}
	
print_ascii_art


while getopts ":t:a:s:o:" OPTIONS
do
            case $OPTIONS in
            t)     TYPE=$OPTARG;;
            s)     SUBNET_FILE=$OPTARG;;
            a)     FILE=$OPTARG;;
            o)     OFFSEC=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL}
SUBNET_FILE=${SUBNET_FILE:=NULL}
FILE=${FILE:=NULL}
OFFSEC=${OFFSEC:=NULL}

if [ $TYPE = NULL ] ; then

cat << "EOF"

Opciones: 

-t : Tipo de escaneo [completo/parcial]

Definicion del alcance (opcional):
	-s : Lista con las subredes a escanear (Formato CIDR 0.0.0.0/24)
	-f : Lista con las IP a escanear

Ejemplo 1: Escanear la red local (completo)
	lanscanner.sh -t completo

Ejemplo 2: Escanear el listado de IPs (completo)
	lanscanner.sh -t completo -a lista.txt

Ejemplo 3: Escanear el listadado de subredes (completo)
	lanscanner.sh -t completo -s subredes.txt
EOF

exit
fi
######################

if [[ $TYPE == "completo" ]] || [ $TYPE == "parcial" ]; then


echo -e "\n\n$OKRED ############################### Configurando los parametros ##################################### $RESET"

echo -e "\t $OKBLUE Cual es el nombre del proyecto? $RESET"
read project

mkdir $project
cd $project

mkdir -p .arp
mkdir -p .escaneos
mkdir -p .datos
mkdir -p .nmap
mkdir -p .nmap_1000p
mkdir -p .nmap_banners
mkdir -p enumeracion
mkdir -p vulnerabilidades
mkdir -p .masscan
mkdir -p reportes
mkdir -p .servicios
mkdir -p .tmp
mkdir -p logs/cracking
mkdir -p logs/enumeracion
mkdir -p logs/vulnerabilidades

mkdir .enumeracion2 2>/dev/null
mkdir .vulnerabilidades2 2>/dev/null

touch $smb_list 
touch $smbclient_list
touch $mass_scan_list 
touch $ping_list
cp /usr/share/lanscanner/resultados.db .

echo -e "\t $OKBLUE Que interfaz usaremos? eth0,tap0, etc ?$RESET"
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
echo -e "#####################################" | tee -a reportes/info.txt
echo -e "\t $OKRED IP Origen: $my_ip $RESET" | tee -a reportes/info.txt
echo -e "\t $OKRED MAC : $my_mac $RESET" | tee -a reportes/info.txt
echo -e "\t $OKRED Gateway: $my_route $RESET" | tee -a reportes/info.txt
echo -e "\t $OKRED DNS: $dns $RESET" | tee -a reportes/info.txt
echo -e "\t $OKRED Subnet: $current_subnet.0/24 $RESET" | tee -a reportes/info.txt
echo -e "\t $OKRED Date: $date $RESET" | tee -a reportes/info.txt
echo -e "#####################################" | tee -a reportes/info.txt

  
echo -e "$OKGREEN Lanzando monitor $RESET" 
xterm -hold -e monitor.sh 2>/dev/null&
sleep 5

# Using ip list    
  if [ $FILE != NULL ] ; then
    echo -e "\t "
    
     echo -e  "\n##############################################################################" 
     echo -e  "$OKRED \t Usando  ----> $FILE <----- $RESET" 
     cat ../$FILE | cut -d "," -f 2 | uniq > $live_hosts
    
    
    ####### smbclient scan #
    echo -e "\t $OKBLUE Realizaremos escaneo con smbclient para descubrir mas host? s/n (Recomendado para LAN) $RESET"
	read smbclient

    if [ $smbclient == 's' ]
   then     
		echo -e "$OKGREEN\t Buscando mas host vivos con smbclient  $RESET" 
		for ip in `cat $live_hosts`;			
		do 		
			smbclient -L $ip -U "%"  | egrep -vi "comment|---|master|Error|reconnecting|failed" | awk '{print $1}' | tee -a .escaneos/smbclient.txt 2>/dev/null
		done
		cat .escaneos/smbclient.txt | sort | uniq > .escaneos/smbclient2.txt

		for hostname in `cat .escaneos/smbclient2.txt`;
		do 			
			host $hostname | grep "has address" | cut -d " " -f 4 >> $smbclient_list
		done
		
		cat ../$FILE $smbclient_list | cut -d "," -f 2 | sort | uniq > $live_hosts # join file + smbclient_lis		
		cat $live_hosts
		echo ""       
		echo -e  "\n##############################################################################" 
	
   fi   
   cat $live_hosts | cut -d . -f 1-3 | sort | uniq > .datos/subnets.txt # get subnets      
	##################
    
  else

# FASE: 1
#######################################  Discover live hosts ##################################### 
  
  echo -e "$OKGREEN\t\t Buscar host vivos en otras redes usando ICMP,SMB,TCP21,22,80,443  $RESET" 
  echo -e "\n$OKRED [+] FASE 1: DESCUBRIR HOST VIVOS $RESET"

  ######## ARP ########
  echo -e "$OKGREEN\t ++ Obteniendo host vivos locales  $RESET"
  arp-scan $iface $current_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null
  sleep 2
  arp-scan $iface $current_ip/24  | tee -a .arp/$current_subnet.0.arp2 2>/dev/null  
  
  sort .arp/$current_subnet.0.arp2 | uniq > .arp/$current_subnet.0.arp
  rm .arp/$current_subnet.0.arp2
  echo -e "\t \n"
  
  	# ARP
  for ip_list in $(ls .arp | egrep -v "all|done"); do      
      cat .arp/$ip_list | egrep -v "DUP|packets" | grep ^1 | awk '{print $1}' | sort >> $arp_list
      mv .arp/$ip_list .arp/$ip_list.done	
   done;  
  #######################  
  
  if [ $SUBNET_FILE = NULL ] ; then
	echo -e "\t$OKBLUE Definir el numero de redes a escanear en busca de hosts vivos $RESET"    
	echo -e "$OKGREEN\t Ej:  Si escribe $OKRED 20$OKGREEN se escaneara las redes :"  
	#echo -e "10.0$OKRED.1-20$OKGREEN.0/24  \n192.168$OKRED.1-20$OKGREEN.0/24  \n172.16$OKRED.1-20$OKGREEN.0/24  $RESET"   
	net1="${netA/.X/$OKRED.1-20$OKGREEN}"
	net2="${netB/.X/$OKRED.1-20$OKGREEN}"
	net3="${netC/.X/$OKRED.1-20$OKGREEN}"
	echo -e $net1
	echo -e $net2
	echo -e $net3
  
  
	echo -e "\t $OKBLUE Que redes escanear ? $RESET"
	read num_nets_enum     
  fi
  
	  	  
	echo -e "\t $OKBLUE Realizar escaneo de puertos 22,80,443 en busca de mas hosts vivos ? s/n $RESET"	  
	read adminports
	  
	echo -e "\t $OKBLUE Realizar escaneo ICMP (ping) en busca de mas hosts vivos ? (Mas lento aun ...) s/n $RESET"	  
	read pingscan	 

	    	  	 
	  	  	 	
	  #################################   SMB    ###########################################
	  echo -e "\t ##### Realizando escaneo SMB en busca de mas hosts vivos #####"	  
	  
	  if [ $SUBNET_FILE != NULL ] ; then	  	 
		for subnet in `cat ../$SUBNET_FILE`;
		do 
			echo "scanning $subnet "
			nbtscan $subnet | tee -a .escaneos/escaneo-smb.txt
		done
		
	  else
		# escaneo a redes definidas por el usuario
		smb-scan.pl $netA $netB $netC $num_nets_enum | tee -a .escaneos/escaneo-smb.txt		
	  fi
	  
	  cat .escaneos/escaneo-smb.txt | grep : | awk '{print $1}' > $smb_list 2>/dev/null	  
      
                                   
      echo -e  "\n##############################################################################" 
      echo -e  "$OKGREEN Con el escaneo SMB  encontramos estos hosts vivos: $RESET" 
      cat $smb_list
      echo ""      
      #####################################################################################
      
      
      #################################   DNS    ###########################################

	  
	  if [ $SUBNET_FILE != NULL ] ; then	
   	 	echo -e "\t ##### Realizando escaneo DNS en busca de mas hosts vivos #####"	  
  	 
		for subnet in `cat ../$SUBNET_FILE`;
		do 
			echo "scanning $subnet "
			dnsrecon -r $subnet | tee -a .escaneos/escaneo-dns.txt
		done

	  	#cat .escaneos/escaneo-dns.txt | grep : | awk '{print $1}' > $smb_list 2>/dev/null	  
		grep PTR .escaneos/escaneo-dns.txt 2>/dev/null| awk '{print $4}'  > $dns_list 2>/dev/null			  

                                   
	      echo -e  "\n##############################################################################" 
	      echo -e  "$OKGREEN Con el escaneo DNS  encontramos estos hosts vivos: $RESET" 
	      cat $dns_list
	      echo ""      
	      #####################################################################################
	  fi
	  
           
      
      #################################   PORT 23,80,443,22  escaneando #########################################
	  
	  if [ $adminports == 's' ]
      then 
		echo -e "\t $OKBLUE ##### Realizando escaneo al puerto 22,80,443 en busca de mas hosts vivos ##### $RESET"	  
      
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat ../$SUBNET_FILE`;
			do 
				echo "scanning $subnet "				
				masscan -p21,22,23,80,443,445 --rate=150 $subnet | tee -a .escaneos/mass-scan.txt
			done		
		else
				mass-scan.pl $netA $netB $netC .escaneos/mass-scan.txt
		fi
	               
		
		cat .escaneos/mass-scan.txt | cut -d " " -f 6 | uniq > $mass_scan_list 2>/dev/null

		echo -e  "\n##############################################################################" 
		echo -e  "$OKRED Encontramos estos hosts vivos: $RESET" 
		cat $mass_scan_list
		echo ""             
      fi  	  	  
      
      #####################################################################################
	  
	  
	  
	   #################################   ICMP escaneando   ###########################################
	  
	  if [ $pingscan == 's' ]
      then 
		echo -e "\t $OKBLUE ##### Realizando escaneo ping en busca de mas hosts vivos ##### $RESET"	  
		
		if [ $SUBNET_FILE != NULL ] ; then	  	 
			for subnet in `cat ../$SUBNET_FILE`;
			do 
				echo "scanning $subnet "								
				fping -a -g $subnet | tee -a .escaneos/escaneo-ping.txt 
			done		
		else
				ping-scan.pl $netA $netB $netC $num_nets_enum | tee -a .escaneos/escaneo-ping.txt 
		fi
		
        
        cat .escaneos/escaneo-ping.txt | grep -v Escaneando  | sort | uniq > $ping_list 2>/dev/null
        
        echo -e  "\n##############################################################################" 
        echo -e  "$OKGREEN Con el escaneo ICMP (ping) encontramos estos hosts vivos: $RESET" 
        cat $ping_list
        echo ""       
      fi        
	  #####################################################################################
	           
    #fi #if scan_type
      #################################   smbclient   ###########################################
	  
	   ####### smbclient scan #
    echo -e "\t $OKBLUE Realizaremos escaneo con smbclient para descubrir mas host? s/n (Recomendado para LAN) $RESET"
	read smbclient

    if [ $smbclient == 's' ]
   then     
		
		echo -e "\t $OKBLUE ##### Realizando escaneo smclient en busca de mas hosts vivos ##### $RESET"	  
		
		######## preliminar join arp + ping +smb + mass scan + DNS to review more hosts
		cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list 2>/dev/null | sort | uniq > $live_hosts #2>/dev/null 
		sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
		##################  
     
		for ip in `cat $live_hosts`;			
		do 		
			smbclient -L $ip -U "%"  | egrep -vi "comment|---|master|Error|reconnecting|failed" | awk '{print $1}' >> .escaneos/smbclient.txt 2>/dev/null
		done
		cat .escaneos/smbclient.txt | uniq | sort > .escaneos/smbclient2.txt

		for hostname in `cat .escaneos/smbclient2.txt`;
		do 			
			host $hostname | grep "has address" | cut -d " " -f 4 >> $smbclient_list
		done
				
        
        echo -e  "\n##############################################################################" 
        echo -e  "$OKGREEN Con el escaneo de smbclient encontramos estos hosts vivos: $RESET" 
        cat $smbclient_list
        echo ""             
	  ##################################################################################### 
	
   fi   
	##################
	

    
    echo -e  "\n##############################################################################" 
    ############ Generando lista ###########
   
    
     ######## Final join arp + ping +smb + mass scan + DNS + smbclient
	 cat $dns_list $smb_list $mass_scan_list $ping_list $arp_list $smbclient_list 2>/dev/null | sort | uniq > $live_hosts #2>/dev/null 
	 sed -i '/^\s*$/d' $live_hosts # delete empty lines	          
     ##################     
        
     echo "Revisar si hay host que no debemos escanear ($live_hosts). Presionar ENTER para continuar"
     read n	    	 
	 cat $live_hosts | cut -d . -f 1-3 | uniq > .datos/subnets.txt # generate subnets 
	  
	  echo -e  "\n##############################################################################" 
      echo -e  "$OKGREEN TOTAL HOST VIVOS ENCONTRADOS: $RESET" 
      cat $live_hosts
      echo ""                  
 fi # if FILE

###### #check host number########
total_hosts=`wc -l .datos/total-host-vivos.txt | sed 's/.datos\/total-host-vivos.txt//g' `
echo -e  "$OKGREEN TOTAL HOST VIVOS ENCONTRADOS: $total_hosts hosts $RESET" 

#if [ $total_hosts -gt 490 ] ; then	  	 
	#echo "Muchos hosts. Dividir el archivo .datos/total-host-vivos.txt y volver a ejecutar lanscanner"	
	#echo -e "\tlanscanner.sh -t completo -f lista.txt"
	#exit
#fi
#################################  

######################################### end discover live hosts #########################################



# FASE: 2
echo -e "\n$OKRED [+] FASE 2: ESCANEO DE PUERTOS,VoIP, etc $RESET"
######################################### Escanear (voip,smb,ports,etc) #########################################
echo -e "$OKGREEN################################## Escaneando ######################################$RESET"

echo -e "\n\t $OKBLUE Proceder con el escaneo? ENTER $RESET"
read enter

echo -e "$OKBLUE\n\t ¿Estamos escaneado IPs publicas? s/n $RESET"	  
read internet
      
########### searching VoIP devices ##########
if [ $internet == "n" ]; then 	

  if [ $TYPE = "parcial" ] ; then 	
	echo -e "\n\t $OKBLUE Realizar escaneo VoIP ? s/n $RESET"
    read resp_voip
  fi
  
 #if [[ ( ${TYPE} == "completo" || ${resp_voip} == "s" ) && (${FILE} = NULL )]];then 
  if [[ ${TYPE} == "completo" || ${resp_voip} == "s" ]];then 
	echo -e "$OKBLUE\n\t#################### Buscando dispositivos VoIP: ######################$RESET"	  
	
	for subnet in $(cat .datos/subnets.txt); do
	  echo -e "\t Escaneando $subnet.0/24"	  
	  svmap $subnet".0/24" > enumeracion/$subnet-voip.txt 2>/dev/null 
    done;	
  fi
fi  
 ############################################
  
 
  
   
	
############################################
  
  
  ########### shared resource escaneando ##########
 if [ $TYPE = "parcial" ] ; then
	echo -e "\n	$OKBLUE Buscar recursos compartidos?: s/n $RESET"	
    read resp_shared
  fi
  
 #if [[ $TYPE = "completo" ]] || [ $resp_shared == "s" ]; then 
  
#	echo -e "$OKBLUE\n\t#################### Buscando recursos compartidos ######################$RESET"	  
	#mkdir -p .shared/	
	#cp $live_hosts .shared/
	
	#echo -e "\t $OKBLUE Realizare la copia de archivos compartidos? s/n $RESET"
	#read copy_shared
#	copy_shared="n"

	#if [ $copy_shared == 's' ]
    #then
	#echo -e "\t $OKBLUE Tamaño maximo de archivos a copiar de los recursos compartidos (Mb)? $RESET"
	#read max_file_size

	#mkdir -p copied/
	#echo -e "\t $OKBLUE Donde guardare los archivos compartidos? ej `pwd`/copied/ $RESET"
	#read dir_shared    
	#fi
		
	###########################################

	#if [ $FILE != NULL ] || [ $scan_type == 's' ] ; then
 
  	  #echo "Realizando escaneo con nbtscan"
      #nbtscan -f .datos/total-host-vivos.txt | grep ^1 | awk '{print $1}' | tee -a $smb_list
    #fi
	
	#cd .shared/
	#scan_shared_docs.pl ../$live_hosts
	
	#grep --color=never -i disk * | grep -v '\$|' | grep -v "\$ip =" > ../reportes/shared_files.txt
	
	#if [ $copy_shared = "s" ] ; then
	#echo -e "\n	$OKBLUE Copiando recursos compartidos $RESET"	
	#get_shared_docs.pl $max_file_size $dir_shared    
    #fi
    
    #cd ../
	
  #fi
  ############################################


   
if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	echo -e "$OKBLUE\n\t#################### Escaneo de puertos TCP ######################$RESET"	  
	
	echo -e "\t $OKBLUE Configurar escaneo de puertos TCP: $RESET"
	echo -e "\t\t $OKGREEN Opcion 1: Solo puertos WEB (80,3306,etc): $RESET"
	echo -e "\t\t $OKGREEN Opcion 2: Los 1000 puertos mas usados: $RESET"
	echo -e "\t\t $OKGREEN Opcion 3: Los 65535 puertos: $RESET"
	echo -e "\t $OKBLUE Escribe el numero de la opcion: $RESET"
	
	read port_scan_num
	
	echo "	## Cuantas instancias de nmap permitiremos (5-15) ##"       	
	read max_nmap_ins  
	
	if [ $port_scan_num == '1' ]        	    
	then
     	echo "	## Realizando escaneo de puertos especificos (Web, SSH, Telnet,SMB, etc) ##"  
     	nmap -n -iL $live_hosts -sV -p21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,8080 -oG .nmap/nmap-tcp.grep >> reportes/nmap-tcp.txt 2>/dev/null     	     	
     fi	
     
     
     if [ $port_scan_num == '2' ]   
     then   	
     	echo "	## Realizando escaneo de puertos especificos (informix, Web services) ##"  
     	nmap -n -iL $live_hosts -p82,83,84,85,37777,5432,3306,1525,1530,1526,1433,8728,1521 -oG .nmap/nmap2-tcp.grep >> reportes/nmap-tcp.txt 2>/dev/null       	
     	sleep 2;        			
			
     	echo "	## Realizando escaneo tcp en (solo 1000 puertos) ##"       	
     	while read ip           
		do    			
			nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
			#echo "instancias de nmap ($nmap_instances)"
			if [ "$nmap_instances" -lt $max_nmap_ins ] #Max 5 instances
				then
					#echo "nmap $ip"
					nmap -n $ip -oG .nmap_1000p/$ip-tcp.grep > .nmap_1000p/$ip-tcp.txt 2>/dev/null &					
					sleep 0.2;	
				else				
					while true; do
						echo "Max instancias de nmap ($nmap_instances)"
						sleep 10;
						nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
						if [ "$nmap_instances" -lt $max_nmap_ins ] #Max 5 instances
						then							
							break
						fi							
					done										
				fi		
		done <$live_hosts

     	
     	#nmap -n -iL $live_hosts -sV -oG .nmap/nmap1-tcp.grep > reportes/nmap-tcp.txt 2>/dev/null       	
     	
     	while true; do
		nmap_instances=`pgrep nmap | wc -l`			
						
		if [ "$nmap_instances" -gt 0  ];then	
			echo "Todavia hay escaneos de nmap ($nmap_instances) activos"  
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
			echo "	[+] Escaneando todos los puertos de $ip con mass-escaneando (TCP)"   		
			masscan -p1-65535 --rate 700 $ip --output-format grepable --output-filename .masscan/$ip.tcp 2>/dev/null ;
			ports=`cat .masscan/$ip.tcp  | grep -o "[0-9][0-9]*/open" | tr '\n' ',	' | tr -d '/open'`		
			num_ports=`echo $ports | tr -cd ',' | wc -c`		

			if [ "$num_ports" -gt 35 ]
			then
				echo "Sospechoso!!. Muchos puertos abiertos ($num_ports)"
			else				
				echo -e "	[+] Identificando servicios de $ip ($ports)"
				nmap -n -sV -O -p $ports $ip -oG .escaneos/$ip-tcp.grep2 >> reportes/nmap-tcp.txt 2>/dev/null &						
			fi					                            			
        done 
        
        cat .escaneos/*.grep2 > .nmap/nmap-tcp.grep       
                       
     fi      
     	
 fi 
    

################### TCP/UDP escaneo  ###################
 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n \t $OKBLUE Realizar escaneo de puertos UDP?: s/n $RESET"
    read udp_scan
 fi

 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n \t $OKBLUE Realizar escaneo de puertos TCP?: s/n $RESET"
    read tcp_scan
  fi
   

 if [[ $TYPE = "completo" ]] || [ $udp_escaneando == "s" ]; then 	
    echo -e "$OKBLUE\n\t#################### Escaneo de puertos UDP ######################$RESET"	  
       
		
	nmap -n -sU -p 53,161,500,67,1604  -iL $live_hosts -oG .nmap/nmap-udp.grep > reportes/nmap-udp.txt 2>/dev/null 
		
	
	if [ $internet == "n" ]; then 	
	
		for subnet in $(cat .datos/subnets.txt); do
			echo -e "\t Escaneando $subnet.0/24"	  
			masscan --interface $iface -pU:161 $subnet".0/24" | grep --color=never -i Discovered  > .masscan/$subnet-snmp.txt 2>/dev/null 
			masscan --interface $iface -pU:500 $subnet".0/24" | grep --color=never -i Discovered  > .masscan/$subnet-vpn.txt 2>/dev/null 
			masscan --interface $iface -pU:67 $subnet".0/24" | grep --color=never -i Discovered  > .masscan/$subnet-dhcp.txt 2>/dev/null 
		done;    
    fi	
	
	echo ""			
 fi	      
    
########## making reportes #######
if [[ $TYPE == "completo"  || $tcp_escaneando == "s"   || $udp_escaneando == "s" ]] ; then 
	echo -e "\t#### Creando reporte nmap ###"      
	# clean tcp wrapped
	
	#if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	#	cd reportes
	#	cat nmap-tcp2.txt | grep -v tcpwrapped > nmap-tcp.txt    
	#	rm nmap-tcp2.txt
	#	cd ..
	#fi
	
		
	# replace IP with subdomain
	#cat nmap-tcp.grep  | grep -v "Status: Up" >nmap-tcp.grep
	#rm nmap-tcp.grep
	#for domain in `grep "Nmap escaneando reportes for" nmap-tcp.txt | cut -d " " -f 5`
	#do	   	             
		# echo "domain $domain"			
		#sed -i "1,/[0-9]\{2,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/s/[0-9]\{2,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/$domain/g" nmap-tcp.grep
	#done	  
	#### generar reporte nmap ######   
	cd .nmap
	report-open-ports.pl -l ../$live_hosts -t nmap-tcp.grep -u nmap-udp.grep
	cd ../
fi
##########################################  
  
########################################## Ordernar IPs por servicio ##########################################
if [[ $TYPE = "completo" ]] || [ $tcp_escaneando == "s" ]; then 
	cd .nmap	
					
	grep '/rtsp/' nmap-tcp.grep | grep --color=never -o -P '(?<=Host: ).*(?=\(\))'>../.servicios/ip-cameras.txt
	grep '/http-proxy/' nmap-tcp.grep | grep --color=never -o -P '(?<=Host: ).*(?=\(\))'>../.servicios/proxy-http.txt
	
	
	#web
	grep " 80/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:80\n"' > ../.servicios/web.txt	
	grep " 81/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:81\n"' >> ../.servicios/web.txt	
	grep " 82/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:82\n"' >> ../.servicios/web.txt	
	grep " 83/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:83\n"' >> ../.servicios/web.txt	
	grep " 84/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:84\n"' >> ../.servicios/web.txt	
	grep " 85/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:85\n"' >> ../.servicios/web.txt	
	grep " 86/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:86\n"' >> ../.servicios/web.txt	
	grep " 87/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:87\n"' >> ../.servicios/web.txt	
	grep " 88/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:88\n"' >> ../.servicios/web.txt	
	grep " 89/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:89\n"' >> ../.servicios/web.txt	
	grep " 8080/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8080\n"' >> ../.servicios/web.txt	
	grep " 8081/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8081\n"' >> ../.servicios/web.txt	
	grep " 8010/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8010\n"' >> ../.servicios/web.txt	
	
	# web-ssl
	grep " 443/open" nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:443\n"' > ../.servicios/web-ssl.txt
	grep " 8443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8443\n"' >> ../.servicios/web-ssl.txt
	grep " 4443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4443\n"' >> ../.servicios/web-ssl.txt
	grep " 4433/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4433\n"' >> ../.servicios/web-ssl.txt
		
	grep ' 21/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:21\n"' >> ../.servicios/ftp.txt
	grep ' 513/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:513\n"' >> ../.servicios/rlogin.txt
	## ssh																	del newline       add port
	grep ' 22/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:22\n"' >> ../.servicios/ssh.txt
	grep ' 6001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6001\n"' >> ../.servicios/ssh.txt
	grep ' 23/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:23\n"' >> ../.servicios/telnet.txt
	
	## smtp																	del newline       add port
	grep ' 25/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:25\n"' >> ../.servicios/smtp.txt
	grep ' 587/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:587\n"' >> ../.servicios/smtp.txt
	grep ' 465/open' nmap-tcp.grep | awk '{print $2}'| perl -ne '$_ =~ s/\n//g; print "$_:465\n"'  >> ../.servicios/smtp.txt
	grep ' 110/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:110\n"' >> ../.servicios/pop.txt 
	grep ' 143/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:143\n"' >> ../.servicios/imap.txt 
	grep ' 10000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:10000\n"' >> ../.servicios/webmin.txt 
	grep ' 111/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:111\n"' >> ../.servicios/rpc.txt 
  
	## ldap																	del newline       add port
	grep ' 389/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:389\n"' >> ../.servicios/ldap.txt
	grep ' 636/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:636\n"' >> ../.servicios/ldaps.txt
  
  
	### SMB 														   del newline       add port
	grep ' 445/open' nmap-tcp.grep | awk '{print $2}' >> ../.servicios/smb2.txt
	grep ' 139/open' nmap-tcp.grep | awk '{print $2}' >> ../.servicios/smb2.txt
	sort ../.servicios/smb2.txt | uniq > ../.servicios/smb.txt;rm ../.servicios/smb2.txt
	grep ' 139/open' nmap-tcp.grep | awk '{print $2}' >> ../.servicios/smb-139.txt
			

    
	# Java related
	grep ' 8009/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8009\n"' >> ../.servicios/java.txt
	grep ' 9001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9001\n"' >> ../.servicios/java.txt
			# database ports 														   del newline       add port
	grep ' 1525/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1525\n"' | sort | uniq >> ../.servicios/informix.txt
	grep ' 1530/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1530\n"' | sort | uniq >> ../.servicios/informix.txt
	grep ' 1526/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1526\n"' | sort | uniq >> ../.servicios/informix.txt	
	
	
	grep ' 1521/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1521\n"' | sort | uniq >> ../.servicios/oracle.txt
	grep ' 1630/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1630\n"' | sort | uniq >> ../.servicios/oracle.txt
	grep ' 5432/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5432\n"' | sort | uniq >> ../.servicios/postgres.txt     
	grep ' 3306/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3306\n"' | sort | uniq >> ../.servicios/mysql.txt 
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
	grep ' 6000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6000\n"' >> ../.servicios/x11.txt
	grep ' 631/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:631\n"' >> ../.servicios/cups.txt
	grep ' 9100/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:9100\n"' >> ../.servicios/printers.txt	
	grep ' 2049/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:2049\n"' >> ../.servicios/nfs.txt
	grep ' 5723/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5723\n"' >> ../.servicios/SystemCenter.txt
	grep ' 5724/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5724\n"' >> ../.servicios/SystemCenter.txt
	grep ' 1099/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1099\n"' >> ../.servicios/rmi.txt
	grep ' 1433/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' | sort | uniq >> ../.servicios/mssql.txt 
	grep ' 37777/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3777\n"' >> ../.servicios/dahua.txt 	
	
	#Esp
	grep ' 16992/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' >> ../.servicios/intel.txt 	
	
	grep ' 47808/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:47808\n"' >> ../.servicios/scada.txt 	
	grep ' 502/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:502\n"' >> ../.servicios/scada.txt 	



		
		
	cd ..
fi
    
  
  
 ##################UDP#########
if [[ $TYPE = "completo" ]] || [ $udp_escaneando == "s" ]; then 
	cd .nmap
	grep 53/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:53\n"' >> ../.servicios/dns.txt
	
	grep 161/open/ nmap-udp.grep | awk '{print $2}'  >> ../.servicios/snmp2.txt	
	grep '161/udp' ../.masscan/* 2>/dev/null| cut -d " " -f 6 >> ../.servicios/snmp2.txt
	sort ../.servicios/snmp2.txt | uniq >../.servicios/snmp.txt; rm ../.servicios/snmp2.txt
	
	grep 67/open/ nmap-udp.grep | awk '{print $2}'  >> ../.servicios/dhcp2.txt	
	grep '67/udp' ../.masscan/* 2>/dev/null | cut -d " " -f 6 >> ../.servicios/dhcp2.txt
	sort ../.servicios/dhcp2.txt | uniq >../.servicios/dhcp.txt; rm ../.servicios/dhcp2.txt
	
	grep 500/open/ nmap-udp.grep | awk '{print $2}'  >> ../.servicios/vpn2.txt
	grep '500/udp' ../.masscan/* 2>/dev/null | cut -d " " -f 6 >> ../.servicios/vpn2.txt
	sort ../.servicios/vpn2.txt | uniq >../.servicios/vpn.txt; rm ../.servicios/vpn2.txt
	
	grep 1604/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1604\n"' >> ../.servicios/citrix.txt
	grep 1900/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1900\n"' >> ../.servicios/upnp.txt
	cd ../
fi
        
find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
 ################################
  
   
echo "######################################################################################### "


fi # enumerar

# FASE: 3
echo -e "\n\n$OKRED [+] FASE 3: ENUMERACION DE PUERTOS E IDENTIFICACION DE VULNERABILIDADES $RESET"
###################################  ENUMERACION ########################################
echo -e "$OKGREEN#################################### EMPEZANDO ENUMERACION ########################################$RESET"  

if [ -f .servicios/smb.txt ]
then  
	echo -e "$OKBLUE\n\t#################### SMB (`wc -l .servicios/smb.txt`) ######################$RESET"	
	mkdir -p .smbinfo/
	for ip in $(cat .servicios/smb.txt); do							
		echo -e "\n\t### $ip (port 445)"				
		#,smb-vuln-ms10-061,,smb-vuln-ms06-025,smb-vuln-ms07-029 
		nmap -n -p445 --script smb-vuln-ms08-067,smb-vuln-ms17-010 $ip > logs/vulnerabilidades/$ip-445-nmap.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-445-nmap.txt | egrep -v "ACCESS_DENIED|false" > vulnerabilidades/$ip-445-nmap.txt  
		
		smbmap -H $ip -u anonymous -p anonymous > logs/enumeracion/$ip-445-shared.txt 2>/dev/null
		egrep --color=never "READ|WRITE" logs/enumeracion/$ip-445-shared.txt > enumeracion/$ip-445-shared.txt
		
		smbmap -H $ip  >> logs/enumeracion/$ip-445-shared.txt 2>/dev/null
		egrep --color=never "READ|WRITE" logs/enumeracion/$ip-445-shared.txt >> enumeracion/$ip-445-shared.txt
		
			
		########## making reportes #######
		echo -e "\t Obteniendo OS/DOMAIN" 		
		cp $live_hosts .smbinfo/
		nmap -n -Pn --script smb-os-discovery.nse -p445 $ip | grep "|"> .smbinfo/$ip.txt	

		################################										
	done
		echo -e "\t#### Creando reporte (OS/Domain/users) ###" 		
		cd .smbinfo/
		report-OS-domain.pl total-host-vivos.txt 2>/dev/null
		cd ..
	
	#insert clean data	
	insert_data
fi

grep -i windows reportes/reporte-OS.txt | cut -d ";" -f 1 >> .servicios/Windows.txt

#if [ -f .servicios/smb-139.txt ]
#then
	#echo -e "$OKBLUE\n\t#################### SMB (`wc -l .servicios/smb-139.txt`) ######################$RESET"	
	#for ip in $(cat .servicios/smb-139.txt); do		
		
		#nmap -n -Pn --script=samba-vuln-cve-2012-1182  -p 139 $ip > logs/vulnerabilidades/$ip-139-vuln.txt 2>/dev/null
		#grep "|" logs/vulnerabilidades/$ip-139-vuln.txt | egrep -vi "failed|DENIED|ERROR|aborting|Couldnt|Sorry" > vulnerabilidades/$ip-139-vuln.txt	
		
	#done
#fi

#####################################


if [ -f .servicios/ip-cameras.txt ]
then
	echo -e "$OKBLUE\n\t#################### Camaras IP (`wc -l .servicios/ip-cameras.txt`) ######################$RESET"	  
	for line in $(cat .servicios/ip-cameras.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`						
		echo -e "\n\t### $ip"
		nmap -n -sV -p 554 --script=rtsp-url-brute $ip > logs/vulnerabilidades/$ip-554-openstreaming.txt 2>/dev/null 
		grep "|" logs/vulnerabilidades/$ip-554-openstreaming.txt > vulnerabilidades/$ip-554-openstreaming.txt 		
	done
	
		# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'ftp|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data		
fi


if [ -f .servicios/mysql.txt ]
then
	echo -e "$OKBLUE\n\t#################### MY SQL (`wc -l .servicios/mysql.txt`) ######################$RESET"	  
	for line in $(cat .servicios/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t### $ip"	
				
		#echo  -e "\tRevisar vulnerabilidades"
		#nmap -n -p $port --script=mysql-vuln-cve2012-2122 $ip > logs/vulnerabilidades/$ip-mysql-vuln.txt 2>/dev/null
		#grep "|" logs/vulnerabilidades/$ip-mysql-vuln.txt | grep -v "failed" > vulnerabilidades/$ip-mysql-vuln.txt 	
					
	done
	
		# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'ftp|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	
fi

if [ -f .servicios/mongoDB.txt ]
then
	echo -e "$OKBLUE\n\t#################### MongoDB (`wc -l .servicios/mongoDB.txt`) ######################$RESET"
	for line in $(cat .servicios/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		nmap -n -sV -p $port --script=mongodb-databases,mongodb-info $ip  > logs/enumeracion/$ip-monogodb.txt 2>/dev/null 
		grep "|" logs/enumeracion/$ip-monogodb.txt > enumeracion/$ip-monogodb.txt 			
	done
	
	#insert clean data	
	insert_data	
fi


if [ -f .servicios/couchDB.txt ]
then
	echo -e "$OKBLUE\n\t#################### couchDB ######################$RESET"
	for line in $(cat .servicios/couchDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		nmap -n -sV -p $port --script=couchdb-databases,couchdb-stats $ip > logs/enumeracion/$ip-couchdb.txt 2>/dev/null
		grep "|" logs/enumeracion/$ip-couchdb.txt > enumeracion/$ip-couchdb.txt 
	done
	
	#insert clean data	
	insert_data	
fi

######################################

if [ -f .servicios/x11.txt ]
then
	echo -e "$OKBLUE\n\t#################### X11 (`wc -l .servicios/x11.txt`)  ######################$RESET"	  
	for line in $(cat .servicios/x11.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
				
		nmap -n $ip --script=x11-access.nse > logs/enumeracion/$ip-x11.txt 2>/dev/null 
		grep "|" logs/enumeracion/$ip-x11.txt > enumeracion/$ip-x11.txt 
	done	
	
	#insert clean data	
	insert_data
fi

if [ -f .servicios/rpc.txt ]
then
	echo -e "$OKBLUE\n\t#################### RPC (`wc -l .servicios/rpc.txt`)  ######################$RESET"	  
	for line in $(cat .servicios/rpc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
				
		nmap -n -p $port $ip --script=nfs-ls.nse,rpcinfo > logs/enumeracion/$ip-rpc.txt 2>/dev/null 
		grep "|" logs/enumeracion/$ip-rpc.txt > enumeracion/$ip-rpc.txt 
		
	done	
	
	#insert clean data	
	insert_data	
fi



if [ -f .servicios/upnp.txt ]
then
	echo -e "$OKBLUE\n\t#################### upnp(`wc -l .servicios/upnp.txt`)   ######################$RESET"	    
	for line in $(cat .servicios/upnp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		nmap -n -sU -p $port $ip --script=upnp-info, broadcast-upnp-info > enumeracion/$ip/upnp.txt 2>/dev/null &
			
	done
	
	#insert clean data	
	insert_data
fi


if [ -f .servicios/redis.txt ]
then	
	echo -e "$OKBLUE\n\t#################### Redis (`wc -l .servicios/redis.txt`) ######################$RESET"	    
	for line in $(cat .servicios/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		nmap -n -p $port $ip --script redis-info > logs/enumeracion/$ip-redis.txt 2>/dev/null
		grep "|" logs/enumeracion/$ip-redis.txt  > enumeracion/$ip-redis.txt						
	done
	
	#insert clean data	
	insert_data	
fi

if [ -f .servicios/rmi.txt ]
then	
	echo -e "$OKBLUE\n\t#################### RMI (`wc -l .servicios/rmi.txt`) ######################$RESET"	    
	for line in $(cat .servicios/rmi.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		nmap -n -p $port $ip --script rmi-vuln-classloader > logs/vulnerabilidades/$ip-rmi-vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-rmi-vuln.txt  > vulnerabilidades/$ip-rmi-vuln.txt
		
	done
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'ftp|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi


if [ -f .servicios/ftp.txt ]
then
	echo -e "$OKBLUE\n\t#################### FTP (`wc -l .servicios/ftp.txt`) ######################$RESET"	    
	touch 68b329da9893e34099c7d8ad5cb9c940.txt # file to test upload
	for line in $(cat .servicios/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t### $ip"				
		#nmap -n -sV -Pn -p $port $ip --script=ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 > enumeracion/$ip-ftp-vuln.txt 2>/dev/null &
		echo  "escaneando $ip (ftp - banner)"
		echo "LIST" | nc -w 3 $ip 21 > enumeracion/$ip-21-banner.txt 2>/dev/null &					
		echo  "escaneando $ip (ftp - anonymous)"
		ftp-anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt > vulnerabilidades/$ip-21-anonymous.txt 2>/dev/null &	
		sleep 5
	done	
	rm 68b329da9893e34099c7d8ad5cb9c940.txt 2>/dev/null
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'ftp|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
	
fi


if [ -f .servicios/telnet.txt ]
then
	echo -e "$OKBLUE\n\t#################### TELNET (`wc -l .servicios/telnet.txt`)######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		

		echo -e "\t Default Pass (telnet)"
		medusa -u root -p vizxv -h $ip -M telnet > logs/vulnerabilidades/$ip-23-passwordDahua.txt 2>/dev/null
		grep --color=never SUCCESS logs/vulnerabilidades/$ip-23-passwordDahua.txt > vulnerabilidades/$ip-23-passwordDahua.txt 					
					
		echo  "escaneando $ip (telnet - banner)"
		nc -w 3 $ip 23 <<<"print_debug" > enumeracion/$ip-23-banner.txt 2>/dev/null
		sed -i -e "1d" enumeracion/$ip-23-banner.txt 2>/dev/null																
		cp enumeracion/$ip-23-banner.txt logs/enumeracion/$ip-23-banner.txt
	done <.servicios/telnet.txt

	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'finger|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
		
	#insert clean data	
	insert_data
		
fi




if [ -f .servicios/finger.txt ]
then
	echo -e "$OKBLUE\n\t#################### FINGER ######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d";"`		
		echo  "escaneando $ip (finger)"
		finger @$ip > enumeracion/$ip-69-users.txt &
		sleep 1
					# done true				        	        				
	done < .servicios/finger.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'finger|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
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
	echo -e "$OKBLUE\n\t#################### VPN (`wc -l .servicios/vpn.txt`) ######################$RESET"	    
	for ip in $(cat .servicios/vpn.txt); do		
			
		echo -e "\n\t### $ip"
		ike=`ike-scan -M $ip`
		if [[ $ike == *"HDR"* ]]; then
			echo $ike > enumeracion/$ip-500-transforms.txt
			cp enumeracion/$ip-500-transforms.txt logs/enumeracion/$ip-500-transforms.txt
			ike-scan -A -M --pskcrack=enumeracion/$ip-500-handshake.txt $ip 2>/dev/null ;
		fi			
	done
	
	
	#insert clean data	
	insert_data

fi

if [ -f .servicios/vnc.txt ]
then
	echo -e "$OKBLUE\n\t#################### VNC (`wc -l .servicios/vnc.txt`) ######################$RESET"	    
	for line in $(cat .servicios/vnc.txt); do		
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "\n\t### $ip ($port)"					
		#vnc_response=`echo "a" | nc -w 3 $ip $port`
		#if [[ ${vnc_response} == *"RFB 003.008"* ]];then
			#echo "VNC bypass ($vnc_response)" > vulnerabilidades/$ip-$port-bypass.txt 
		#fi	
		
		msfconsole -x "use auxiliary/scanner/vnc/vnc_none_auth;set RHOSTS $ip; set rport $port;run;exit" > logs/vulnerabilidades/$ip-$port-nopass.txt 2>/dev/null		
		grep --color=never -i "None" logs/vulnerabilidades/$ip-$port-nopass.txt  > vulnerabilidades/$ip-$port-nopass.txt 
		
		nmap -n -p $port --script realvnc-auth-bypass $ip > logs/vulnerabilidades/$ip-$port-bypass2.txt 2>/dev/null
		grep "|" logs/vulnerabilidades/$ip-$port-bypass2.txt > vulnerabilidades/$ip-$port-bypass2.txt
	done
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi


# enumerar MS-SQL
if [ -f .servicios/mssql.txt ]
then
	echo -e "$OKBLUE\n\t#################### MS-SQL (`wc -l .servicios/mssql.txt`) ######################$RESET"	    
	while read line           
	do   	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "\n\t### $ip ($port)"	
		nmap -sU -n -sV -p 1434 --host-timeout 10s --script ms-sql-info $ip > logs/enumeracion/$ip-1434-info.txt  2>/dev/null
		grep "|" logs/enumeracion/$ip-1434-info.txt  > enumeracion/$ip-1434-info.txt 
					
	done <.servicios/mssql.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi
		

#LDAPS
if [ -f .servicios/ldaps.txt ]
then
	echo -e "$OKBLUE\n\t#################### LDAPS (`wc -l .servicios/ldaps.txt`) ######################$RESET"	    
	while read line       
	do     					
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "\n\t### $ip "			
		domain=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g'`
				
		if [ -z "$domain" ]; then
			domain=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g'`
		fi
		
		
		echo $domain > enumeracion/$ip-$port-domain.txt
		domain=`echo $domain | head -1`
		ldapsearch -x -p $port -h $ip -b $domain -s sub "(objectclass=*)" > logs/enumeracion/$ip-$port-directory.txt 
		
		egrep -i "successful bind must be completed|Not bind" logs/enumeracion/$ip-$port-directory.txt 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Requiere autenticacion"
		else
			cp logs/enumeracion/$ip-$port-directory.txt enumeracion/$ip-$port-directory.txt 
		fi
													 
	done <.servicios/ldaps.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi

#VMWARE
if [ -f .servicios/vmware.txt ]
then
	echo -e "$OKBLUE\n\t#################### vmware (`wc -l .servicios/vmware.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		#nmap -n --script vmware-version -p443 $ip > logs/enumeracion/$ip-vmware-version.txt 2>/dev/null
		#grep "|" logs/enumeracion/$ip-vmware-version.txt > enumeracion/$ip-vmware-version.txt 
													 
	done <.servicios/vmware.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi


#CITRIX
if [ -f .servicios/citrix.txt ]
then
	echo -e "$OKBLUE\n\t#################### citrix (`wc -l .servicios/citrix.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -sU --script=citrix-enum-apps -p 1604 $ip > logs/enumeracion/$ip-citrix-app.txt 2>/dev/null
		nmap -n -sU --script=citrix-enum-servers -p 1604  $ip > logs/enumeracion/$ip-citrix-servers.txt 2>/dev/null
		
		grep "|" logs/enumeracion/$ip-citrix-app.txt > enumeracion/$ip-citrix-app.txt 
		grep "|" logs/enumeracion/$ip-citrix-servers.txt > enumeracion/$ip-citrix-servers.txt 
													 
	done <.servicios/citrix.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	
fi

#	dahua

if [ -f .servicios/dahua.txt ]
then
	echo -e "$OKBLUE\n\t#################### DAHUA (`wc -l .servicios/dahua.txt`)######################$RESET"	    
	while read line       
	do     			
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		echo -e "\n\t### ($ip) "						
		echo -e "\t Bypass"		
		msfconsole -x "use auxiliary/scanner/misc/dahua_dvr_auth_bypass;set RHOSTS $ip; set ACTION USER;run;exit" > logs/vulnerabilidades/$ip-dahua-vuln.txt 2>/dev/null		
		grep --color=never "37777" logs/vulnerabilidades/$ip-dahua-vuln.txt  > vulnerabilidades/$ip-dahua-vuln.txt 
															
	done <.servicios/dahua.txt
			
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
	
fi

#INTEL
if [ -f .servicios/intel.txt ]
then
	echo -e "$OKBLUE\n\t#################### intel (`wc -l .servicios/intel.txt`) ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -p 16992 --script http-vuln-cve2017-5689 $ip > logs/vulnerabilidades/$ip-intel-bypass.txt 2>/dev/null			
		grep "|" logs/vulnerabilidades/$ip-intel-bypass.txt > vulnerabilidades/$ip-intel-bypass.txt
													 
	done <.servicios/intel.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi




if [ -f .servicios/snmp.txt ]
then
	echo -e "$OKBLUE\n\t#################### SNMP (`wc -l .servicios/snmp.txt`) ######################$RESET"	    
	echo  "escaneando (snmp - onesixtyone)"
	onesixtyone -c /usr/share/lanscanner/community.txt -i .servicios/snmp.txt  | grep --color=never "\[" | sed 's/ \[/~/g' |  sed 's/\] /~/g' | sort | uniq > banners-snmp2.txt

	while read line; do
		ip=`echo $line | cut -f1 -d"~"`
		community=`echo $line | cut -f2 -d"~"`
		device=`echo $line | cut -f3 -d"~"`
		
		echo  "escaneando $ip (snmp - $community )"
		### snmp write ##
		snmp-write.pl -t $ip -c $community > enumeracion/$ip-161-$community.txt 2>/dev/null &										
				
		### snmp bruteforce ##				
		
		if [[ ${device} == *"windows"*  ]];then 
			echo  "escaneando $ip (snmp - enumerate - windows)"
			snmpbrute.py -t $ip -c $community --windows --auto > enumeracion/$ip-161-enumerate.txt 2>/dev/null 
		fi	
		
		if [[ ${device} == *"SunOS"* || ${device} == *"SonicWALL"* || ${device} == *"SofaWare"* || ${device} == *"SRP521W"* || ${device} == *"RouterOS"* || ${device} == *"Cisco"* || ${device} == *"juniper"* ]];then 
			echo  "escaneando $ip (snmp - enumerate - router)"
			snmpbrute.py -t $ip -c $community --cisco --auto > enumeracion/$ip-161-enumerate.txt 2>/dev/null 
		fi								
			
		if [[ (${device} == *"linux"* || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
			echo  "escaneando $ip (snmp - enumerate - Linux)"
			snmpbrute.py -t $ip -c $community --linux --auto > enumeracion/$ip-161-enumerate.txt 2>/dev/null 
		fi										
					
		if [ ! -f enumeracion/$ip-161-enumerate.txt ]; then
			echo  "escaneando $ip (snmp - enumerate - generic)"
			snmpbrute.py -t $ip -c $community --linux --auto > enumeracion/$ip-161-enumerate.txt 2>/dev/null 
		fi
		cp enumeracion/$ip-161-enumerate.txt logs/enumeracion/$ip-161-enumerate.txt
		
	done <banners-snmp2.txt
	rm banners-snmp2.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
	##################################
fi


if [ -f .servicios/ldap.txt ]
then
	echo -e "$OKBLUE\n\t#################### LDAP (`wc -l .servicios/ldap.txt`) ######################$RESET"	    
	while read line          
	do        
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "\n\t### $ip "			
		domain=`nmap -n -p $port --script ldap-rootdse $ip | grep --color=never namingContexts | sed 's/|       namingContexts: //g'`
		echo $domain > enumeracion/$ip-$port-domain.txt
		domain=`echo $domain | head -1`
		ldapsearch -x -p $port -h $ip -b $domain -s sub "(objectclass=*)" > logs/enumeracion/$ip-$port-directory.txt 
		
		egrep -i "successful bind must be completed|Not bind" logs/enumeracion/$ip-$port-directory.txt 
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			echo -e "\t Requiere autenticacion"
		else
			cp logs/enumeracion/$ip-$port-directory.txt enumeracion/$ip-$port-directory.txt 
		fi
		
		
	done <.servicios/ldap.txt
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data
fi	


if [ -f .servicios/printers.txt ]
then
	echo -e "$OKBLUE\n\t#################### Printers (`wc -l .servicios/printers.txt`) ######################$RESET"	    		
	echo quit > command.txt
	for line in $(cat .servicios/printers.txt); do
        ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		echo -e "\n\t### $ip "	
		
		echo -e "\t PJL "			
		pret.sh --safe $ip pjl -i `pwd`/command.txt  > logs/enumeracion/$ip-9100-PJL.txt 2>/dev/null ;
		echo -e "\t PS "			
		pret.sh --safe $ip ps -i `pwd`/command.txt > logs/enumeracion/$ip-9100-PS.txt 2>/dev/null ;
				
		
		
		grep -i --color=never "found" logs/enumeracion/$ip-9100-PJL.txt | grep -iv "not|http" >> enumeracion/$ip-9100-printer2.txt 
		grep -i --color=never "found" logs/enumeracion/$ip-9100-PS.txt | grep -iv "not|http" >> enumeracion/$ip-9100-printer2.txt 		
		sort enumeracion/$ip-9100-printer2.txt  | uniq > enumeracion/$ip-9100-printer.txt 
		rm enumeracion/$ip-9100-printer2.txt 
			
    done;   
    rm command.txt
    
    # check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
    #insert clean data	
	insert_data
    
fi	



if [ -f .servicios/smtp.txt ]
	then
		echo -e "$OKBLUE\n\t#################### SMTP (`wc -l .servicios/smtp.txt`) ######################$RESET"	    
		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			
			echo  "escaneando $ip (smtp - vrfy,openrelay)"		
			vrfy-test.py $ip $port > enumeracion/$ip-$port-vrfy.txt 2>/dev/null &
			open-relay.py $ip $port > logs/enumeracion/$ip-$port-openrelay.txt 2>/dev/null 
			nc -w 3 $ip $port <<<"EHLO localhost"  enumeracion/$ip-$port-EHLO.txt 2>/dev/null
						
		done <.servicios/smtp.txt
		
		
		# check if we have any script running
		while true; do
		webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
		if [ "$webbuster_instances" -gt 1 ]
		then
			echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
			sleep 20
			else
				break		
			fi
		done	# done true	
	
		#insert clean data	
		insert_data
	
	fi


if [ -f .servicios/web.txt ]
then
      
     echo -e "$OKBLUE\n\t#################### WEB (`wc -l .servicios/web.txt`) ######################$RESET"	    
	for line in $(cat .servicios/web.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		
		perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
		if [ "$perl_instances" -lt $max_web_ins ] #Max 5 instances
		then						
			echo -e "\t[+] Obteniendo informacion web ($ip:$port)"	
			webData.pl -t $ip -p $port -s 0 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt > enumeracion/$ip-$port-webData.txt 2>/dev/null  &
			echo ""	
			sleep 0.1;	
												
		else				
			while true; do
				echo "Max instancias de perl ($max_web_ins)"
				sleep 5;
				perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
				if [ "$perl_instances" -lt $max_web_ins ] #Max 5 instances
				then	
					webData.pl -t $ip -p $port -s 0 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt > enumeracion/$ip-$port-webData.txt 2>/dev/null  &						
					break
				fi							
			done										
		 fi		
	done		
		
	 ######## wait to finish########
	  while true; do
		perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
		if [ "$perl_instances" -gt 0 ]
		then
			echo "Todavia hay escaneos de perl activos ($perl_instances)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	  ##############################


	for line in $(cat .servicios/web.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		checked=0
		
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
			if [[ $free_ram -gt $min_ram && $perl_instances -lt 80  ]];then 							
					
				#######  if the server is IIS ######
				grep -i IIS enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 && $checked -eq 0  ]];then 		
					checked=1
					echo -e "\n\t### $ip:$port "
				   #nmap -n -p $port --script http-vuln-cve2015-1635 $ip > logs/vulnerabilidades/$ip-$port-HTTPsys.txt 2>/dev/null 
					nmap -n -p $port --script=http-iis-webdav-vuln $ip > logs/vulnerabilidades/$ip-$port-webdav.txt 2>/dev/null 
					grep "|" logs/vulnerabilidades/$ip-$port-webdav.txt > vulnerabilidades/$ip-$port-webdav.txt 
					echo -e "\t### web-buster (IIS)"			
					web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &													
				fi
										
				####################################	
		
		
				#######  if the server is java ######
				egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" enumeracion/$ip-$port-webData.txt
				greprc=$?
				if [[ $greprc -eq 0 && $checked -eq 0  ]];then 		
					checked=1
					echo -e "\n\t### $ip:$port "			
					echo -e "\t### web-buster (JSP)"			
					web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &					
					#web-buster.pl -t $ip -p $port -h 5 -d / -m backup -s 0 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &							
					sleep 1
				fi
										
				####################################	
		
		
				#######  if the server is apache ######
				grep -i apache enumeracion/$ip-$port-webData.txt | egrep -iv "cisco|BladeSystem|oracle"
				greprc=$?
				if [[ $greprc -eq 0 && $checked -eq 0  ]];then 		
					checked=1			
					echo -e "\n\t### $ip:$port (Revisando vulnerabilidad Struts)"
					nmap -n -p $port $ip --script=http-vuln-cve2017-5638 > logs/vulnerabilidades/$ip-$port-Struts.txt 2>/dev/null  					
					grep "|" logs/vulnerabilidades/$ip-$port-Struts.txt > vulnerabilidades/$ip-$port-Struts.txt  	
					
					echo -e "\n\t### $ip:$port (Revisando vulnerabilidad cgi)"
					nmap -n -p $port $ip --script=http-vuln-cve2012-1823 > logs/vulnerabilidades/$ip-$port-cgi.txt 2>/dev/null  					
					grep "|" logs/vulnerabilidades/$ip-$port-cgi.txt > vulnerabilidades/$ip-$port-cgi.txt  	
			
					echo -e "\t### web-buster (apache)"
					web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 0 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
					web-buster.pl -t $ip -p $port -h 5 -d / -m cgi -s 0 -q 1 | grep --color=never ^200 | awk '{print $2}' >> .servicios/cgi.txt 
					#web-buster.pl -t $ip -p $port -h 5 -d / -m backup -s 0 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &										
					sleep 1
				fi						
				####################################						
			break
		else
			perl_instances=`ps aux | grep perl | wc -l`
			echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de perl ($perl_instances) "
			sleep 3
		fi
		done	# done true	
		
				
		if [ $OFFSEC = "1" ] ; then	
		
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			if [ "$free_ram" -gt 500 ]			
			then						
				
				echo -e "\t[+] Web-buster ..  $ip:$port"
				web-buster.pl -s $ip -p $port -t 20 -a / -m completo -l 2  -q 1 | grep --color=never ^200  > enumeracion/$ip-$ort-webusername.txt  &
				sleep 1
		
				#echo -e "\t[+] nikto ..  $ip:$port"
				#nikto -host http://$ip:$port > enumeracion/$ip-$port-nikto.txt  2>/dev/null &												
													
				break
			else
				ruby_instances=`pgrep ruby | wc -l`
				echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de nmap ($ruby_instances )"
				sleep 3
			fi
		done	# done true	OFFSEC
	    fi # if iffsec
	done	# done for                       
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
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
    
    echo -e "$OKBLUE\n\t#################### WEB - SSL (`wc -l .servicios/web-ssl.txt`) ######################$RESET"	    		

	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		
		perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
		if [ "$perl_instances" -lt $max_web_ins ] #Max 10 instances
		then
			echo -e "\t[+] Obteniendo informacion web $ip:$port"	
			webData.pl -t $ip -p $port -s 1 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt> enumeracion/$ip-$port-webData.txt 2>/dev/null  &			
			get_ssl_cert.py $ip $port  2>/dev/null | grep "("> enumeracion/$ip-$port-cert.txt  &
			echo ""	
			sleep 0.1;	
												
		else				
			while true; do
				echo "Max instancias de perl ($max_web_ins)"
				sleep 5;
				perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
				if [ "$perl_instances" -lt $max_web_ins ] #Max 10 instances
				then	
					webData.pl -t $ip -p $port -s 1 -e todo -d / -l logs/enumeracion/$ip-$port-webData.txt> enumeracion/$ip-$port-webData.txt 2>/dev/null  &			
					get_ssl_cert.py $ip $port 2>/dev/null | grep "("> enumeracion/$ip-$port-cert.txt  &
					break
				fi							
			done										
		  fi		
	done		
		
	 ######## wait to finish########
	  while true; do
		perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
		if [ "$perl_instances" -gt 0 ]
		then
			echo "Todavia hay escaneos de perl activos ($perl_instances)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	  ##############################


	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		checked=0
		
		
		while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`		
				perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
				if [[ $free_ram -gt $min_ram && $perl_instances -lt 80  ]];then 											
										
					#######  if the server is apache ######
					grep -i apache enumeracion/$ip-$port-webData.txt | egrep -iv "cisco|BladeSystem|oracle"
					greprc=$?
					if [[ $greprc -eq 0 ]] ; then						
						checked=1
						echo -e "\n\t### $ip:$port (Revisando vulnerabilidad Struts)"
						nmap -n -Pn -p $port $ip --script=http-vuln-cve2017-5638 > logs/vulnerabilidades/$ip-$port-Struts.txt 2>/dev/null  					
						grep "|" logs/vulnerabilidades/$ip-$port-Struts.txt > vulnerabilidades/$ip-$port-Struts.txt  	
			
						echo -e "\n\t### $ip:$port (Revisando vulnerabilidad cgi)"
						nmap -n -Pn -p $port $ip --script=http-vuln-cve2012-1823 > logs/vulnerabilidades/$ip-$port-cgi.txt 2>/dev/null  					
						grep "|" logs/vulnerabilidades/$ip-$port-cgi.txt > vulnerabilidades/$ip-$port-cgi.txt  	
			
						#echo -e "\t### web-buster"					
						web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 1 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
						web-buster.pl -t $ip -p $port -h 5 -d / -m webserver -s 1 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &									
						#web-buster.pl -t $ip -p $port -h 5 -d / -m cgi -s 1 -q 1 | grep --color=never ^200 | awk '{print $2}' >>.servicios/cgi.txt &
						#web-buster.pl -t $ip -p $port -h 5 -d / -m backup -s 1 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &		
						sleep 1;					
					fi						
					####################################
		
					#######  if the server is IIS ######
					grep -i IIS enumeracion/$ip-$port-webData.txt
					greprc=$?
					if [[ $greprc -eq 0 && $checked -eq 0  ]];then 		
						checked=1
						echo -e "\n\t### $ip:$port ( IIS - HTTPsys)"
						nmap -n -Pn -p $port --script http-vuln-cve2015-1635 $ip > logs/vulnerabilidades/$ip-$port-HTTPsys.txt 2>/dev/null 
						grep "|" logs/vulnerabilidades/$ip-$port-HTTPsys.txt > vulnerabilidades/$ip-$port-HTTPsys.txt 
				
						#echo -e "\t### web-buster"				
						web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 1 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
#						web-buster.pl -t $ip -p $port -h 5 -d / -m archivos -s 1 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &								
						sleep 1
						
					fi
										
					####################################
		
		
					#######  if the server is java ######
					egrep -i "GlassFish|Coyote|Tomcat|Resin|JBoss|WildFly" enumeracion/$ip-$port-webData.txt
					greprc=$?
					if [[ $greprc -eq 0 && $checked -eq 0  ]];then 		
						checked=1
						echo -e "\n\t### $ip:$port "			
						echo -e "\t### web-buster (JSP)"			
						web-buster.pl -t $ip -p $port -h 5 -d / -m admin -s 1 -q 1 | grep --color=never ^200 >> enumeracion/$ip-$port-webarchivos.txt  &			
						#web-buster.pl -t $ip -p $port -h 5 -d / -m archivos -s 1 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &						
						#web-buster.pl -t $ip -p $port -h 5 -d / -m backup -s 1 -q 1 | grep --color=never 200 >> enumeracion/$ip-$port-webarchivos.txt  &					
						sleep 1
					fi									
					####################################	
					
					break
				else
					perl_instances=`ps aux | grep perl | wc -l`
					echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de nmap ($perl_instances) "
					sleep 3
				fi
		done	# done true					
     done #for


	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
		if [ "$nmap_instances" -lt $max_nmap_ins ] #Max 5 instances
		then									
			echo -e "\n\t### $ip:$port (Vulnerabilidades SSL)"	
			nmap -n -Pn -p $port --script=ssl-heartbleed $ip > logs/vulnerabilidades/$ip-$port-heartbleed.txt 2>/dev/null &
			a2sv.sh -t $ip -p $port -d n 2>/dev/null | grep CVE > logs/vulnerabilidades/$ip-$port-a2sv.txt &
			echo ""	
			sleep 0.1;	
												
		else				
			while true; do
				echo "Max instancias de nmap ($max_nmap_ins)"
				sleep 5;
				perl_instances=$((`ps aux | grep perl | wc -l` - 1)) 
				if [ "$perl_instances" -lt $max_web_ins ] #Max 5 instances
				then	
					nmap -n -Pn -p $port --script=ssl-heartbleed $ip > logs/vulnerabilidades/$ip-$port-heartbleed.txt 2>/dev/null &
					#a2sv.sh -t $ip -p $port -d n | grep CVE > logs/vulnerabilidades/$ip-$port-a2sv.txt 2>/dev/null &						
					break
				fi							
			done										
		 fi		
	done	 					
	
	######## wait to finish########
	  while true; do
		nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
		if [ "$nmap_instances" -gt 0 ]
		then
			echo "Todavia hay escaneos de nmap activos ($nmap_instances)"  
			sleep 30
		else
			break		  		 
		fi				
	  done
	  ##############################
	  
	#Filtrar solo equipos vulnerables
	for line in $(cat .servicios/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		grep "|" logs/vulnerabilidades/$ip-$port-heartbleed.txt > vulnerabilidades/$ip-$port-heartbleed.txt				
		grep --color=never "Vulnerable" logs/vulnerabilidades/$ip-$port-a2sv.txt 2> /dev/null | grep -iv "not"  > vulnerabilidades/$ip-$port-a2sv.txt							
	done	
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data   		
fi




if [ -f .servicios/rdp.txt ]
then
    
    #if [ $rdp == "s" ] ; then	
		#mkdir -p screenshots
		echo -e "$OKBLUE\n\t#################### RDP (`wc -l .servicios/rdp.txt`) ######################$RESET"	  
		for line in $(cat .servicios/rdp.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`				
			#nmap -Pn -p $port $ip --script=rdp-enum-encryption > enumeracion/$ip/rdp.txt 2>/dev/null					
			
			while true; do
				free_ram=`free -m | grep -i mem | awk '{print $7}'`
				if [ "$free_ram" -gt 300 ]			
				then
					echo  "escaneando $ip (rdp -cert)"				
					#rdpscreenshot -o `pwd`/screenshots/ $ip 2>/dev/null			
					get_ssl_cert.py $ip $port 2>/dev/null | grep "("> enumeracion/$ip-$port-cert.txt  &
					sleep 0.2
					break
				else
					python_instances=`pgrep python | wc -l`
					echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de python ($python_instances)"
					sleep 3
				fi
			done	# done true	
			
		done	
	#fi   
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data	 		
fi



if [ -f .servicios/cgi.txt ]
then
        		
		echo -e "$OKBLUE\n\t#################### Shellsock (`wc -l .servicios/cgi.txt`) ######################$RESET"	  
		for line in $(cat .servicios/cgi.txt); do
			ip=`echo $line |  cut -d ":" -f 2 | tr -d /`
			path=`echo $line | cut -d ":" -f 3 | sed 's/80//g'`	
			echo  "escaneando ip=$ip path=$path(CGI -Shellsock)"				
			nmap -sV -p80 --script http-shellshock.nse --script-args uri=$path $ip > logs/vulnerabilidades/$ip-80-shellshock.txt
			grep "|" logs/vulnerabilidades/$ip-80-shellshock.txt  > vulnerabilidades/$ip-80-shellshock.txt										
			
			if [ -s vulnerabilidades/$ip-80-shellshock.txt ]
			then 
				echo "\n $path"  >> vulnerabilidades/$ip-80-shellshock.txt			
			fi
			
		done
		
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data	
	insert_data		 	
fi

if [ -f .servicios/cgi-ssl.txt ]
then
        		
		echo -e "$OKBLUE\n\t#################### Shellsock (`wc -l .servicios/cgi-ssl.txt`) ######################$RESET"	  
		for line in $(cat .servicios/cgi-ssl.txt); do
			ip=`echo $line |  cut -d ":" -f 2 | tr -d /`
			path=`echo $line | cut -d ":" -f 3 | sed 's/443//g'`
			if [ $ip != "200" ]
			then 			
				echo  "escaneando $ip (CGI -Shellsock)"				
				nmap -sV -p443 --script http-shellshock.nse --script-args uri=$path $ip > logs/vulnerabilidades/$ip-443-shellshock.txt
				grep "|" logs/vulnerabilidades/$ip-443-shellshock.txt  > vulnerabilidades/$ip-443-shellshock.txt			
			fi
			
						
		done	
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	
	#insert clean data		
	insert_data
	
fi


if [ -f .servicios/dns.txt ]
then
	echo -e "$OKBLUE\n\t#################### DNS (`wc -l .servicios/dns.txt`) ######################$RESET"	  
	for line in $(cat .servicios/dns.txt); do
		ip=`echo $line | cut -f1 -d":"`
		
		echo  "scan $ip (DNS - zone transfer)"
		#resolve IP - domain
		domain=`dig -x $ip @$ip| egrep "PTR|SOA" | egrep -iv ";|adsl|mobile|static|host-|LACNIC|tld" | head -1 | awk '{print $5}'`
		
		if [[ ${domain} != "" && ${domain} != *"local"*  && ${domain} != *"arpa"*  ]];then
			#remove subdomain
			set -- "$domain" 
			IFS="."; declare -a Array=($*) 	
			array_len=${#Array[@]}
			IFS=" ";
			sub2=${Array[$array_len - 2]} # dominio ó com
			sub3=${Array[$array_len - 1]} # com ó bo
	
			if [[ ${sub3} == "bo" ]] && [[ "$sub2" == "com" || "$sub2" == "org" || "$sub2" == "gob" || "$sub2" == "edu" ]];then
				sub1=${Array[$array_len - 3]}"." # dominio
			fi				        		

			domain=$sub1$sub2.$sub3
			echo "Dominio = $domain"			
			
			### zone transfer ###
			zone_transfer=`dig -tAXFR @$ip $domain`
			if [[ ${zone_transfer} != *"failed"*  && ${zone_transfer} != *"timed out"* && ${zone_transfer} != *"error"* ]];then
				echo $zone_transfer > vulnerabilidades/$ip-53-transfer.txt 
			fi													
		fi					
		
	done
	
	# check if we have any script running
	while true; do
	webbuster_instances=`ps aux | egrep 'buster|nmap' | wc -l`		
	if [ "$webbuster_instances" -gt 1 ]
	then
		echo -e "\t[-] Todavia hay scripts activos ($webbuster_instances)"				
		sleep 20
		else
			break		
		fi
	done	# done true	
	#insert clean data	
	insert_data		
fi


find reportes -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
insert-data.py

#########  filter files with metada ###
 #if [[ $TYPE = "completo" ]] || [ $resp_shared == "s" ]; then 
  #mkdir -p $dir_shared."/metadata" \;
  #cd $dir_shared 
  

  #find . -name "*.pdf" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.xls" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.doc" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.ppt" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.pps" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.docx" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.pptx" -exec cp {} $dir_shared."/metadata" \;
  #find . -name "*.xlsx" -exec cp {} $dir_shared."/metadata" \;
#fi
######################################

echo -e "\t $OKBLUE Obteniendo banners de los servicios $RESET"
getBanners.pl -l .datos/total-host-vivos.txt -t .nmap/nmap-tcp.grep 	



	######## wait to finish########
  while true; do
	nmap_instances=$((`ps aux | grep nmap | wc -l` - 1)) 
  if [ "$nmap_instances" -gt 0 ]
	then
		echo "Todavia hay escaneos de nmap activos ($nmap_instances)"  
		sleep 30
	else
		break		  		 
	fi				
  done
	  ##############################
	  
	cat .nmap_banners/*.grep > .nmap/nmap-tcp-banners.grep
	cat .nmap_banners/*.txt > reportes/nmap-tcp-banners.txt


	cd .nmap
	grep -i "ZK Web Server" nmap-tcp-banners.grep | awk '{print $2}' >> ../.servicios/ZKSoftware2.txt
	grep --color=never ZKSoftware ../.arp/* 2>/dev/null| awk '{print $1}' | cut -d ":" -f 2 >> ../.servicios/ZKSoftware2.txt
	sort ../.servicios/ZKSoftware2.txt | uniq > ../.servicios/ZKSoftware.txt; rm ../.servicios/ZKSoftware2.txt	
	
	grep -i "MikroTik" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt
	grep ' 8728/open' nmap-tcp.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/MikroTik2.txt 
	sort ../.servicios/MikroTik2.txt | uniq > ../.servicios/MikroTik.txt; rm ../.servicios/MikroTik2.txt		
	
	grep -i "ASA" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/ciscoASA.txt
	grep -i samba nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/samba.txt
	grep -i "Allegro RomPager" nmap-tcp-banners.grep 2>/dev/null| awk '{print $2}' >> ../.servicios/RomPager.txt
	cd ..
	cd .enumeracion2/
	grep --color=never -i admin * 2>/dev/null| grep --color=never http | awk '{print $2}' >> ../.servicios/admin-web.txt
	cd ..

find .servicios -size  0 -print0 |xargs -0 rm 2>/dev/null

#cisco
if [ -f .servicios/ciscoASA.txt ]
then
	echo -e "$OKBLUE\n\t#################### cisco (`wc -l .servicios/ciscoASA.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "\n\t### $ip "	
		nmap -n -Pn  -p 443 --script http-vuln-cve2014-2128 $ip > logs/vulnerabilidades/$ip-cisco-vuln.txt 2>/dev/null		
		grep "|" logs/vulnerabilidades/$ip-cisco-vuln.txt  > vulnerabilidades/$ip-cisco-vuln.txt
		
		nmap -n -Pn  -p 443 --script http-vuln-cve2014-2129 $ip > logs/vulnerabilidades/$ip-cisco-dos.txt 2>/dev/null		
		grep "|" logs/vulnerabilidades/$ip-cisco-dos.txt  > vulnerabilidades/$ip-cisco-dos.txt
													 
	done <.servicios/ciscoASA.txt
fi

#samba
if [ -f .servicios/samba.txt ]
then
	echo -e "$OKBLUE\n\t#################### samba (`wc -l .servicios/samba.txt`) ######################$RESET"	    
	while read ip       
	do     						
		echo -e "\n\t### $ip "	
		nmap -n -Pn --script smb-vuln-cve-2017-7494 -p 445 $ip > logs/vulnerabilidades/$ip-samba-vuln.txt 2>/dev/null		
		grep "|" logs/vulnerabilidades/$ip-samba-vuln.txt  > vulnerabilidades/$ip-samba-vuln.txt
													 
	done <.servicios/samba.txt
fi

#RomPager
if [ -f .servicios/RomPager.txt ]
then
	echo -e "$OKBLUE\n\t#################### RomPager (`wc -l .servicios/RomPager.txt`) ######################$RESET"	    
	while read ip     
	do     						
		echo -e "\n\t### $ip "	
		misfortune_cookie.pl -target $ip -port 80 > vulnerabilidades/$ip-80-misfortune.txt 2>/dev/null &
													 
	done <.servicios/RomPager.txt
fi
