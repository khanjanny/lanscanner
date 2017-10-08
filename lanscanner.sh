#!/bin/bash
# Author: Daniel Torres
# daniel.torres@owasp.org
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'	


################## Config HERE ####################
netA="10.0.X.0/24";
netB="172.16.X.0/24";
netC="192.168.X.0/24";
#netC="192.168.X.0/24";
####################################################


smb_list=".scans/smb-list.txt"
mass_scan_list=".scans/mass-scan-list.txt"
live_hosts=".data/all-live_hosts.txt"
ping_list=".scans/ping-list.txt"
allports="no"


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


while getopts ":t:f:o:" OPTIONS
do
            case $OPTIONS in
            t)     TYPE=$OPTARG;;
            f)     FILE=$OPTARG;;
            o)     OFFSEC=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL}
FILE=${FILE:=NULL}
OFFSEC=${OFFSEC:=NULL}

if [ $TYPE = NULL ] ; then

echo "|              														 			"
echo "| USO: lanscanner.sh -t [completo/parcial]    "
echo "|																		 			"
echo ""
exit
fi
######################

echo -e "\n\n$OKRED ############################### Configurando los parametros ##################################### $RESET"

echo -e "\t $OKBLUE Cual es el nombre del proyecto? $RESET"
read project

mkdir $project
cd $project

mkdir -p .arp
mkdir -p .scans
mkdir -p .data
mkdir -p .nmap
mkdir -p enumeration
mkdir -p vulnerabilities
mkdir -p screenshots
mkdir -p .masscan
mkdir -p reports
mkdir -p .services
mkdir -p .tmp
mkdir -p logs/cracking
mkdir -p logs/enumeration
mkdir -p logs/vulnerabilities

touch $smb_list 
touch $mass_scan_list 
touch $ping_list
cp /usr/share/lanscanner/results.db .

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

rm  reports/info.txt 2>/dev/null
echo -e "#####################################" | tee -a reports/info.txt
echo -e "\t $OKRED IP actual: $my_ip $RESET" | tee -a reports/info.txt
echo -e "\t $OKRED MAC actual: $my_mac $RESET" | tee -a reports/info.txt
echo -e "\t $OKRED Gateway actual: $my_route $RESET" | tee -a reports/info.txt
echo -e "\t $OKRED Subnet: $current_subnet.0/24 $RESET" | tee -a reports/info.txt
echo -e "\t $OKRED Date: $date $RESET" | tee -a reports/info.txt
echo -e "#####################################" | tee -a reports/info.txt

  
echo -e "\t $OKBLUE Escanear los 65535 puertos? s/n? $RESET"
read allports
  
# Using ip list    
  if [ $FILE != NULL ] ; then
    echo -e "\t "
    
     echo -e  "\n##############################################################################" 
     echo -e  "$OKRED \t Usando  ----> $FILE <----- $RESET" 
     cat ../$FILE | cut -d "," -f 2 | uniq > $live_hosts
     #cat $live_hosts | cut -d . -f 1-3 | sort | uniq > .data/subnets.txt # get subnets 
     cat $live_hosts
     echo ""       
     echo -e  "\n##############################################################################" 
       
    
  else

# FASE: 1
#######################################  Discover live hosts ##################################### 
  echo -e "\t $OKBLUE Es una red plana? s/n $RESET"
  echo -e "$OKGREEN\t\t si = Buscar host vivos en otras redes usando ARP $RESET" 
  echo -e "$OKGREEN\t\t no = Buscar host vivos en otras redes usando ICMP,SMB,TCP21,80,443  $RESET" 
  read flat


  echo -e "\n$OKRED [+] FASE 1: DESCUBRIR HOST VIVOS $RESET"

  echo -e "$OKGREEN\t ++ Obteniendo host vivos locales  $RESET"
  arp-scan $iface $current_ip/24 $num_nets_enum | tee -a .arp/$current_subnet.0.arp 2>/dev/null
  echo -e "\t \n"
  
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
  
  echo -e "\t $OKBLUE Realizar escaneo de puertos 22,80,443 en busca de mas hosts vivos ? s/n $RESET"	  
  read webport	  
	  
  echo -e "\t $OKBLUE Realizar escaneo ICMP (ping) en busca de mas hosts vivos ? (Mas lento aun ...) s/n $RESET"	  
  read pingscan	 
  
      
    if [ $flat == 's' ]
    then    	
	  	  	 	           
       echo -e "\t $OKBLUE ##### Realizando escaneo ARP en busca de mas hosts vivos ##### $RESET "       
       arp-scan.py $netA $netB $netC $iface .arp/allnets.txt $num_nets_enum

	   #getting live host
	   echo -e  "$OKGREEN Con el escaneo ARP encontramos estos hosts vivos: $RESET" 
       while IFS='' read -r network || [[ -n "$network" ]]; do
  	    ip="${network/\/24/}"
	    echo $network
	    arp-scan $iface $network > .arp/$ip.arp 2>/dev/null	
       done < .arp/allnets.txt	 
       
       #configurando de nuevo la IP       
       echo -e "\t $OKBLUE Configurando $iface con la IP $my_ip y gateway $my_route $RESET"
       ifconfig $iface $my_ip
       route add default gw $my_route   	 
	fi # flat
	    	  	 
	  	  	 	
	  #################################   SMB    ###########################################
	  echo -e "\t ##### Realizando escaneo SMB en busca de mas hosts vivos #####"	  
      smb-scan.pl $netA $netB $netC $num_nets_enum | tee -a .scans/escaneo-smb.txt
      cat .scans/escaneo-smb.txt | grep : | awk '{print $1}' > $smb_list 2>/dev/null
                                   
      echo -e  "\n##############################################################################" 
      echo -e  "$OKGREEN Con el escaneo SMB  encontramos estos hosts vivos: $RESET" 
      cat $smb_list
      echo ""      
      #####################################################################################
      
      
      
      #################################   PORT 80,443,22  SCAN #########################################
	  
	  if [ $webport == 's' ]
      then 
        echo -e "\t $OKBLUE ##### Realizando escaneo al puerto 22,80,443 en busca de mas hosts vivos ##### $RESET"	  
		mass-scan.pl $netA $netB $netC .scans/mass-scan.txt
		cat .scans/mass-scan.txt | cut -d " " -f 6 | uniq > $mass_scan_list 2>/dev/null

		echo -e  "\n##############################################################################" 
		echo -e  "$OKRED Encontramos estos hosts vivos: $RESET" 
		cat $mass_scan_list
		echo ""             
      fi  	  	  
      
      #####################################################################################
	  
	  
	  
	   #################################   ICMP SCAN   ###########################################
	  
	  if [ $pingscan == 's' ]
      then 
        ping-scan.pl $netA $netB $netC $num_nets_enum | tee -a .scans/escaneo-ping.txt 
        cat .scans/escaneo-ping.txt | grep -v Escaneando  | sort | uniq > $ping_list 2>/dev/null
        
        echo -e  "\n##############################################################################" 
        echo -e  "$OKGREEN Con el escaneo ICMP (ping) encontramos estos hosts vivos: $RESET" 
        cat $ping_list
        echo ""       
      fi        
	  #####################################################################################
	           
    #fi #if flat
        
    
    echo -e  "\n##############################################################################" 
    ############ Generando lista ###########

    for ip_list in $(ls .arp | egrep -v "all|done"); do
       #cat .arp/$ip_list | grep ^1 |grep -v "DUP" | awk '{print $1}' | sort >> .data/all-live_hosts-1.txt                  
       cat .arp/$ip_list | egrep -v "DUP|packets" | grep ^1 | awk '{print $1}' | sort >> .data/all-live_hosts-1.txt
       mv .arp/$ip_list .arp/$ip_list.done	
    done;      
    
    	 #join arp-list & ping & smb scan & mass scan
	 cat $smb_list $mass_scan_list $ping_list .data/all-live_hosts-1.txt | sort | uniq > $live_hosts #2>/dev/null 
	 sed -i '/^\s*$/d' $live_hosts # delete empty lines	   
     rm .data/all-live_hosts-1.txt      
          
        
     if [ $flat == 's' ]
      then 
        echo "Revisar si hay host que no debemos escanear ($live_hosts). Presionar ENTER para continuar"
        read n	    
	  fi	 
	  cat $live_hosts | cut -d . -f 1-3 | uniq > .data/subnets.txt # get subnets 
	  
	  echo -e  "\n##############################################################################" 
      echo -e  "$OKGREEN TOTAL HOST VIVOS ENCONTRADOS: $RESET" 
      cat $live_hosts
      echo ""       
  fi

######################################### end discover live hosts #########################################



# FASE: 2
echo -e "\n$OKRED [+] FASE 2: ESCANEO DE PUERTOS,VoIP, etc $RESET"
######################################### Escanear (voip,smb,ports,etc) #########################################
echo -e "$OKGREEN################################## Escaneando ######################################$RESET"

echo -e "\n\t $OKBLUE Realizar screenshot remoto de RDP?. Un poco lento s/n $RESET"
read rdp

echo -e "\n\t $OKBLUE Realizar escaneo de vulnerabilidades (Un IDS puede bloquearnos)? s/n $RESET"
read vuln
    
 ########### searching VoIP devices ##########
if [ $TYPE = "parcial" ] ; then 	
	echo -e "\n\t $OKBLUE Realizar escaneo VoIP ? s/n $RESET"
    read resp_voip
  fi
  
 if [[ ( ${TYPE} == "completo" || ${resp_voip} == "s" ) && (${FILE} = NULL )]];then 
	echo -e "$OKBLUE\n\t#################### Buscando dispositivos VoIP: ######################$RESET"	  
	
	for subnet in $(cat .data/subnets.txt); do
	  echo -e "\t Escaneando $subnet.0/24"	  
	  svmap $subnet".0/24" > enumeration/$subnet-voip.txt 2>/dev/null &
    done;
		
  fi
 ############################################
  
 

 ########### smb scan (enum4linux) ##########
if [ $TYPE = "parcial" ] ; then
	echo -e "\n\t $OKBLUE Escanear con enum4linux  (Obtener Sistema Operativo,Dominio,usuarios)?: s/n $RESET"
    read resp_enum4linux
  fi
  
 if [[ $TYPE = "completo" ]] || [ $resp_enum4linux == "s" ]; then 
  		echo -e "$OKBLUE\n\t#################### Escaneo SMB ######################$RESET"	  
		mkdir -p .enum4linux/
		
		## copy files
		cp $live_hosts .enum4linux/
		#################
		cd .enum4linux/
		get-SMBinfo.py all-live_hosts.txt
		
		########## making reports #######
		echo -e "\t#### Creando reporte (OS/Domain/users) ###" 		
		report-OS-domain.pl all-live_hosts.txt
		
		### users/groups ####
		grep -ir "Local User" * > ../reports/users.txt
		sed -i -e 's/.txt:/;/g' ../reports/users.txt
		sed -i -e 's/ (Local User)//g' ../reports/users.txt
		grep "Local Group" * > ../reports/groups.txt
		
		#### delete ###		
		find ../reports -size  0 -print0 |xargs -0 rm  # delete empty files
		cd ../
		################################
   fi
   
   
	
############################################
  
  
  ########### shared resource scan ##########
 if [ $TYPE = "parcial" ] ; then
	echo -e "\n	$OKBLUE Buscar recursos compartidos?: s/n $RESET"	
    read resp_shared
  fi
  
 if [[ $TYPE = "completo" ]] || [ $resp_shared == "s" ]; then 
  
	echo -e "$OKBLUE\n\t#################### Buscando recursos compartidos ######################$RESET"	  
	mkdir -p .shared/	
	cp $live_hosts .shared/
	
	#echo -e "\t $OKBLUE Realizare la copia de archivos compartidos? s/n $RESET"
	#read copy_shared
	copy_shared="n"

	if [ $copy_shared == 's' ]
    then
	echo -e "\t $OKBLUE Tamaño maximo de archivos a copiar de los recursos compartidos (Mb)? $RESET"
	read max_file_size

	mkdir -p copied/
	echo -e "\t $OKBLUE Donde guardare los archivos compartidos? ej `pwd`/copied/ $RESET"
	read dir_shared    
	fi
		
	###########################################

	if [ $FILE != NULL ] || [ $flat == 's' ] ; then
 
  	  echo "Realizando escaneo con nbtscan"
      nbtscan -f .data/all-live_hosts.txt | grep ^1 | awk '{print $1}' | tee -a $smb_list
    fi
	
	cd .shared/
	scan_shared_docs.pl ../$smb_list 
	
	grep -i disk * | grep -v '\$|' | grep -v "\$ip =" > ../reports/shared_files.txt
	
	if [ $copy_shared = "s" ] ; then
	echo -e "\n	$OKBLUE Copiando recursos compartidos $RESET"	
	get_shared_docs.pl $max_file_size $dir_shared    
    fi
    
    cd ../
	
  fi
  ############################################


################### TCP/UDP scan  ###################
 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n \t $OKBLUE Realizar escaneo de puertos UDP?: s/n $RESET"
    read udp_scan
 fi

 if [ $TYPE = "parcial" ] ; then	
	echo -e "\n \t $OKBLUE Realizar escaneo de puertos TCP?: s/n $RESET"
    read tcp_scan
  fi
  

 if [[ $TYPE = "completo" ]] || [ $udp_scan == "s" ]; then 
	echo -e "$OKBLUE\n\t#################### Escaneo de puertos ######################$RESET"	 
    echo "	## Realizando escaneo udp en segundo plano ##"
       
		
	nmap -n -Pn -sU -p 53,161,500,1604  -iL $live_hosts -oG .nmap/nmap-udp.grep > reports/nmap-udp.txt 2>/dev/null 
	
	echo ""			
 fi	  
   
if [[ $TYPE = "completo" ]] || [ $tcp_scan == "s" ]; then 
	echo -e "$OKBLUE\n\t#################### Escaneo de puertos ######################$RESET"	  
			
	if [ $allports == 's' ]
    then    			
		for ip in $( cat $live_hosts  ); do        
			echo "	[+] Escaneando todos los puertos de $ip con mass-scan (TCP)"   		
			masscan -p1-65535 --rate 700 $ip --output-format grepable --output-filename .masscan/$ip.tcp 2>/dev/null ;
			ports=`cat .masscan/$ip.tcp  | grep -o "[0-9][0-9]*/open" | tr '\n' ',	' | tr -d '/open'`		
			num_ports=`echo $ports | tr -cd ',' | wc -c`		

			if [ "$num_ports" -gt 35 ]
			then
				echo "Sospechoso!!. Muchos puertos abiertos ($num_ports)"
			else				
				echo -e "	[+] Identificando servicios de $ip ($ports)"
				nmap -n -Pn -sV -O -p $ports $ip -oG .scans/$ip-tcp.grep2 >> reports/nmap-tcp2.txt 2>/dev/null &						
			fi					                            			
        done                
     else   
     	echo "	## Realizando escaneo tcp en segundo plano (solo 1000 puertos) ##"  
     	
     	nmap -n -Pn -iL $live_hosts -sV -O -oG .nmap/nmap-tcp.grep > reports/nmap-tcp2.txt 2>/dev/null       	
    
        
     fi		
 fi 
#################################################  
  
#### check nmap instances ###
 echo -e "$OKBLUE\n\t Finalizando escaneo $RESET"	  
 while true; do
		nmap_instances=`pgrep nmap | wc -l`
			if [ "$nmap_instances" -gt 0 ]
		then
			echo "Todavia hay escaneos de nmap activos ($nmap_instances)"  
			sleep 20
		else
			break		  		 
		fi				
done

if [ $allports == 's' ]
then
	cat .scans/*.grep2 > .nmap/nmap-tcp.grep       
	sed -i 's/open\/tcp\/\/tcpwrapped/tcpwrapped/g' .nmap/nmap-tcp.grep 
fi
##################################################        
    
    
########## making reports #######
if [[ $TYPE == "completo"  || $tcp_scan == "s"   || $udp_scan == "s" ]] ; then 
	echo -e "\t#### Creando reporte nmap ###"      
	# clean tcp wrapped
	
	if [[ $TYPE = "completo" ]] || [ $tcp_scan == "s" ]; then 
		cd reports
		cat nmap-tcp2.txt | grep -v tcpwrapped > nmap-tcp.txt    
		rm nmap-tcp2.txt
		cd ..
	fi
	
		
	# replace IP with subdomain
	#cat nmap-tcp.grep  | grep -v "Status: Up" >nmap-tcp.grep
	#rm nmap-tcp.grep
	#for domain in `grep "Nmap scan reports for" nmap-tcp.txt | cut -d " " -f 5`
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
if [[ $TYPE = "completo" ]] || [ $tcp_scan == "s" ]; then 
	cd .nmap	
					
	find . -name "*.grep" | xargs -n 20 egrep -oi '[[:digit:]]{2,5}/open/tcp//http-proxy//[[:alpha:]]{2,5}' 2>/dev/null | sed 's/-tcp.grep//g' | cut -d "/" -f2 > ../.services/proxy-http.txt
	#find . -name "*.grep" | xargs -n 20 egrep -oi '[[:digit:]]{2,5}/open/tcp//rtsp//[[:alpha:]]{2,5}' 2>/dev/null | sed 's/-tcp.grep//g' | cut -d "/" -f2 >../.services/ip-cameras.txt
	grep '/rtsp/' nmap-tcp.grep | grep --color=never -o -P '(?<=Host: ).*(?=\(\))'>../.services/ip-cameras.txt
	
	
	#web
	grep " 80/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:80\n"' > ../.services/web.txt	
	grep " 81/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:81\n"' >> ../.services/web.txt	
	grep " 82/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:82\n"' >> ../.services/web.txt	
	grep " 8080/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8080\n"' >> ../.services/web.txt	
	grep " 8081/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8081\n"' >> ../.services/web.txt	
	grep " 8010/open" nmap-tcp.grep| awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8010\n"' >> ../.services/web.txt	
	
	# web-ssl
	grep " 443/open" nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:443\n"' > ../.services/web-ssl.txt
	grep " 8443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8443\n"' >> ../.services/web-ssl.txt
	grep " 4443/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4443\n"' >> ../.services/web-ssl.txt
	grep " 4433/open" nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4433\n"' >> ../.services/web-ssl.txt
		
	grep ' 21/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:21\n"' >> ../.services/ftp.txt
	grep ' 513/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:513\n"' >> ../.services/rlogin.txt
	## ssh																	del newline       add port
	grep ' 22/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:22\n"' >> ../.services/ssh.txt
	grep ' 6001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6001\n"' >> ../.services/ssh.txt
	grep	 ' 23/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:23\n"' >> ../.services/telnet.txt
	
	## smtp																	del newline       add port
	grep ' 25/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:25\n"' >> ../.services/smtp.txt
	grep ' 587/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:587\n"' >> ../.services/smtp.txt
	grep ' 465/open' nmap-tcp.grep | awk '{print $2}'| perl -ne '$_ =~ s/\n//g; print "$_:465\n"'  >> ../.services/smtp.txt
	grep ' 110/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:110\n"' >> ../.services/pop.txt 
	grep ' 143/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:143\n"' >> ../.services/imap.txt 
	grep ' 10000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:10000\n"' >> ../.services/webmin.txt 
	grep ' 111/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:111\n"' >> ../.services/rpc.txt 
  
	## ldap																	del newline       add port
	grep ' 389/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:389\n"' >> ../.services/ldap.txt
	grep ' 636/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:636\n"' >> ../.services/ldaps.txt
  
  
	### SMB 														   del newline       add port
	grep ' 445/open' nmap-tcp.grep | awk '{print $2}' >> ../.services/smb-445.txt
			

    
	# Java related
	grep ' 8009/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8009\n"' >> ../.services/java.txt
	grep ' 9001/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9001\n"' >> ../.services/java.txt
			# database ports 														   del newline       add port
	grep ' 1521/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1521\n"' >> ../.services/oracle.txt
	grep ' 5432/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5432\n"' >> ../.services/postgres.txt     
	grep ' 3306/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3306\n"' >> ../.services/mysql.txt 
	grep ' 27017/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:27017\n"' >> ../.services/mongoDB.txt 
	grep ' 28017/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:28017\n"' >> ../.services/mongoDB.txt 
	grep ' 27080/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:27080\n"' >> ../.services/mongoDB.txt 
	grep ' 5984/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5984\n"' >> ../.services/couchDB.txt 
	grep ' 6379/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6379\n"' >> ../.services/redis.txt 
	grep ' 9000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9000\n"' >> ../.services/Hbase.txt 
	grep ' 9160/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:9160\n"' >> ../.services/cassandra.txt 
	grep ' 7474/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:7474\n"' >> ../.services/neo4j.txt 
	grep ' 8098/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:8098\n"' >> ../.services/riak.txt 
        
    
	# remote desk
	grep ' 3389/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:3389\n"' >> ../.services/rdp.txt
	grep ' 4899/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:4899\n"' >> ../.services/radmin.txt  
	grep ' 5800/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5800\n"' >> ../.services/vnc-http.txt
	grep ' 5900/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5900\n"' >> ../.services/vnc.txt
	grep ' 5901/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5901\n"' >> ../.services/vnc.txt
   
   	#Virtual
	grep ' 902/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:902\n"' >> ../.services/vmware.txt	
	grep ' 1494/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1494\n"' >> ../.services/citrix.txt    
		  
		
	#Misc      
	grep ' 6000/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:6000\n"' >> ../.services/x11.txt
	grep ' 631/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:631\n"' >> ../.services/cups.txt
	grep ' 9100/open' nmap-tcp.grep | awk '{print $2}'  | perl -ne '$_ =~ s/\n//g; print "$_:9100\n"' >> ../.services/printers.txt	
	grep ' 2049/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:2049\n"' >> ../.services/nfs.txt
	grep ' 5723/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5723\n"' >> ../.services/SystemCenter.txt
	grep ' 5724/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5724\n"' >> ../.services/SystemCenter.txt
	grep ' 1099/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1099\n"' >> ../.services/rmi.txt
	grep ' 1433/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' >> ../.services/mssql.txt 
	
	#Esp
	grep ' 16992/open' nmap-tcp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1434\n"' >> ../.services/intel.txt 
	grep -i "ZKSoftware" nmap-tcp.grep | awk '{print $2}' >> ../.services/ZKSoftware.txt
	grep -i "MikroTik" nmap-tcp.grep | awk '{print $2}' >> ../.services/MikroTik.txt
	grep -i windows ../reports/OS-report.txt | cut -d ";" -f 1 >> ../.services/Windows.txt
	
	cd ..
fi
    
  
  
 ##################UDP#########
if [[ $TYPE = "completo" ]] || [ $udp_scan == "s" ]; then 
	cd .nmap
	grep 53/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:53\n"' >> ../.services/dns.txt
	grep 161/open/ nmap-udp.grep | awk '{print $2}'  >> ../.services/snmp.txt
	grep 139/open/ nmap-udp.grep | awk '{print $2}'  >> ../.services/smb-139.txt
	grep 137/open/ nmap-udp.grep | awk '{print $2}'  >> ../.services/smb-137.txt
	grep 500/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:500\n"' >> ../.services/vpn.txt
	grep 5060/open nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:5060\n"' >> ../.services/sip.txt	
	grep 1604/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1604\n"' >> ../.services/citrix.txt
	grep 1900/open/ nmap-udp.grep | awk '{print $2}' | perl -ne '$_ =~ s/\n//g; print "$_:1900\n"' >> ../.services/upnp.txt
	cd ../
fi
        
find .services -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
 ################################
  
   
echo "######################################################################################### "




# FASE: 3
echo -e "\n\n$OKRED [+] FASE 3: ENUMERACION DE PUERTOS E IDENTIFICACION DE VULNERABILIDADES $RESET"
###################################  ENUMERACION ########################################
echo -e "$OKGREEN#################################### EMPEZANDO ENUMERACION ########################################$RESET"  

echo -e "$OKBLUE\n\t#################### SMB ######################$RESET"	
if [ -f .services/smb-445.txt ]
then  
	for ip in $(cat .services/smb-445.txt); do		
						
		echo -e "\n\t### $ip (port 445)"				
		nmap -n -Pn -p445 --script smb-vuln-ms08-067,smb-vuln-ms17-010,smb-vuln-ms06-025 $ip > logs/vulnerabilities/$ip-445-nmap.txt 2>/dev/null
		grep "|" logs/vulnerabilities/$ip-445-nmap.txt  > vulnerabilities/$ip-445-nmap.txt  
		
		if [ $vuln == "s" ] ; then	
			nmap -n -Pn -p445 --script smb-vuln-ms10-061,smb-vuln-ms10-054,smb-vuln-ms07-029 $ip | grep "|" > vulnerabilities/$ip-445-nmap.txt 2>/dev/null &					
		fi							
	done
fi


if [ -f .services/smb-137.txt ]
then
	for ip in $(cat .services/smb-137.txt); do		
		
		nmap -n -Pn -sU -p U:137 --script smb-vuln-ms08-067 $ip > logs/vulnerabilities/$ip-137-nmap.txt 2>/dev/null
		grep "|" logs/vulnerabilities/$ip-137-nmap.txt > vulnerabilities/$ip-137-nmap.txt 	
		
	done
fi

#####################################

if [ -f .services/ip-cameras.txt ]
then
	echo -e "$OKBLUE\n\t#################### IP cameras ######################$RESET"	  
	for line in $(cat .services/ip-cameras.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`						
		
		nmap -n -Pn -sV -p 554 --script=rtsp-url-brute $ip > logs/vulnerabilities/$ip-554-openstreaming.txt 2>/dev/null 
		grep "|" logs/vulnerabilities/$ip-554-openstreaming.txt > enumeration/$ip-554-openstreaming.txt 		
	done		
fi


if [ -f .services/mysql.txt ]
then
	echo -e "$OKBLUE\n\t#################### MY SQL ######################$RESET"	  
	for line in $(cat .services/mysql.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo  "scan $ip (mysql)"
	
		# user=root password=''
		mysql -uroot -h $ip -e 'select * from mysql.user;' > vulnerabilities/$ip-mysql-nopass.txt 2>/dev/null &
	
		# user=root password=root	
		mysql -uroot -h $ip -proot -e 'select * from mysql.user;' > vulnerabilities/$ip-mysql-password.txt  2>/dev/null &
			
		#nmap -sV -Pn -p $port $ip --script mysql-info > enumeration/$ip-mysql.txt 2>/dev/null &
		#nmap -sV -Pn -p $port $ip --script=mysql-vuln-cve2012-2122 | grep "|" > enumeration/$ip-mysql-vuln.txt 2>/dev/null
	done
fi


if [ -f .services/mongoDB.txt ]
then
	echo -e "$OKBLUE\n\t#################### MongoDB ######################$RESET"
	for line in $(cat .services/mongoDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		
		nmap -n -sV -Pn -p $port --script=mongodb-databases,mongodb-info $ip  > logs/enumeration/$ip-monogodb.txt 2>/dev/null 
		grep "|" logs/enumeration/$ip-monogodb.txt > enumeration/$ip-monogodb.txt 
			
		
	done
fi


if [ -f .services/couchDB.txt ]
then
	echo -e "$OKBLUE\n\t#################### couchDB ######################$RESET"
	for line in $(cat .services/couchDB.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		nmap -n -sV -Pn -p $port --script=couchdb-databases,couchdb-stats $ip > logs/enumeration/$ip-couchdb.txt 2>/dev/null
		grep "|" logs/enumeration/$ip-couchdb.txt > enumeration/$ip-couchdb.txt 
	done	
fi

######################################

if [ -f .services/x11.txt ]
then
	echo -e "$OKBLUE\n\t#################### X11 ######################$RESET"	  
	for line in $(cat .services/x11.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
				
		nmap -n -Pn $ip --script=x11-access.nse > logs/enumeration/$ip-x11.txt 2>/dev/null 
		grep "|" logs/enumeration/$ip-x11.txt > enumeration/$ip-x11.txt 
		
	done	
fi

if [ -f .services/rpc.txt ]
then
	echo -e "$OKBLUE\n\t#################### RPC ######################$RESET"	  
	for line in $(cat .services/rpc.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
				
		nmap -n -Pn -p $port $ip --script=nfs-ls.nse,rpcinfo > logs/enumeration/$ip-rpc.txt 2>/dev/null 
		grep "|" logs/enumeration/$ip-rpc.txt > enumeration/$ip-rpc.txt 
		
	done	
fi



if [ -f .services/upnp.txt ]
then
	echo -e "$OKBLUE\n\t#################### upnp ######################$RESET"	    
	for line in $(cat .services/upnp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		
		nmap -n -Pn -sU -p $port $ip --script=upnp-info, broadcast-upnp-info > enumeration/$ip/upnp.txt 2>/dev/null &
			
	done
fi


if [ -f .services/redis.txt ]
then	
	echo -e "$OKBLUE\n\t#################### Redis ######################$RESET"	    
	for line in $(cat .services/redis.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`				
		nmap -n -Pn -p $port $ip --script redis-info > logs/enumeration/$ip-redis.txt 2>/dev/null
		grep "|" logs/enumeration/$ip-redis.txt  > enumeration/$ip-redis.txt						
	done
fi

if [ -f .services/rmi.txt ]
then	
	echo -e "$OKBLUE\n\t#################### RMI ######################$RESET"	    
	for line in $(cat .services/rmi.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		nmap -n -Pn -p $port $ip --script rmi-vuln-classloader > logs/vulnerabilities/$ip/rmi-vuln.txt 2>/dev/null
		grep "|" logs/vulnerabilities/$ip/rmi-vuln.txt  > vulnerabilities/$ip/rmi-vuln.txt
		
	done
fi


if [ -f .services/ftp.txt ]
then
	echo -e "$OKBLUE\n\t#################### FTP ######################$RESET"	    
	touch 68b329da9893e34099c7d8ad5cb9c940.txt # file to test upload
	for line in $(cat .services/ftp.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		echo -e "\n\t### $ip"				
		#nmap -n -sV -Pn -p $port $ip --script=ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 > enumeration/$ip-ftp-vuln.txt 2>/dev/null &
		echo  "scan $ip (ftp - banner)"
		echo "LIST" | nc -w 3 $ip 21 > enumeration/$ip-21-banner.txt 2>/dev/null &					
		echo  "scan $ip (ftp - anonymous)"
		ftp-anonymous.pl -t $ip -f 68b329da9893e34099c7d8ad5cb9c940.txt > vulnerabilities/$ip-21-anonymous.txt 2>/dev/null &	
		sleep 5
	done	
	rm 68b329da9893e34099c7d8ad5cb9c940.txt 2>/dev/null
fi


if [ -f .services/telnet.txt ]
then
	echo -e "$OKBLUE\n\t#################### TELNET ######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
					
		echo  "scan $ip (telnet - banner)"
		nc -w 3 $ip 23 <<<"print_debug" > enumeration/$ip-23-banner.txt 2>/dev/null
		sed -i -e "1d" enumeration/$ip-23-banner.txt 2>/dev/null																
		cp enumeration/$ip-23-banner.txt logs/enumeration/$ip-23-banner.txt
	done <.services/telnet.txt
fi




if [ -f .services/finger.txt ]
then
	echo -e "$OKBLUE\n\t#################### FINGER ######################$RESET"	    
	while read line; do
		ip=`echo $line | cut -f1 -d";"`		
		echo  "scan $ip (finger)"
		finger @$ip > enumeration/$ip-69-users.txt &
		sleep 1
					# done true				        	        				
	done < .services/finger.txt
fi

if [ -f .services/vpn.txt ]
then
	echo -e "$OKBLUE\n\t#################### VPN ######################$RESET"	    
	for line in $(cat .services/vpn.txt); do
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "\n\t### $ip"
		ike=`ike-scan -M $ip`
		if [[ $ike == *"HDR"* ]]; then
			echo $ike > enumeration/$ip-500-transforms.txt
			cp enumeration/$ip-500-transforms.txt logs/enumeration/$ip-500-transforms.txt
			ike-scan -A -M --pskcrack=enumeration/$ip-500-handshake.txt $ip 2>/dev/null &
		fi	
		
		
	done

fi

if [ -f .services/vnc.txt ]
then
	echo -e "$OKBLUE\n\t#################### VNC ######################$RESET"	    
	for line in $(cat .services/vnc.txt); do		
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`		
		echo -e "\n\t### $ip ($port)"					
		vnc_response=`echo "a" | nc -w 3 $ip $port`
		if [[ ${vnc_response} == *"RFB 003.008"* ]];then
			echo "VNC bypass ($vnc_response)" > vulnerabilities/$ip-$port-bypass.txt 
		fi	
	
	done
fi


# enumerate MS-SQL
if [ -f .services/mssql.txt ]
then
	echo -e "$OKBLUE\n\t#################### MS-SQL ######################$RESET"	    
	while read line           
	do   	
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`	
		echo -e "\n\t### $ip ($port)"	
		nmap -sU -n -Pn -sV -p 1434 --host-timeout 10s --script ms-sql-info $ip > logs/enumeration/$ip-1434-info.txt  2>/dev/null
		grep "|" logs/enumeration/$ip-1434-info.txt  > enumeration/$ip-1434-info.txt 
					
	done <.services/mssql.txt
fi
		

#LDAPS
if [ -f .services/ldaps.txt ]
then
	echo -e "$OKBLUE\n\t#################### LDAPS ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -Pn -p 636 --script ldap-rootdse $ip > logs/enumeration/$ip-636-open.txt 2>/dev/null
		grep -i namingContexts logs/enumeration/$ip-636-open.txt > enumeration/$ip-636-open.txt 
													 
	done <.services/ldaps.txt
fi

#VMWARE
if [ -f .services/vmware.txt ]
then
	echo -e "$OKBLUE\n\t#################### vmware ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -Pn --script vmware-version -p443 $ip > logs/enumeration/$ip-vmware-version.txt 2>/dev/null
		grep "|" logs/enumeration/$ip-vmware-version.txt > enumeration/$ip-vmware-version.txt 
													 
	done <.services/vmware.txt
fi


#CITRIX
if [ -f .services/citrix.txt ]
then
	echo -e "$OKBLUE\n\t#################### citrix ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -Pn -sU --script=citrix-enum-apps -p 1604 $ip > logs/enumeration/$ip-citrix-app.txt 2>/dev/null
		nmap -n -Pn -sU --script=citrix-enum-servers -p 1604  $ip > logs/enumeration/$ip-citrix-servers.txt 2>/dev/null
		
		grep "|" logs/enumeration/$ip-citrix-app.txt > enumeration/$ip-citrix-app.txt 
		grep "|" logs/enumeration/$ip-citrix-servers.txt > enumeration/$ip-citrix-servers.txt 
													 
	done <.services/citrix.txt
fi

#INTEL
if [ -f .services/intel.txt ]
then
	echo -e "$OKBLUE\n\t#################### intel ######################$RESET"	    
	while read line       
	do     				
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		echo -e "\n\t### $ip ($port)"	
		nmap -n -Pn -p 16992 --script http-vuln-cve2017-5689 $ip > logs/vulnerabilities/$ip-intel-bypass.txt 2>/dev/null			
		grep "|" logs/vulnerabilities/$ip-intel-bypass.txt > vulnerabilities/$ip-intel-bypass.txt
													 
	done <.services/intel.txt
fi


if [ -f .services/snmp.txt ]
then
	echo -e "$OKBLUE\n\t#################### SNMP ######################$RESET"	    
	echo  "scan (snmp - onesixtyone)"
	onesixtyone -c /usr/share/lanscanner/community.txt -i .services/snmp.txt  | grep --color=never "\[" | sed 's/ \[/~/g' |  sed 's/\] /~/g' > banners-snmp2.txt

	while read line; do
		ip=`echo $line | cut -f1 -d"~"`
		community=`echo $line | cut -f2 -d"~"`
		device=`echo $line | cut -f3 -d"~"`
		
		echo  "scan $ip (snmp - $community )"
		### snmp write ##
		snmp-write.pl -t $ip -c $community > enumeration/$ip-161-$community.txt 2>/dev/null &										
				
		### snmp bruteforce ##				
		
		if [[ ${device} == *"windows"*  ]];then 
			echo  "scan $ip (snmp - enumerate - windows)"
			snmpbrute.py -t $ip -c $community --windows --auto > enumeration/$ip-161-enumerate.txt 2>/dev/null 
		fi	
		
		if [[ ${device} == *"SunOS"* || ${device} == *"SonicWALL"* || ${device} == *"SofaWare"* || ${device} == *"SRP521W"* || ${device} == *"RouterOS"* || ${device} == *"Cisco"* || ${device} == *"juniper"* ]];then 
			echo  "scan $ip (snmp - enumerate - router)"
			snmpbrute.py -t $ip -c $community --cisco --auto > enumeration/$ip-161-enumerate.txt 2>/dev/null 
		fi								
			
		if [[ (${device} == *"linux"* || ${device} == *"Linux"* ) && (${device} != *"linux host"* )]];then 
			echo  "scan $ip (snmp - enumerate - Linux)"
			snmpbrute.py -t $ip -c $community --linux --auto > enumeration/$ip-161-enumerate.txt 2>/dev/null 
		fi										
					
		if [ ! -f enumeration/$ip-161-enumerate.txt ]; then
			echo  "scan $ip (snmp - enumerate - generic)"
			snmpbrute.py -t $ip -c $community --linux --auto > enumeration/$ip-161-enumerate.txt 2>/dev/null 
		fi
		cp enumeration/$ip-161-enumerate.txt logs/enumeration/$ip-161-enumerate.txt
		
	done <banners-snmp2.txt
	#rm banners-snmp2.txt
	##################################
fi


if [ -f .services/ldap.txt ]
then
	echo -e "$OKBLUE\n\t#################### LDAP ######################$RESET"	    
	while read line          
	do        
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"` 	
		
		nmap -n -Pn -p 389 --script ldap-rootdse $ip > logs/enumeration/$ip-389-open.txt 
		grep -i namingContexts logs/enumeration/$ip-389-open.txt  > enumeration/$ip-389-open.txt 
		
	done <.services/ldap.txt
fi	



if [ -f .services/smtp.txt ]
	then
		echo -e "$OKBLUE\n\t#################### SMTP ######################$RESET"	    
		while read line
		do  	
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`
			
			echo  "scan $ip (smtp - vrfy,openrelay)"		
			vrfy-test.py $ip $port > enumeration/$ip-$port-vrfy.txt 2>/dev/null &
			open-relay.py $ip $port > enumeration/$ip-$port-openrelay.txt 2>/dev/null &
			sleep 2;
		done <.services/smtp.txt
	fi


if [ -f .services/web.txt ]
then
      
	echo -e "$OKBLUE\n\t#################### WEB ######################$RESET"	    		

	for line in $(cat .services/web.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`			
		
			
		echo -e "\t[+] whatweb $ip:$port"	
		whatweb --quiet --user-agent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Trident/5.0)" $ip:$port --log-brief enumeration/$ip-$port-whatweb.txt 2>/dev/null  ;
		
		echo -e "\t[+] Getting Title $ip:$port"	
		webTitle.pl -t $ip -p $port > enumeration/$ip-$port-title.txt 2>/dev/null  ;
		
		#######  if the server is apache ######
		grep -i apache enumeration/$ip-$port-whatweb.txt
		greprc=$?
		if [[ $greprc -eq 0 ]] ; then			
			
			echo -e "\n\t### $ip:$port (Revisando vulnerabilidades apache)"
			nmap -n -Pn -p $port $ip --script=http-vuln-cve2017-5638 > logs/vulnerabilities/$ip-$port-Struts.txt 2>/dev/null  					
			grep "|" logs/vulnerabilities/$ip-$port-Struts.txt > vulnerabilities/$ip-$port-Struts.txt 2>/dev/null 	
			
			if [ $OFFSEC != "1" ] ; then	
				echo -e "\n\t### $ip:$port (Revisando si apache tiene slowloris)"
				nmap -n -sV -Pn -p $port --script=http-slowloris-check   $ip > logs/vulnerabilities/$ip-$port-slowloris.txt 2>/dev/null 
				grep "|" logs/vulnerabilities/$ip-$port-slowloris.txt > vulnerabilities/$ip-$port-slowloris.txt 2>/dev/null 	
			fi
		fi						
		####################################	
				
		
		if [ $OFFSEC = "1" ] ; then	
		
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			if [ "$free_ram" -gt 200 ]			
			then						
				
				echo -e "\t[+] Web-buster ..  $ip:$port"
				web-buster.pl -s $ip -p $port -t 33 -a / -m username -q 1 | grep http > enumeration/$ip-$port-webusername.txt  &
				web-buster.pl -s $ip -p $port -t 33 -a / -m directorios -q 1 | grep http > enumeration/$ip-$port-webdirectorios.txt  &
				web-buster.pl -s $ip -p $port -t 33 -a / -m archivos -q 1 | grep http > enumeration/$ip-$port-webarchivos.txt  &
				web-buster.pl -s $ip -p $port -t 33 -a / -m cgi  -q 1| grep http > enumeration/$ip-$port-webcgi.txt  &
				web-buster.pl -s $ip -p $port -t 33 -a / -m backup -q 1 | grep http > enumeration/$ip-$port-webbackup.txt  &				
		
				#echo -e "\t[+] nikto ..  $ip:$port"
				#nikto -host http://$ip:$port > enumeration/$ip-$port-nikto.txt  2>/dev/null &												
	

				#######  if the server is IIS ######
				#grep -i IIS enumeration/$ip/whatweb$port.txt
				#greprc=$?
				#if [[ $greprc -eq 0 ]] ; then
					#echo -e "\n\t### $ip:$port (Enumerando IIS)"
					#nmap -sV -Pn -p $port $ip --script=http-aspnet-debug,http-internal-ip-disclosure,http-mobileversion-checker,http-ntlm-info,http-robtex-reverse-ip | grep "|"  > enumeration/$ip/http-iis-$port.txt 2>/dev/null  
					#	echo -e "\n\t### $ip:$port (Revisando vulnerabilidades IIS)"
					#	nmap -sV -Pn -p $port $ip --script=http-iis-webdav-vuln,http-vuln-cve2015-1635 | grep "|"  > enumeration/$ip/http-iis-vuln-$port.txt 2>/dev/null
				
				#fi						
				####################################												
				break
			else
				ruby_instances=`pgrep ruby | wc -l`
				echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de nmap ($ruby_instances )"
				sleep 3
			fi
		done	# done true		
	  fi # if scan web servers
	done    #done file
fi # file exists



if [ -f .services/web-ssl.txt ]
then    
    
    echo -e "$OKBLUE\n\t#################### WEB - SSL######################$RESET"	    		

	for line in $(cat .services/web-ssl.txt); do    
		ip=`echo $line | cut -f1 -d":"`
		port=`echo $line | cut -f2 -d":"`
		
		
		echo -e "\t[+] Getting Title $ip:$port"	
		webTitle.pl -t $ip -p $port > enumeration/$ip-$port-title.txt 2>/dev/null  ;
			
		
		while true; do
			free_ram=`free -m | grep -i mem | awk '{print $7}'`		
			if [ "$free_ram" -gt 200 ]			
			then						
				echo -e "\n\t### $ip:$port (Enumeracion SSL)"			
				whatweb --quiet --user-agent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Trident/5.0)" https://$ip:$port --log-brief enumeration/$ip-$port-whatweb.txt 2>/dev/null &
				
				if [ $vuln == "s" ] ; then	
					nmap -n -sV -Pn -p $port $ip  --script=ssl-heartbleed  | grep "|" > vulnerabilities/$ip-$port-nmap.txt 2>/dev/null &
					a2sv.sh -t $ip -p $port -d n | grep CVE > vulnerabilities/$ip-$port-a2sv.txt 2>/dev/null &
				fi							
				sleep 0.7				
				break
			else
				nmap_instances=`pgrep nmap | wc -l`
				echo "[-] Poca RAM ($free_ram Mb). Maximo número de instancias de nmap ($nmap_instances )"
				sleep 3
			fi
		done	# done true	
	done   		
fi




if [ -f .services/rdp.txt ]
then
    
    if [ $rdp == "s" ] ; then	
		
		echo -e "$OKBLUE\n\t#################### RDP ######################$RESET"	  
		for line in $(cat .services/rdp.txt); do
			ip=`echo $line | cut -f1 -d":"`
			port=`echo $line | cut -f2 -d":"`				
			#nmap -Pn -p $port $ip --script=rdp-enum-encryption > enumeration/$ip/rdp.txt 2>/dev/null					
			echo  "scan $ip (rdp -screenshot)"				
			rdpscreenshot -o `pwd`/screenshots/ $ip 2>/dev/null			
		done	
	fi    		
fi

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

find vulnerabilities -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
find enumeration -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
find reports -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
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
date
