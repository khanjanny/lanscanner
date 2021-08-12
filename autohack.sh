#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

while getopts ":d:n:t:k:m:i:s:" OPTIONS
do
            case $OPTIONS in            
            d)     DOMAIN=$OPTARG;;
            n)     NOMBRE=$OPTARG;;
            k)     KEYWORD=$OPTARG;;
            t)     TYPE=$OPTARG;;
            i)     IPS=$OPTARG;;
            s)     SUBNET=$OPTARG;;
            m)     MODE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

TYPE=${TYPE:=NULL}
DOMAIN=${DOMAIN:=NULL}
MODE=${MODE:=NULL}
SUBNET=${SUBNET:=NULL}
IPS=${IPS:=NULL}
KEYWORD=${KEYWORD:=NULL} # para cracker

if [ "$KEYWORD" = NULL ] || [ "$DOMAIN" = NULL ]; then

cat << "EOF"

Opciones: 

-c : palabra KEYWORD para generar passwords
-d : dominio

Ejemplo 1: Escanear el listado de subredes (completo)
	autohack.sh -d agetic.gob.bo -k agetic -t internet
	autohack.sh -d agetic.gob.bo -k agetic -t lan -s subnet.txt
	autohack.sh -d agetic.gob.bo -k agetic -t lan -s subnet.txt -m vpn
	autohack.sh -d agetic.gob.bo -k agetic -t lan -i ips.txt 
	
EOF

exit
fi
######################
if [ $TYPE == "internet" ]; then 	
	mkdir INTERNO
	mkdir EXTERNO
	cd EXTERNO
	recon.sh -d $DOMAIN -k $KEYWORD
	cd $DOMAIN
	lanscanner.sh -t completo -i importarMaltego/subdominios.csv -d $DOMAIN
	cracker.sh -e $KEYWORD -t completo
else
	# escaneo LAN
	
	echo -e "$OKBLUE Iniciando Responder $RESET"	
	iface=`ip addr | grep -iv DOWN | awk '/UP/ {print $2}' | egrep -v "lo|dummy|rmnet|vmnet" | sed 's/.$//'`
	#Borrar logs pasados
	#rm /usr/bin/pentest/Responder/logs/* 2>/dev/null
	/etc/init.d/smbd stop 
	xterm -hold -e responder.sh -F -f -I $iface 2>/dev/null& 	
	
		


	if [ "$SUBNET" != NULL ]; then 	
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -s $SUBNET -d $DOMAIN -m $MODE
		else
			lanscanner.sh -t completo -s $SUBNET -d $DOMAIN
		fi
		
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo
		pwd
	fi
	if [ "$IPS" != NULL ]; then 	
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -i $IPS -d $DOMAIN -m $MODE
		else
			lanscanner.sh -t completo -i $IPS -d $DOMAIN
		fi
				
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo
		pwd
	fi
	
	if [ "$IPS" = NULL ] && [ "$SUBNET" = NULL ]; then
	
		if [ "$MODE" != NULL ]; then 	
			lanscanner.sh -t completo -d $DOMAIN -m $MODE
		else
			lanscanner.sh -t completo -d $DOMAIN
		fi
				
		directory=`ls -hlt | grep '^d' | head -1 | awk '{print $9}'`
		pwd
		echo "entrando al directorio $directory" # creado por lanscanner
		cd $directory
		cracker.sh -e $KEYWORD -t completo
		pwd
	fi		
	mv /usr/bin/pentest/Responder/logs/* `pwd`/responder 2>/dev/null
	
fi
killall xterm

