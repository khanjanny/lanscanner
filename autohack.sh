#!/bin/bash
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

while getopts ":d:n:c:" OPTIONS
do
            case $OPTIONS in            
            d)     DOMAIN=$OPTARG;;
            n)     NOMBRE=$OPTARG;;
            c)     CLAVE=$OPTARG;;
            ?)     printf "Opcion invalida: -$OPTARG\n" $0
                          exit 2;;
           esac
done

DOMAIN=${DOMAIN:=NULL}
NOMBRE=${NOMBRE:=NULL}
CLAVE=${CLAVE:=NULL} # para cracker

if [ "$CLAVE" = NULL ] || [ "$DOMAIN" = NULL ]; then

cat << "EOF"

Opciones: 

-c : palabra clave para generar passwords
-d : dominio
-n : nombre

Ejemplo 1: Escanear el listado de subredes (completo)
	autohack.sh -d agetic.gob.bo -c agetic -n agetic
	
EOF

exit
fi
######################

recon.sh -d $DOMAIN -n "$NOMBRE"
cd $DOMAIN
lanscanner.sh -t completo -i reportes/subdominios.csv -d $DOMAIN
cracker.sh -e $CLAVE -t completo
