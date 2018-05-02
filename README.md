
# LanScanner.sh

Lanscanner realiza una auto enumeracion de protocolos y pruebas basicas de vulnerabilidades

FASE 1: Descubrir host vivos

- Escaneo ARP
- Escaneo ICMP (Ping)
- Escaneo TCP (Puertos 22,23,80,443)
- Escaneo SMB

FASE 2: Escaneo de la red (Solo hosts vivos)

- Escaneo de dispositivos VoIP
- Escaneo de puertos TCP/UDP

FASE 3: Enumeracion

Si el programa encuentra alguno de estos puertos abiertos procede a su enumeracion
- SNMP (Common Community String)
- SMB (Recursos compartidos, Obtener S.O, Dominio, Nombre de equipo)
- WEB (Obtiene titulo, metadados, banners)
- LDAP (Intenta obtener una copia del directorio LDAP)
- Proxy (Veifica si es un proxy abierto)
- SMTP (Verifica si en un SMTP relay)
- RTSP (Verifica si es un openstreaming)
- MS-SQL (Obtiene version del servidor de base de datos)
- VPN-IPsec (Verifica si esta en modo agresivo)
- FTP (Verifica si el usuario anonymous esta activo)
- VMWARE: (Obtiene la version)
  Camaras DAHUA:  (Verifica si se puede extraer la lista de usuarios)


## ¿COMO INSTALAR?

Testeado en Kali 2:

    git clone https://github.com/DanielTorres1/lanscanner
    cd lanscanner
    bash instalar.sh


## ¿COMO USAR?
**lanscanner.sh**

Opciones: 

    -t : Tipo de escaneo [completo/parcial]
    
    Definicion del alcance (opcional):
    	-s : Lista con las subredes a escanear (Formato CIDR 0.0.0.0/24)
    	-f : Lista con las IP a escanear

Ejemplo 1: Escanear la red local (completo)

    lanscanner.sh -t completo

Ejemplo 2: Escanear el listado de IPs (completo)

    lanscanner.sh -t completo -f lista.txt

Ejemplo 3: Escanear el listadado de subredes (completo)

    lanscanner.sh -t completo -s subredes.txt


@[youtube](dQw4w9WgXcQ)
