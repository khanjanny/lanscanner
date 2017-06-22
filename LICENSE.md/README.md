# LanScanner.sh

Con el objetivo de hacer mas rápido las auditorias creé el script lanscanner.sh que realiza las siguiente tareas:

FASE 1: Descubrir host vivos

- Escaneo ARP
- Escaneo ICMP (Ping)
- Escaneo TCP (Puertos 22,23,80,443)
- Escaneo SMB

FASE 2: Escaneo de la red (Solo hosts vivos)

- Escaneo de dispositivos VoIP
- Escaneo de recursos compartidos
- Escaneo SMB (Obtener S.O, Dominio, Nombre de equipo)
- Escaneo de puertos TCP/UDP

FASE 3: Enumeracion

Si el programa encuentra alguno de estos puertos abiertos procede a su enumeracion
- SNMP
- SMB
- WEB
- LDAP
- Proxy
- SMTP
- RTSP
- MS-SQL
- VPN-IPsec
- FTP
- MySQL
- RDP
- Escaneo de vulnerabilidades con nmap


## ¿COMO INSTALAR?

```sh
git clone https://github.com/DanielTorres1/lanScanner
cd lanScanner
bash instalar.sh
```


Probado en Kali Linux 
https://www.offensive-security.com/kali-linux-vmware-virtualbox-image-download/



LICENCIA: GPLv3
- Libertad usar el software
- Libertad de estudiar el programa (código fuente)
- Liberta de distribuir el programa
- Libertad de mejorar el programa y publicar las mejoras
