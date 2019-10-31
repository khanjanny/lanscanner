#!/bin/bash

# john --show Magistratura-NTLMv2.txt | cut -d ":" -f1-3 > john.pot
archivo=$1 #cracked.csv

function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}
	

for archivo_original in $(ls responder 2>/dev/null); do		
#echo "archivo_original $archivo_original"
	if [[ ${archivo_original} == *"SMB"* ]];then 
		ip=`echo $archivo_original | cut -d "-" -f 4 | sed 's/.txt//'`
		#echo "ip $ip"
		cp responder/$archivo_original .vulnerabilidades/"$ip"_ntlm_llmnr.txt
	else	
		ip=`echo $archivo_original | cut -d "-" -f 3 | sed 's/.txt//'`
		#echo "ip $ip"
		cp responder/$archivo_original .vulnerabilidades/"$ip"_ntlm_llmnr.txt
	fi
				
	
done


IFS=$'\n'
for line in `cat $archivo`;
do 		
	 username=`echo $line | cut -d ":" -f 1`
	 password=`echo $line | cut -d ":" -f 7 | tr -d '\n'`
	 domain=`echo $line | cut -d ":" -f 3`	 
	 
	 #username=`echo $username | sed 's/~/ /g'`
	
	 ip=`grep -i "$username" responder/*.txt | cut -d "-" -f3 | cut -d "t" -f1 | head -1`
	 ip=${ip//[$'\t\r\n']} # limpiar saltos de linea
	 ip=`echo "${ip::-1}"` # limpiar .txt
	 #echo "$ip $username ($domain) $password"
	# [445][smb] host: 172.16.0.3   login: att   password: att	 
	 echo -e "IP:$ip  $domain\\\\\\$username  Pasword:$password" > .vulnerabilidades/"$ip"_445_passwordHost.txt
	 
	 #pth-winexe -U administrador%prtgadmin3 //192.168.1.199  ipconfig
	 #echo "echo \"$ip\"" >> comand.sh
	 #echo "pth-winexe -U $domain\\\\$username%$password //$ip ipconfig " >> comand.sh
	 #echo "echo \"\"">> comand.sh
	 	 
done


insert_data
