#!/bin/bash
# john --show Magistratura-NTLMv2.txt | cut -d ":" -f1-3 > john.pot
#sed -i 's/ /~/g' cracked.pot
IFS=$'\n'
for line in `cat cracked.pot`;
do 		
	 username=`echo $line | cut -d ":" -f 1`
	 password=`echo $line | cut -d ":" -f 7`
	 domain=`echo $line | cut -d ":" -f 3`	 
	 
	 #username=`echo $username | sed 's/~/ /g'`
	 #echo "$username $password"
	 
	 ip=`grep -i "$username" *.txt | cut -d "-" -f3 | cut -d "t" -f1 | head -1`
	 ip=${ip//[$'\t\r\n']} # limpiar saltos de linea
	 ip=`echo "${ip::-1}"` # limpiar .txt
	# [445][smb] host: 172.16.0.3   login: att   password: att
	
	 echo -e "$ip\t445\tpasswordHost\t IP:$ip  $domain\\\\\\$username  Pasword:$password" >> results.txt 	
	 	 
done
