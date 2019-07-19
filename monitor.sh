#!/bin/bash
# */10 * * * * root cd /home/hkng/monitor; bash monitor.sh >> log.txt
# anonftp,” or “x11open.”
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
RESET='\e[0m'

while true; do 
current_time=`date +"%H:%M"`
echo "Current time: $current_time"
delta=`date +"%M"`
delta=$(echo "($delta*2)/60" | bc -l )
echo "Delta: $delta"
echo ""

echo -e "$OKBLUE[+] Revisando procesos de python $RESET"		
for line in $( ps aux | grep --color=never get_ssl_cert | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 2 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de snmpwalk $RESET"		
for line in $( ps aux | grep --color=never snmpwalk | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 3 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de netcat $RESET"		
for line in $( ps aux | grep --color=never nc | grep -v color | grep "\-w 3" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 3 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de perl $RESET"		
for line in $( ps aux | grep --color=never perl  | grep -v color | egrep -v "passWeb|joomscan|web-buster|getBanners|color|getDomainInfo|mass-scan|smtp-user-enum" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 1 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""


echo -e "$OKBLUE[+] Revisando procesos de web-buster $RESET"		
for line in $( ps aux | grep --color=never web-buster | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 40 && $diff -lt 70 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de hydra/medusa/patator $RESET"		
for line in $( ps aux | egrep --color=never "hydra|medusa|patator" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 3 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de masscan $RESET"		
for line in $( ps aux | grep --color=never masscan | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 10 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de reaver/snmp $RESET"		
for line in $( ps aux | egrep --color=never "reaver|snmp" | grep -v color | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	if [[  $diff -gt 0 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""

echo -e "$OKBLUE[+] Revisando procesos de nmap $RESET"		
for line in $( ps aux | grep --color=never nmap | egrep -v "getBanners|color|nmap-udp" | awk '{print $2,$9}' | tr " " ";" ); do
	pid=`echo $line | cut -f1 -d";"`
	time=`echo $line | cut -f2 -d";"`
    #echo process time: $time
    echo "pid: $pid time $time"
               
	diff=$(  echo "$current_time - $time"  | sed 's%:%+(1/60)*%g' | bc -l )	
	diff=$(echo "($diff - $delta)*60" | bc  ) # fix with delta
	diff=`printf "%.0f\n" "$diff"` # round
	diff=`echo $diff | tr -d -`
	echo "Idle time: $diff minutes"	
	
	
	if [[  $diff -gt 8 && $diff -lt 60 ]];then 
		
		echo -e "$OKRED[-] Killing $pid) $RESET"
		kill -9 $pid		
	else
		echo -e "$OKGREEN[+] OK $RESET"		
	fi
	echo ""		
done
echo ""
echo ""
echo ""
sleep 60
done

