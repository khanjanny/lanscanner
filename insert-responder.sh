#!/bin/bash
function insert_data () {
	find .vulnerabilidades -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	find .enumeracion -size  0 -print0 |xargs -0 rm 2>/dev/null # delete empty files
	insert-data.py 2>/dev/null
	mv .enumeracion/* .enumeracion2 2>/dev/null
	mv .vulnerabilidades/* .vulnerabilidades2 2>/dev/null
	mv .banners/* .banners2 2>/dev/null
	}
	

for archivo_original in $(ls responder 2>/dev/null); do		
	ip=`echo $archivo_original | cut -d "-" -f 4 | sed 's/.txt//'`
	cp responder/$archivo_original .vulnerabilidades/"$ip"_ntlm_llmnr.txt
done

insert_data
