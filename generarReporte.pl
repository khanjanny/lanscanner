#!/usr/bin/perl
binmode STDOUT, ':utf8';
use Data::Dumper;
use XML::Simple;
use Time::localtime;
use Getopt::Std;
use Term::ANSIColor qw(:constants);
use MIME::Base64 qw( decode_base64 );
no warnings;
use DBI;
use Encode;
use URI::Escape;
use utf8;
use Switch;
    



$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0; 
my $t = localtime;
my $today = sprintf("%04d-%02d-%02d",$t->year + 1900, $t->mon + 1, $t->mday);

my $debug = 0; 
my $json =0; 


getopts('d:h:', \%opts);

sub banner
{

	print "Autor: Daniel Torres\n";
	print "\n";
}

sub usage { 
  
  print "Uso:  \n";
  print "Autor: Daniel Torres Sandi \n";
  print  " generarReporte.pl -d ejemplo.com \n"; 
  
  
}	
# Print help message if required
if ($opts{'h'} || !(%opts)) {
	usage();
	exit 0;
}

################### Load xml ####################
my $archivo_vulnerabilidades = "/usr/share/lanscanner/vulnerabilidades.xml";
my $xml = new XML::Simple;

# read accounts XML file
$vulnerabilidades = $xml->XMLin($archivo_vulnerabilidades, ForceArray=>['item']);
$total_vulnerabilidades = @{$vulnerabilidades->{vuln}}; 


######################################################


my $dominio = $opts{'d'} if $opts{'d'};

my $resultados_externos = `find EXTERNO -iname resultados.db`;
my $resultados_internos = `find INTERNO -iname resultados.db`;
my $resultados_todos = $resultados_internos.$resultados_externos;
my @resultados_array = split("\n",$resultados_todos);

my $contador = 1;
my $total_host_analizados = 0;
my $total_host_con_vulnerabilidades = 0;
my $total_host_con_vulnerabilidades_uniq = 0;

my $total_vuln_criticas = 0;
my $total_vuln_altas = 0;
my $total_vuln_medias = 0;

my $host_afectados_vulCriticas = 0;
my $host_afectados_vulAltas = 0;
my $host_afectados_vulMedias = 0;

my $vulnerabilidades_criticas = 0;
my $vulnerabilidades_altas = 0;
my $vulnerabilidades_medias = 0;

for my $resultados_db (@resultados_array)
{
	print "Recolectando resultados de: $resultados_db \n";
	my $vector = $resultados_db;
	$vector =~ s/\/.*//s;
	print "Vector: $vector \n";
	
	my $ruta = $resultados_db;	
	$ruta =~ s/\/resultados.db//g; 
	#INTERNO/usuarios/resultados.db
	my $segmento = $resultados_db;
	$segmento =~ s/INTERNO\///g;
	$segmento =~ s/EXTERNO\///g;
	 
	$segmento =~ s/\/resultados.db//g; 
		
	my $dsn      = "dbi:SQLite:dbname=$resultados_db";
	my $user     = "";
	my $password = "";
	my $dbh = DBI->connect($dsn, $user, $password, {
		PrintError       => 0,
		RaiseError       => 1,
		AutoCommit       => 1,
		FetchHashKeyName => 'NAME_lc',
		});
 
# ...
	my $host_analizados = `wc -l $ruta/.datos/total-host-vivos.txt | cut -d " " -f1`;
	$total_host_analizados = $total_host_analizados + $host_analizados;
	my $ip = `grep --color=never IP $ruta/reportes/info.txt`;
	my $mac = `grep --color=never MAC $ruta/reportes/info.txt`;
	
	open (SALIDA_HTML,">>reporte.html") || die "ERROR: No puedo abrir el fichero reporte.html\n";
	if ($vector eq "INTERNO")
	{
		print SALIDA_HTML "Vector: $vector <br>\n";
		print SALIDA_HTML "Segmento: $segmento <br>\n";
		print SALIDA_HTML "$ip <br>\n";
		print SALIDA_HTML "$mac <br>\n\n\n";
		
	}
	else
	{
		print SALIDA_HTML "Vector: $vector <br>\n";
		print SALIDA_HTML "Dominio: $segmento <br>\n\n";
	}
	

	close (SALIDA_HTML);

	my $sth = $dbh->prepare("SELECT COUNT (DISTINCT IP) FROM VULNERABILIDADES;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $host_con_vulnerabilidades_uniq = $row[0];
	$total_host_con_vulnerabilidades_uniq = $total_host_con_vulnerabilidades_uniq + $host_con_vulnerabilidades_uniq;

	my $sth = $dbh->prepare("SELECT COUNT (IP) FROM VULNERABILIDADES;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $host_con_vulnerabilidades = $row[0];
	$total_host_con_vulnerabilidades = $total_host_con_vulnerabilidades + $host_con_vulnerabilidades;	
	
	
	my $sth = $dbh->prepare("select COUNT (DISTINCT IP) from VULNERABILIDADES where tipo ='ms17010' or tipo ='ms08067' or tipo ='webdav' or tipo ='passwordBD' or tipo ='phpmyadminPassword' or tipo ='passTomcat' or tipo ='mailPass' or tipo ='shellshock' or tipo ='zimbraXXE' or tipo ='winboxVuln';");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_criticas = $row[0];
	$total_vuln_criticas = $total_vuln_criticas + $vul_criticas;	

	my $sth = $dbh->prepare("select COUNT (DISTINCT IP) from VULNERABILIDADES where tipo ='archivosPeligrosos' or tipo ='compartidoNFS' or tipo ='BlueKeep' or tipo ='compartidoSMB' or tipo ='passwordHost' or tipo ='logeoRemoto' or tipo ='heartbleed' or tipo ='adminPassword' or tipo ='rootPassword' or tipo ='ciscoPassword' or tipo ='passwordMikroTik' or tipo ='VNCnopass' or tipo ='VNCbypass' or tipo ='vulnDahua' or tipo ='openrelay';");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_altos = $row[0];
	$total_vuln_altas = $total_vuln_altas + $vul_altos;	

	my $sth = $dbh->prepare("select COUNT (DISTINCT IP) from VULNERABILIDADES where tipo ='modoAgresivo' or tipo ='passwordDefecto' or tipo ='passwordDahuaTelnet' or tipo ='openstreaming' or tipo ='phpinfo' or tipo ='slowloris' or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='spoof' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='vrfy' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL'  or tipo ='malware' ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_medios = $row[0];
	$total_vuln_medias = $total_vuln_medias + $vul_medios;	

   
	# iterar por el archivo XML de vulnerabilidades
	for (my $i=0; $i<$total_vulnerabilidades;$i++)
	{
     
		my $cod = $vulnerabilidades->{vuln}->[$i]->{cod};     
		my $nombre = $vulnerabilidades->{vuln}->[$i]->{nombre};
		my $riesgo = $vulnerabilidades->{vuln}->[$i]->{riesgo};     
		my $descripcion = $vulnerabilidades->{vuln}->[$i]->{descripcion};     
		my $recomendacion = $vulnerabilidades->{vuln}->[$i]->{recomendacion};		
		$recomendacion =~ s/DOMINIOENTIDAD/$dominio/g; 				
		$recomendacion =~ s/SALTOLINEA/<br>/g; 
		$recomendacion =~ s/AMPERSAND/\&/g; 
		my $verificacion = $vulnerabilidades->{vuln}->[$i]->{verificacion}; 		
   		$verificacion =~ s/SALTOLINEA/<br>/g; 
		$verificacion =~ s/AMPERSAND/\&/g; 		
		$verificacion =~ s/DOMINIOENTIDAD/$dominio/g; 

  
          
		my $sql = "SELECT * FROM VULNERABILIDADES WHERE TIPO=\"$cod\";";
		my $sth = $dbh->prepare($sql);
		$sth->execute();
        
		my $filas =1;
		my $hosts = "";
   
		if ($cod eq "passwordBD")
		{
			while (my @row = $sth->fetchrow_array) {     
				#ACCOUNT FOUND: [postgres] Host: 192.168.2.222 User: postgres Password:  [SUCCESS]
				$vuln_detalles = $row[3];	     
				$vuln_detalles =~ s/User/Usuario/g; 
				$vuln_detalles =~ s/ACCOUNT FOUND://g; 				
				$vuln_detalles =~ s/\[SUCCESS\]//g;
				$vuln_detalles =~ s/Host/IP/g;
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;
	     
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
		
		if ($cod eq "passwordMikroTik")
		{
			while (my @row = $sth->fetchrow_array) {     
				#[+] Login successful!!! Default RouterOS credentials were not changed. Log in with admin:<BLANK>
				$ip = $row[0];
				$vuln_detalles = $row[3];	     
				$vuln_detalles =~ s/Default RouterOS credentials were not changed. Log in with //g;
				$vuln_detalles =~ s/Login successful!!!//g;
				$vuln_detalles =~ s/\[\+\]/Credenciales:/g;
								
				$hosts = $hosts.$ip." ".$vuln_detalles."<br>";
				$filas++;
	     
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
   
		if (($cod eq "adminPassword") || ($cod eq "rootPassword")  || ($cod eq "ciscoPassword"))
		{
			while (my @row = $sth->fetchrow_array) {     
				#18:25:52 patator    INFO - 200  1126:-1        0.201 | admin                              |    22 | HTTP/1.0 200 OK
			
				my $user = $cod;
				$ip = $row[0];	
				$user =~ s/Password//g; 		 
				$vuln_detalles = $row[3];	
	          
				$content =~ /|\ (.*?)                              \|/;
				my $password = $1; 
	
				$hosts = $hosts."$ip - $user/$password (HTTP)<br>";
				$filas++;
				
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
		
		if ($cod eq "winboxVuln")
		{
			while (my @row = $sth->fetchrow_array) {     
											
				$ip = $row[0];							 
				$vuln_detalles = $row[3];	
	          	$vuln_detalles =~ s/User/Usuario/g; 		
	          	$vuln_detalles =~ s/Pass/Contraseña/g; 
				$hosts = $hosts."$ip (WinBox) - $vuln_detalles<br>";
				$filas++;
				
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
				
		if ($cod eq "logeoRemoto") 
		{
			while (my @row = $sth->fetchrow_array) {     
				$ip = $row[0];
				$vuln_detalles = $row[3];
				$hosts = $hosts." $ip ($vuln_detalles) <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
		
		if ($cod eq "passwordHost") 
		{
			while (my @row = $sth->fetchrow_array) {     
				#[445][smb] host: 192.168.2.5   login: administrador   password: 123
				$vuln_detalles = $row[3];	     
				$vuln_detalles =~ s/login/Usuario/g; 
				$vuln_detalles =~ s/\[445\]\[smb\] host/IP/g;
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
   
		if ($cod eq "compartidoSMB")
		{
			while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY

				$ip = $row[0];	
				$vuln_detalles = $row[3];	 	            
				$vuln_detalles =~ s/                                             	/ /g; 	     
				$vuln_detalles =~ s/READ, WRITE|READ ONLY|READ, WRITE/<br>/g;
				$hosts = $hosts."\\\\$ip <br>    $vuln_detalles <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}      	
      	      	
      	if (($cod eq "passwordDefecto") || ($cod eq "passwordAdivinado"))
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];	
				$port = $row[1];				
				$vuln_detalles = $row[3];	 	            								
				#ACCOUNT FOUND: [telnet] Host: 192.168.6.1 User: admin Password:  [SUCCESS]
				$vuln_detalles =~ s/ACCOUNT FOUND://g; 
				$vuln_detalles =~ s/Password encontrado://g; 
				$vuln_detalles =~ s/\[SUCCESS\]//g; 				
				$hosts = $hosts." $ip:$port ".$vuln_detalles."<br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
      	
   	if (($cod eq "mailPass") || ($cod eq "erroresWeb") || ($cod eq "ACL")  )
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];
				$verificacion =~ s/CORREOENTIDAD/$ip/g; 	
				$vuln_detalles = $row[3];	 	            
				$vuln_detalles =~ s/Password encontrado/ /g;
				$vuln_detalles =~ s/\n/<br>\n/g; 
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
   

   
		if (($cod eq "googlehacking") || ($cod eq "listadoDirectorio") || ($cod eq "phpmyadminPassword") )
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	 	            	     
				$vuln_detalles =~ s/http/<br>http/g;
				$vuln_detalles =~ s/Password encontrado://g;
				$hosts = $hosts." $vuln_detalles <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}  
		}
		
		
   
		if ($cod =~ m/snmpCommunity/) 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $community_string = `echo '$vuln_detalles' |grep --color=never "Community string"`;
				# print "community_string $community_string \n";
				$hosts = $hosts."$ip: $community_string <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}       
		}
	
		if ($cod =~ m/shellshock/) 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $url_shellsock = `echo '$vuln_detalles' |grep --color=never "URL"`;	     
				$hosts = $hosts." $url_shellsock <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}       
		}
		
		if ($cod =~ m/phpinfo/) 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $file = `echo '$vuln_detalles' |grep --color=never "SCRIPT_FILENAME"`;
				$hosts = $ip;
				$file =~ s/PATH \(SCRIPT_FILENAME\)://g; 
				$recomendacion =~ s/SCRIPT_FILENAME/$file/g; 				
				$verificacion =~ s/IP/$ip/g; 
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}       
		}
				
		
		if ($cod =~ m/webdav/) 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
	
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my @vuln_detalles_array = split(" ",$vuln_detalles);	     
				my $url_webdav=@vuln_detalles_array[1];
				#print "url_webdav $url_webdav \n";
	     
				$hosts = $hosts." $url_webdav <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}       
		}
   
      
		if ($cod =~ m/archivosPeligrosos/) 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				#200	https://sigec.fonadin.gob.bo:443/.git/	, 
				my @vuln_detalles_array = split("\t",$vuln_detalles);	     
				my $current_url = @vuln_detalles_array[1];	     
	     
				$hosts = $hosts." $current_url <br>";
				$filas++;
				##### Contabilizar nivel de riesgos ######
				switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
				#############################################
			}       
		}
   
		if (($cod eq "ms17010") || ($cod eq "ms08067")  || ($cod eq "vulnDahua") || ($cod eq "passwordDahua")|| ($cod eq "enum4linux")|| ($cod eq "heartbleed") || ($cod eq "directorioLDAP") || ($cod eq "spoof") || ($cod eq "transferenciaDNS") || ($cod eq "listadoDirectorio")  || ($cod eq "vrfy") || ($cod eq "anonymous") || ($cod eq "openstreaming") || ($cod eq "modoAgresivo")  || ($cod eq "zimbraXXE") || ($cod eq "BlueKeep") || ($cod eq "slowloris") || ($cod eq "openresolver") || ($cod eq "openrelay") || ($cod eq "malware") ) 
		{
			#$hosts = "<table border='0' cellspacing='10'><tr>";	 	
		
			while (my @row = $sth->fetchrow_array) {     
			if (( $filas % 5 == 0 ) && ($filas >0))
				{ #$hosts = $hosts."<td>".$row[0]."</td></tr><tr>";
				$hosts = $hosts.$row[0]."\n<br>";
				}
			else
				{ #$hosts = $hosts."<td>".$row[0]."</td>";
				$hosts = $hosts.$row[0]."&nbsp;&nbsp;&nbsp;";   	 
				}
			$filas++;
      
			##### Contabilizar nivel de riesgos ######
			switch ($riesgo) {    	
					case "Crítico"	{ $host_afectados_vulCriticas++ }
					case "Alto"	{ $host_afectados_vulAltas++ }
					case "Medio"	{ $host_afectados_vulMedias++ }
				}
			#############################################
			}	   
     
			$hosts = $hosts."</tr></table>";
		}
   
   
		if ($filas>1)
		{	   
				print "cod $cod\n";
				print "nombre $nombre\n\n";
		
			#    open (SALIDA,">>reporte.csv") || die "ERROR: No puedo abrir el fichero google.html\n";
			#		print SALIDA "Nombre:;$nombre\n";
				#print SALIDA "Riesgo:;$riesgo\n";
				#print SALIDA "Descripcion:;$descripcion\n";
				#print SALIDA "Evidencia;Evidencia $contador;\n";
				#print SALIDA "Recomendacion:;$recomendacion\n";
				#print SALIDA "Hosts:;$hosts\n";
				#print SALIDA "\n\n";
				#close (SALIDA);
		
				open (SALIDA_HTML,">>reporte.html") || die "ERROR: No puedo abrir el fichero reporte.html\n";
				print SALIDA_HTML "<div class='simditor-table'> <table border=1>  <colgroup><col width='20%'><col width='80%'></colgroup>\n";		
				open (SALIDA_HTML,">>reporte.html") || die "ERROR: No puedo abrir el fichero reporte.html\n";
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Nro:</td><td class='' style='text-align: justify;'>$contador</td>\n";
				print SALIDA_HTML "</tr>\n";
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Vulnerabilidad:</td><td class='' style='text-align: justify;'>$nombre</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Criticidad:</td><td class='' style='text-align: justify;'>$riesgo</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Descripción:</td><td class='' style='text-align: justify;'>$descripcion</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Evidencia:</td><td class='' style='text-align: justify;'> Evidencia $contador</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Verificación:</td><td class='' style='text-align: justify;'> $verificacion</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Recomendación:</td><td class='' style='text-align: justify;'>$recomendacion</td>\n";
				print SALIDA_HTML "</tr>\n";
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Hosts afectados:</td><td class='' style='text-align: justify;'>$hosts</td>\n";
				print SALIDA_HTML "</tr>\n";										
				print SALIDA_HTML "</table></div>\n<div><br></div> <p></p> \n\n";	
				close (SALIDA_HTML);
				$contador++;
		}#if filas    
	} #for 
} # fin for

my $total_vuln = $host_afectados_vulCriticas + $host_afectados_vulAltas + $host_afectados_vulMedias;
my $total_vuln_uniq = $total_vuln_criticas + $total_vuln_altas + $total_vuln_medias;
open (SALIDA,">>reporte.csv") || die "ERROR: No puedo abrir el fichero google.html\n";
	print SALIDA "\n\nTotal hosts analizados:;$total_host_analizados\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico:;$total_host_con_vulnerabilidades\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico (host unicos):;$total_host_con_vulnerabilidades_uniq\n\n";
	print SALIDA "Total vulnerabilidades criticas:; $host_afectados_vulCriticas;\n";
	print SALIDA "Total vulnerabilidades altas:;$host_afectados_vulAltas\n";
	print SALIDA "Total vulnerabilidades medias:;$host_afectados_vulMedias\n";
	print SALIDA "Total vulnerabilidades:;$total_vuln\n\n";
	print SALIDA "Total vulnerabilidades criticas(unicos):; $total_vuln_criticas;\n";
	print SALIDA "Total vulnerabilidades altas(unicos):;$total_vuln_altas\n";
	print SALIDA "Total vulnerabilidades medias(unicos):;$total_vuln_medias\n";
	print SALIDA "Total vulnerabilidades (unicos):;$total_vuln_uniq\n\n";
	print SALIDA "\n\n";
close (SALIDA);

		
	#print "host_analizados ($host_analizados)\n";   
	#print "host_con_vulnerabilidades ($host_con_vulnerabilidades)\n";
	#print "host_con_vulnerabilidades_uniq ($host_con_vulnerabilidades_uniq)\n";
	#print "riesgos_criticos ($host_afectados_vulCriticas)\n";
	#print "riesgos_altos ($host_afectados_vulAltas)\n";
	#print "riesgos_medios ($host_afectados_vulMedias)\n";
	#$dbh->disconnect;
