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

######## #Vulnerabilidades por riesgo ########
#AGETIC
my $total_vul_criticas_agetic = 0;
my $total_vul_altas_agetic = 0;
my $total_vul_medias_agetic = 0;
#####

#Entidades privadas
#my $vuln_criticas_privadas = 0;
#my $vuln_altas_privadas = 0;
#my $vuln_medias_privadas = 0;
#my $vuln_bajas_privadas = 0;
######

		
#####################################


######## total host afectados  ########
#AGETIC
my $total_servicios_vuln_criticas_agetic = 0;
my $total_servicios_vuln_altas_agetic = 0;
my $total_servicios_vuln_medias_agetic = 0;
#####

#Entidades privadas
#my $total_hosts_vuln_criticas_privada = 0;
#my $total_hosts_vuln_altas_privada = 0;
#my $total_hosts_vuln_medias_privada = 0;
######
#####################################

###### Vulnerabilidades por vector
my $total_vuln_externas = 0;
my $total_vuln_internas = 0;
#######

###### Vulnerabilidades por activos ####
my $aplicacionWeb = 0;
my $servidores = 0;
my $baseDatos = 0;
my $correos = 0;
my $estacionesTrabajo = 0;
my $telefoniaIP = 0;
my $sistemaVigilancia = 0;
my $dispositivosRed = 0;
my $personal = 0;
my $otros = 0; #Impresoras, lectores de huella
#############

#### Vulnerabilidades por categoria de vulnerabilidad ####
my $vulnerabilidadWeb = 0; #Sqli, XSS, falta control acceso
my $passwordDebil = 0;
my $faltaParches = 0;
my $errorConfiguracion = 0;
#############

my $totalPruebas = 0;

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
	my $host_analizados = 0;	
	print "ruta $ruta \n";
	
	####
	#EXTERNO/senamhi.gob.bo
	# total pruebas por vector
	my $pruebasVulnerabilidades = `ls $ruta/logs/vulnerabilidades | wc -l`;
	my $pruebasPassword = `ls $ruta/logs/cracking | wc -l`;
	$totalPruebas = $totalPruebas + $pruebasVulnerabilidades + $pruebasPassword ;
	######################
	
	my $pruebasVulnerabilidades = `ls $ruta/logs/vulnerabilidades`;
	my @pruebasVulnerabilidades_array = split("\n",$pruebasVulnerabilidades);
		
	open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
	print SALIDA "\n\nVector: $vector\n";
	print SALIDA "IP;Puerto;Código;Descripción\n";
	close (SALIDA);	
	
	foreach ( @pruebasVulnerabilidades_array ) {
		#10.0.0.141_25_openrelay.txt
		my @vulnerabilidad_array = split("_",$_);
		my $ip = @vulnerabilidad_array[0];
		my $port = @vulnerabilidad_array[1];
		my $vuln = @vulnerabilidad_array[2];
		$vuln =~ s/.txt//g; 		
		my ($codVul,$vuln_descripcion) =  buscarDescripcion($vuln);				
		$codVul="" if ($codVul eq "ninguna");
		
		open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
		print SALIDA "$ip;$port;$codVul;$vuln_descripcion;$vuln\n";
		close (SALIDA);	
	}
	
	
	if($ruta =~ /EXTERNO/m){	
		my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES");
		$sth->execute();
		my @row = $sth->fetchrow_array;
		my $vul_externas = $row[0];		
		$total_vuln_externas = $total_vuln_externas + $vul_externas;		
		
		$host_analizados =`wc -l $ruta/reportes/subdominios.csv | cut -d " " -f1`;
	}
	else
	 {
		my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES");
		$sth->execute();
		my @row = $sth->fetchrow_array;
		my $vul_internas = $row[0];
		$total_vuln_internas = $total_vuln_internas + $vul_internas;	 
		
		$host_analizados =`wc -l $ruta/.datos/total-host-vivos.txt | cut -d " " -f1`;
	 }
 	
 	
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
	

	
	####################### AGETIC ###################
	#Total vulnerabilidades criticas
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='ms17010' or tipo ='ms08067' or tipo ='webdav' or tipo ='passwordBD' or tipo ='passTomcat' or tipo ='mailPass' or tipo ='shellshock' or tipo ='zimbraXXE' or tipo ='winboxVuln';");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_criticas = $row[0];
	$total_vul_criticas_agetic = $total_vul_criticas_agetic + $vul_criticas;	

	#Total vulnerabilidades altas
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='archivosPeligrosos' or tipo ='compartidoNFS' or tipo ='BlueKeep' or tipo ='compartidoSMB' or tipo ='passwordHost' or tipo ='logeoRemoto' or tipo ='heartbleed' or tipo ='passwordAdivinado' or tipo ='passwordMikroTik' or tipo ='VNCnopass' or tipo ='VNCbypass' or tipo ='vulnDahua' or tipo ='openrelay' or tipo ='perdidaAutenticacion' or tipo ='spoof' or tipo ='slowloris' or tipo ='wordpressPass'; ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_altos = $row[0];
	$total_vul_altas_agetic = $total_vul_altas_agetic + $vul_altos;	

	#Total vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='modoAgresivo' or tipo ='passwordDefecto' or tipo ='passwordDahuaTelnet' or tipo ='openstreaming' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='vrfy' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='ms12020' or tipo ='debugHabilitado' or tipo ='wpusers' or tipo ='CVE15473' or tipo ='exposicionUsuarios'  ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_medios = $row[0];
	$total_vul_medias_agetic = $total_vul_medias_agetic + $vul_medios;	
	####################################################
	
	
	#Servicios afectados por vulnerabilidades criticas
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='ms17010' or tipo ='ms08067' or tipo ='webdav' or tipo ='passwordBD' or tipo ='passTomcat' or tipo ='mailPass' or tipo ='shellshock' or tipo ='zimbraXXE' or tipo ='winboxVuln';");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_criticas = $row[0];
	$total_servicios_vuln_criticas_agetic = $total_servicios_vuln_criticas_agetic + $servicios_vuln_criticas;	

	#Servicios afectados por vulnerabilidades altas
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='archivosPeligrosos' or tipo ='compartidoNFS' or tipo ='BlueKeep' or tipo ='compartidoSMB' or tipo ='passwordHost' or tipo ='logeoRemoto' or tipo ='heartbleed' or tipo ='adminPassword' or tipo ='rootPassword' or tipo ='ciscoPassword' or tipo ='passwordMikroTik' or tipo ='VNCnopass' or tipo ='VNCbypass' or tipo ='vulnDahua' or tipo ='openrelay' or tipo ='perdidaAutenticacion' or tipo ='spoof' or tipo ='slowloris' or tipo ='wordpressPass' ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_altos = $row[0];
	$total_servicios_vuln_altas_agetic = $total_servicios_vuln_altas_agetic + $servicios_vuln_altos;	

	#Servicios afectados por vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='modoAgresivo' or tipo ='passwordDefecto' or tipo ='passwordDahuaTelnet' or tipo ='openstreaming' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='vrfy' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='ms12020' or tipo ='wpusers' or tipo ='CVE15473' or tipo ='exposicionUsuarios' ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_medios = $row[0];
	$total_servicios_vuln_medias_agetic = $total_servicios_vuln_medias_agetic + $servicios_vuln_medios;	
	####################################################


	#IPs afectados por vulnerabilidades medias
	#my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='modoAgresivo' or tipo ='passwordDefecto' or tipo ='passwordDahuaTelnet' or tipo ='openstreaming' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='vrfy' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='ms12020' ;");
	#$sth->execute();
	#my @row = $sth->fetchrow_array;
	#my $servicios_vuln_medios = $row[0];
	#$total_servicios_vuln_medias_agetic = $total_servicios_vuln_medias_agetic + $servicios_vuln_medios;	
	
	###### Vulnerabilidades por activos ####
	# aplicacionWeb
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='debugHabilitado' or TIPO='listadoDirectorios' or TIPO='archivosDefecto' or TIPO='divulgacionInformacion' or TIPO='archivosPeligrosos' or TIPO='googlehacking' or TIPO='perdidaAutenticacion' or TIPO='erroresWeb' or TIPO='wpusers' or TIPO='exposicionUsuarios'  or TIPO='wordpressPass' ;  ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_app = $row[0];
	$aplicacionWeb = $aplicacionWeb + $vuln_app;	
	
	# servidores
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='compartidoNFS' or TIPO='enum4linux' or TIPO='shellshock' or TIPO='webdav' or TIPO='heartbleed' or TIPO='zimbraXXE' or TIPO='slowloris' or TIPO='CVE15473' or TIPO='directorioLDAP' or TIPO='transferenciaDNS' or TIPO='vrfy' or TIPO='openresolver' or TIPO='openrelay' or TIPO='spoof' or TIPO='openrelay2' ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_serv = $row[0];
	$servidores = $servidores + $vuln_serv;
	
	# base de datos
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordBD'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_bd = $row[0];
	$baseDatos = $baseDatos + $vuln_bd;
	
	# estaciones de trabajo
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordHost' or TIPO='compartidoSMB' or TIPO='ms17010' or TIPO='ms08067' or TIPO='BlueKeep' or TIPO='ms12020'");
	$sth->execute();																					     
	my @row = $sth->fetchrow_array;
	my $vuln_estacion = $row[0];	
	$estacionesTrabajo = $estacionesTrabajo + $vuln_estacion;	
										
    #sistemaVigilancia
    my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='vulnDahua' or TIPO='openstreaming' or TIPO='passwordDahua'");
	$sth->execute();																					     
	my @row = $sth->fetchrow_array;
	my $vuln_vigilancia = $row[0];
	$sistemaVigilancia = $sistemaVigilancia + $vuln_vigilancia;    
	
	#Dispositivos de red
    my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordMikroTik' or TIPO='winboxVuln' or TIPO='passwordDefecto' or TIPO='snmpCommunity' or TIPO='modoAgresivo'");
	$sth->execute();																					     
	my @row = $sth->fetchrow_array;
	my $vuln_red = $row[0];
	$dispositivosRed = $dispositivosRed + $vuln_red;   
		
    # personal
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='mailPass'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_personal = $row[0];	
	$personal = $personal + $vuln_personal;
		
	# otros  #Impresoras, lectores de huella
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='ftpAnonymous'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_otros = $row[0];	
	$otros = $otros + $vuln_otros;
	
		
	#### Vulnerabilidades por categoria ####
	# aplicacionWeb
	# Errores en app web SQli, mala configuracion, XSS
	
	# password
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordMikroTik' or TIPO='passwordAdivinado' or TIPO='passwordHost' or TIPO='passwordDefecto' or TIPO='mailPass' or TIPO='passwordDahua' or TIPO='passwordBD' ;");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_pass = $row[0];	
	$passwordDebil = $passwordDebil + $vuln_pass;
	
	# falta de parches																									     																						    
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='winboxVuln' or TIPO='shellshock' or TIPO='ms17010' or TIPO='ms08067' or TIPO='heartbleed' or TIPO='zimbraXXE' or TIPO='BlueKeep' or TIPO='slowloris' or TIPO='CVE15473' or TIPO='ms12020' or TIPO='vulnDahua' or TIPO='webdav';");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_parches = $row[0];	
	$faltaParches = $faltaParches + $vuln_parches;
	
	# Errores de configuracion																		    																								    																   																				   																								     																						    
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='logeoRemoto' or TIPO='compartidoNFS' or TIPO='compartidoSMB' or TIPO='enum4linux' or TIPO='snmpCommunity' or TIPO='directorioLDAP' or TIPO='transferenciaDNS' or TIPO='vrfy' or TIPO='ftpAnonymous' or TIPO='openstreaming' or TIPO='modoAgresivo' or TIPO='openresolver' or TIPO='openrelay' or TIPO='openrelay2' or TIPO='spoof';  ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_conf = $row[0];	
	$errorConfiguracion = $errorConfiguracion + $vuln_conf;
		
#############
   
   
		
   
	# iterar por el archivo XML de vulnerabilidades
	for (my $i=0; $i<$total_vulnerabilidades;$i++)
	{
     
		my $cod = $vulnerabilidades->{vuln}->[$i]->{cod};     
		my $nombre = $vulnerabilidades->{vuln}->[$i]->{nombre};
		my $riesgoAgetic = $vulnerabilidades->{vuln}->[$i]->{riesgoAgetic};        
		my $descripcion = $vulnerabilidades->{vuln}->[$i]->{descripcion}; 
		my $detalles = $vulnerabilidades->{vuln}->[$i]->{detalles}; 
		    
		
		my $probabilidad = $vulnerabilidades->{vuln}->[$i]->{probabilidad};     
		my $impacto = $vulnerabilidades->{vuln}->[$i]->{impacto};     
		my $riesgoInforme = $vulnerabilidades->{vuln}->[$i]->{riesgoInforme};     
		
		my $agente_amenaza = $vulnerabilidades->{vuln}->[$i]->{agente_amenaza};
		my $impacto_tecnico = $vulnerabilidades->{vuln}->[$i]->{impacto_tecnico};     
		my $impacto_negocio = $vulnerabilidades->{vuln}->[$i]->{impacto_negocio};     
		
		my $referencias = $vulnerabilidades->{vuln}->[$i]->{referencias};     
		
		$referencias =~ s/SALTOLINEA//g; 
		
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
				# [MongoDB] $respuesta
				# [Redis] $respuesta"
				$vuln_detalles = $row[3];	     
				$vuln_detalles =~ s/User/Usuario/g; 
				$vuln_detalles =~ s/ACCOUNT FOUND://g; 				
				$vuln_detalles =~ s/\[SUCCESS\]//g;
				$vuln_detalles =~ s/Host/IP/g;
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;				     		
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
			}			
		}
   
		#fallllta
		if (($cod eq "passwordAdivinado"))
		{
			while (my @row = $sth->fetchrow_array) {     
				# [Tomcat] $line (Usuario:tomcat Password:tomcat)
				# [Cisco] Usuario:cisco $respuesta"
				# Password encontrado: [PRTG] $url Usuario:$user Password:$password
				# [AdminWeb] Usuario:admin $respuesta  #401
				# [445][smb] host: 10.0.0.141   login: administrator   password: Pa$$w0rd
				# Password encontrado: [Pentaho] $url (Usuario:$user Password:$password)				
				$ip = $row[0];					
				$vuln_detalles = $row[3];		          
				$vuln_detalles =~ s/Password encontrado://g;
				$vuln_detalles =~ s/[445]//g;				
				$hosts = $hosts."$host $vuln_detalles<br>";
				
				#if($vuln_detalles =~ /Tomcat|Pentaho|AdminWeb/i){$servidores++;}
				#if($vuln_detalles =~ /Cisco|PRTG/i){$dispositivosRed++;}				
				#if($vuln_detalles =~ /smb/i){$estacionesTrabajo++;}				
				$filas++;
			}			
		}
		
				
		if ($cod eq "wordpressPass")
		{
			while (my @row = $sth->fetchrow_array) {     
											
				$ip = $row[0];							 
				$port = $row[1];
				$vuln_detalles = $row[3];		          	
				$hosts = $hosts."$ip:$port - $vuln_detalles<br>";
				$filas++;								
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
			}  						
		}
				
		if ($cod eq "logeoRemoto") 
		{
			while (my @row = $sth->fetchrow_array) {     
				$ip = $row[0];
				$vuln_detalles = $row[3];
				$hosts = $hosts." $ip ($vuln_detalles) <br>";
				$filas++;				
			}  			
		}
		
		if ($cod eq "passwordHost") #NTLM resonse
		{
			while (my @row = $sth->fetchrow_array) {     
				#IP:192.168.0.2  DOMINIO\\Usuario  Pasword:1234
				$vuln_detalles = $row[3];	     				
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;				
			}  					
		}
   
      
		if ($cod eq "compartidoNFS")  
		{
			while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY

				$ip = $row[0];	
				$vuln_detalles = $row[3];
				print "vuln_detalles $vuln_detalles \n";
				$vuln_detalles2=`echo '$vuln_detalles' | grep --color=never "dr" | awk '{print \$7}'`;
				$vuln_detalles2 =~ s/\n/<br>/g; 					
				#my $usuarios_grupos = `echo '$vuln_detalles' |egrep --color=never "Domain Group|Local User" | grep -vi body`;					 	            							
				$hosts = $hosts."\\\\$ip <br>    $vuln_detalles2 <br>";
				$filas++;				
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
			}  						
		}      	
      	      	
      	if ($cod eq "passwordDefecto")
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];	
				$port = $row[1];				
				$vuln_detalles = $row[3];	
				#[Juniper] $respuesta" 	            								
				#[Zyxel] $respuesta"
				#[Mikrotik] $respuesta
				#[Ubiquiti] $respuesta"
				#[Pfsense] $respuesta
				#[Netgear] $respuesta
				#[Linksys] $respuesta
				#[D-link] $respuesta
				#[Tp-link] $respuesta"
				#[ZTE] $respuesta
				#Password encontrado: [ZTE] $url (Usuario:$user Password:$password)
				#ACCOUNT FOUND: [telnet] Host: 192.168.6.1 User: admin Password:  [SUCCESS]
				$vuln_detalles =~ s/ACCOUNT FOUND://g; 
				$vuln_detalles =~ s/Password encontrado://g; 
				$vuln_detalles =~ s/\[SUCCESS\]//g; 				
				$hosts = $hosts." $host ".$vuln_detalles."<br>";							
				$filas++;
			}  						
		}
      	
   	if (($cod eq "erroresWeb") || ($cod eq "debugHabilitado") || ($cod eq "exposicionUsuarios" ))
		{
			while (my @row = $sth->fetchrow_array) 
			{
				$ip = $row[0];				
				$vuln_detalles = $row[3];	 	            				
				$vuln_detalles =~ s/\n/<br>\n/g; #http://dominio.com/user
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;			
			}  					
		}
		
		
		if (($cod eq "mailPass"))
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];
				$verificacion =~ s/CORREOENTIDAD/$ip/g; 	
				$vuln_detalles = $row[3];	 	            
				$vuln_detalles =~ s/Password encontrado/ /g;
				$vuln_detalles =~ s/\n/<br>\n/g; 
				$hosts = $hosts.$vuln_detalles."<br>";
				$filas++;								
			}  						
		}
   
   		if (($cod eq "wpusers"))
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];				
				$port = $row[1];
				$vuln_detalles = $row[3];	 	            				
				$vuln_detalles =~ s/\n/<br>\n/g; 
				$hosts = $hosts."Usuarios enumerados del host $ip:$port : <br>".$vuln_detalles."<br><br>";
				$filas++;								
			}  						
		}
   

   
		if ($cod eq "googlehacking" )
		{
			while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	 	            	     
				$vuln_detalles =~ s/http/<br>http/g;
				$vuln_detalles =~ s/Password encontrado://g;
				$hosts = $hosts." $vuln_detalles <br>";
				$filas++;				
			}  						
		}
				
		if ($cod eq "listadoDirectorio") 
		{
			while (my @row = $sth->fetchrow_array) 
			{  
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$port = $row[1];	
				$vuln_detalles = $row[3];	
				
				if($vuln_detalles =~ /index/i)
					{
					$hosts = $hosts." http://$ip:$port <br>" if ($port eq "80" ||  $port eq "81" ||  $port eq "82" ||  $port eq "83" ||  $port eq "84" ||  $port eq "85" ||  $port eq "86" ||  $port eq "8080" ||  $port eq "8081" ||  $port eq "8082"  || $port eq "8010"  ||  $port eq "8800");
					$hosts = $hosts." https://$ip:$port <br>" if ($port eq "443" ||  $port eq "8443" ||  $port eq "4443" ||  $port eq "4433" );
					}
				else
					{$vuln_detalles =~ s/200 //g; ;$hosts = $hosts." $vuln_detalles <br>";}								 	            	     						
				$filas++;				
			}  						
		}
		
		if ($cod eq "divulgacionInformacion") 		
		{
			while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$port = $row[1];	
				$vuln_detalles = $row[3];	
				# URL  http://192.168.50.52:80/dashboard/phpinfo.php
				$vuln_detalles =~ /URL(.*?)\n/;				
				$hosts = $hosts." $1 <br>";										
				$filas++;				
			}  						
		}
		
		if ($cod eq "enum4linux") 		
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$port = $row[1];	
				$vuln_detalles = $row[3];									
				my $usuarios_grupos = `echo '$vuln_detalles' |egrep --color=never "Domain Group|Local User" | grep -vi body`;
				#print "enum4linux usuarios_grupos $usuarios_grupos \n";
				$usuarios_grupos =~ s/\n/<br>/g; 
				$hosts = $hosts."IP: ".$ip." usuarios/grupos identificados:<br> $usuarios_grupos<br><br>";
				$filas++;				
			}  						
		}
					
				
		if ($cod eq "snmpCommunity") 
		{
				while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $community_string = `echo '$vuln_detalles' |grep --color=never "Community string"`;
				# print "community_string $community_string \n";
				$hosts = $hosts."$ip: $community_string <br>";
				$filas++;				
			}       						
		}
	
		if ($cod eq "shellshock") 		
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 
				#	Users                                             	READ ONLY		
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $url_shellsock = `echo '$vuln_detalles' |grep --color=never "URL"`;	     
				$hosts = $hosts." $url_shellsock <br>";
				$filas++;				
			}       					
		}
		
			
		if ($cod eq "webdav") 
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 
				#	Users                                             	READ ONLY
	
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my @vuln_detalles_array = split(" ",$vuln_detalles);	     
				my $url_webdav=@vuln_detalles_array[1];
				#print "url_webdav $url_webdav \n";
	     
				$hosts = $hosts." $url_webdav <br>";
				$filas++;	
			}       			
			$faltaParche++;
		}
   
      		
		if (($cod eq "archivosPeligrosos") || ($cod eq "archivosDefecto")  || ($cod eq "perdidaAutenticacion") )
		{
				while (my @row = $sth->fetchrow_array) {     		 					
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				$vuln_detalles =~ s/\n/<br>/g; 
				#https://sigec.fonadin.gob.bo:443/.git/	, 				    	    
				$hosts = $hosts." $vuln_detalles ";
				$filas++;				
			}       						
		}
   
				
		
		########################################################

		
		# Solo se muestra la IP y el puerto en el campo "host"
		if (($cod eq "ms17010") || ($cod eq "ms08067")  || ($cod eq "vulnDahua") || ($cod eq "passwordDahua")|| ($cod eq "heartbleed") || ($cod eq "directorioLDAP") || ($cod eq "spoof") || ($cod eq "transferenciaDNS")  || ($cod eq "vrfy") || ($cod eq "ftpAnonymous") || ($cod eq "openstreaming") || ($cod eq "modoAgresivo")  || ($cod eq "zimbraXXE") || ($cod eq "BlueKeep") || ($cod eq "slowloris") || ($cod eq "openresolver") || ($cod eq "openrelay") || ($cod eq "openrelay2") || ($cod eq "CVE15473") || ($cod eq "ms12020")  )   
		{
			#$hosts = "<table border='0' cellspacing='10'><tr>";	 	
			
			#print "filas $filas \n";
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
			}
			$hosts = $hosts."</tr></table>";
		}
   
   
		if ($filas>1)
		{	   
				print "cod $cod\n";
				print "nombre $nombre\n\n";							
						
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
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Criticidad:</td><td class='' style='text-align: justify;'>$riesgoAgetic</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Descripción:</td><td class='' style='text-align: justify;'>$descripcion</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Evidencia:</td><td class='' style='text-align: justify;'> Evidencia $contador</td>\n";
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Verificación:</td><td class='' style='text-align: justify;'> $verificacion</td>\n" if ($verificacion ne "ninguna");
				print SALIDA_HTML "</tr>\n";	
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Recomendación:</td><td class='' style='text-align: justify;'>$recomendacion</td>\n";
				print SALIDA_HTML "</tr>\n";
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Hosts afectados:</td><td class='' style='text-align: justify;'>$hosts</td>\n";
				print SALIDA_HTML "</tr>\n";										
				print SALIDA_HTML "</table></div>\n<div><br></div> <p></p> \n\n";	
				close (SALIDA_HTML);
								
				$hosts =~ s/<br>//g;
				$hosts =~ s/\n<br>/\n/g;
				$hosts =~ s/&nbsp;&nbsp;&nbsp;/\t/g;
				$hosts =~ s/<\/tr><\/table>//g;			
				$hosts =~ s/\n\n/\n/g;
				$nombre= uc $nombre;
				
				
				$recomendacion =~ s/<br>//g;
#				print "hosts ($hosts) \n";
				open (SALIDA_CSV,">>reporte.csv") || die "ERROR: No puedo abrir el reporte.csv\n";			
				print SALIDA_CSV "$contador|$nombre\n";	
				print SALIDA_CSV "||\n";	
				print SALIDA_CSV "$agente_amenaza|$impacto_tecnico|$impacto_negocio\n";	
				print SALIDA_CSV "ANALISIS DE RIESGO\n";	
				print SALIDA_CSV "PROBABILIDAD: $probabilidad|IMPACTO: $impacto|RIESGO: $riesgoInforme\n";	
				print SALIDA_CSV "DETALLES DE LA PRUEBA\n";	
				print SALIDA_CSV "Host afectados:|\"$hosts\"\n";	
				print SALIDA_CSV "\"$detalles\"\n";	
				print SALIDA_CSV "CONTRAMEDIDAS\n";	
				print SALIDA_CSV "\"$recomendacion\"\n";	
				print SALIDA_CSV "REFERENCIAS\n";	
				print SALIDA_CSV "$referencias\n";	
				print SALIDA_CSV "\n";	
				print SALIDA_CSV "\n";								
				close (SALIDA_CSV);
				
				$contador++;#contador vulnerabilidades
		}#if filas    
	} #for 
} # fin for

my $total_vuln_agetic = $total_vul_criticas_agetic + $total_vul_altas_agetic + $total_vul_medias_agetic;
open (SALIDA,">>reporte-resumen.csv") || die "ERROR: No puedo abrir el fichero google.html\n";
	print SALIDA "\n\nTotal hosts analizados:;$total_host_analizados\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico:;$total_host_con_vulnerabilidades\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico (host unicos):;$total_host_con_vulnerabilidades_uniq\n\n";
	
	print SALIDA "Total vulnerabilidades:; $total_vuln_agetic;\n";	
	print SALIDA "Total vulnerabilidades criticas:; $total_vul_criticas_agetic;\n";	
	print SALIDA "Total vulnerabilidades altas:;$total_vul_altas_agetic\n";
	print SALIDA "Total vulnerabilidades medias:;$total_vul_medias_agetic\n";
	print SALIDA "\n";
	
	print SALIDA "Total servicios con vulnerabilidades criticas:; $total_servicios_vuln_criticas_agetic;\n";
	print SALIDA "Total servicios con vulnerabilidades altas:;$total_servicios_vuln_altas_agetic\n";
	print SALIDA "Total servicios con vulnerabilidades medias:;$total_servicios_vuln_medias_agetic\n";	
	print SALIDA "\n";
	print SALIDA "Total vulnerabilidades externas:; $total_vuln_externas;\n";
	print SALIDA "Total vulnerabilidades internas:;$total_vuln_internas\n";
	print SALIDA "\n";
	print SALIDA "Total vulnerabilidades en aplicaciones web:; $aplicacionWeb;\n";
	print SALIDA "Total vulnerabilidades en servidores:; $servidores;\n";
	print SALIDA "Total vulnerabilidades en baseDatos:; $baseDatos;\n";
	print SALIDA "Total vulnerabilidades en correos:; $correos;\n";
	print SALIDA "Total vulnerabilidades en estacionesTrabajo:; $estacionesTrabajo;\n";
	print SALIDA "Total vulnerabilidades en telefoniaIP:; $telefoniaIP;\n";
	print SALIDA "Total vulnerabilidades en sistemaVigilancia:; $sistemaVigilancia;\n";
	print SALIDA "Total vulnerabilidades en dispositivosRed:; $dispositivosRed;\n";
	print SALIDA "Total vulnerabilidades en el personal:; $personal;\n";
	print SALIDA "Total vulnerabilidades otros:; $otros;\n";
	print SALIDA "\n";
	print SALIDA "Total vulnerabilidades Web:; $aplicacionWeb;\n";
	print SALIDA "Total vulnerabilidades password:; $passwordDebil;\n";
	print SALIDA "Total vulnerabilidades de falta parches:; $faltaParches;\n";
	print SALIDA "Total vulnerabilidades error Configuracion:; $errorConfiguracion;\n";
	print SALIDA "\n";
	
#############
	
	print SALIDA "Total vulnerabilidades explotadas:; $total_vuln_agetic;\n";
	print SALIDA "Total pruebas realizadas:;$totalPruebas\n";
	
	print SALIDA "\n\n";
	
	
close (SALIDA);

sub buscarDescripcion
{
	my ($cod) = @_;
	my $descripcion;
	for (my $i=0; $i<$total_vulnerabilidades;$i++)
	{     
		my $current_cod = $vulnerabilidades->{vuln}->[$i]->{cod};     		       
		$descripcion = $vulnerabilidades->{vuln}->[$i]->{nombre}; 
		$codVul = $vulnerabilidades->{vuln}->[$i]->{codVul}; 
		#print "cod $cod current_cod $current_cod \n";
		if ($cod eq $current_cod)
			{last;}	
	}	
	return ($codVul,$descripcion);
}		
