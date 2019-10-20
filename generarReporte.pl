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
use utf8;                                        # en este programa hay caracteres escritos en utf8 (línea 9)
use open OUT => ':utf8';                         # la salida del programa será en utf8
use open ':std';                                 # la salida STDOUT (el print()) también será en utf8 
use Encode;
use URI::Escape;
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

my $resultados_externos = `find EXTERNO -iname .resultados.db`;
my $resultados_internos = `find INTERNO -iname .resultados.db`;
my $resultados_todos = $resultados_internos.$resultados_externos;
my @resultados_array = split("\n",$resultados_todos);

my $contador = 1;
my $total_host_analizados = 0;
my $total_host_con_vulnerabilidades = 0;
my $total_host_con_vulnerabilidades_uniq = 0;

######## #Vulnerabilidades por riesgo ########
#AGETIC
my $total_vul_criticas = 0;
my $total_vul_altas = 0;
my $total_vul_medias_agetic = 0;
#####
# PRIVADAS
my $total_vul_medias_privadas = 0;
my $total_vul_bajas_privadas = 0;
######

		
#####################################


######## total host afectados  ########
#AGETIC
my $total_servicios_vuln_criticas_agetic = 0;
my $total_servicios_vuln_altas_agetic = 0;
my $total_servicios_vuln_medias_agetic = 0;
#####

#Entidades privadas
my $total_servicios_vuln_bajas_priv = 0;
my $total_servicios_vuln_medias_priv = 0;
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
	###### Reporte de pruebas por activos CSV ####
	my $aplicacionWeb_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $servidores_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $baseDatos_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $estacionesTrabajo_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $telefoniaIP_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $sistemaVigilancia_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $dispositivosRed_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	my $otros_csv = "IP~Puerto~Código CVE~Prueba realizada\n"; #Impresoras, lectores de huella
	
	my $passwords_csv = "IP~Puerto~Código CVE~Prueba realizada\n";
	#############
	

	###### Reporte de pruebas por activos HTML ####
	my $aplicacionWeb_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $servidores_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $baseDatos_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $estacionesTrabajo_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $telefoniaIP_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $sistemaVigilancia_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $dispositivosRed_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	my $otros_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n"; #Impresoras, lectores de huella
	
	my $passwords_html = "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n";
	#############

	print "Recolectando resultados de: $resultados_db \n";
	my $vector = $resultados_db;
	$vector =~ s/\/.*//s;
	print "Vector: $vector \n";
	
	my $ruta = $resultados_db;	
	$ruta =~ s/\/.resultados.db//g; 
	#INTERNO/usuarios/.resultados.db
	my $segmento = $resultados_db;
	$segmento =~ s/INTERNO\///g;
	$segmento =~ s/EXTERNO\///g;	 
	$segmento =~ s/\/.resultados.db//g; 
		
	my $dsn      = "dbi:SQLite:dbname=$resultados_db";
	my $user     = "";
	my $password = "";
	my $dbh = DBI->connect($dsn, $user, $password, {
		PrintError       => 0,
		RaiseError       => 1,
		AutoCommit       => 1,
		FetchHashKeyName => 'NAME_lc',
		mysql_enable_utf8 => 1
		});		
 
# ...
	my $host_analizados = 0;	
	print "ruta $ruta \n";
	
	######################## Generar reporte de pruebas #####################
	#EXTERNO/senamhi.gob.bo
	# total pruebas por vector
	my $pruebasVulnerabilidadesCant = `ls $ruta/logs/vulnerabilidades | wc -l`;
	my $pruebasPasswordCant = `ls $ruta/logs/cracking | wc -l`;
	$totalPruebas = $totalPruebas + $pruebasVulnerabilidadesCant + $pruebasPasswordCant ;
	######################
	
	my $pruebasVulnerabilidades = `ls $ruta/logs/vulnerabilidades`;	
	my @pruebasVulnerabilidades_array = split("\n",$pruebasVulnerabilidades);
	
	my $pruebasCracking = `ls $ruta/logs/cracking`;
	my @pruebasCracking_array = split("\n",$pruebasCracking);
	my $totalPasswords = `cat $ruta/top.txt | wc -l `;	
	$totalPasswords =~ s/\n//g; 	
	
	if ($vector eq "INTERNO")
	{
		open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
		print SALIDA "\n\n~~PRUEBAS INTERNAS DESDE LA VLAN $segmento\n\n";
		close (SALIDA);	
		
		open (SALIDA,">>reporte-pruebas.html") || die "ERROR: reporte-pruebas.csv\n";
		print SALIDA "<center><h2>PRUEBAS INTERNAS DESDE LA VLAN $segmento</h2></center>";
		close (SALIDA);			
	}
	else
	{
		open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
		print SALIDA "\n\n~~PRUEBAS EXTERNAS del dominio $segmento\n";		
		close (SALIDA);	
		
		open (SALIDA,">>reporte-pruebas.html") || die "ERROR: reporte-pruebas.csv\n";
		print SALIDA "<center><h2>PRUEBAS EXTERNAS del dominio $segmento</h2></center>";
		close (SALIDA);	
	}
		
	foreach ( @pruebasVulnerabilidades_array ) {
		#10.0.0.141_25_openrelay.txt
		my @vulnerabilidad_array = split("_",$_);
		my $ip = @vulnerabilidad_array[0];
		my $port = @vulnerabilidad_array[1];
		my $vuln = @vulnerabilidad_array[2];
		$vuln =~ s/.txt|.html//g; 		
						
		my ($codVul,$vuln_descripcion) =  buscarDescripcion($vuln,$dominio);				
		$codVul="N/A" if ($codVul eq "ninguna"); #Buscar el Codigo CVE o MS
		
		#print "vuln $vuln  ($codVul) \n";
		#Activos de informacion - aplicaciones web																																																																						
		if (($vuln eq "debugHabilitado") || ($vuln eq "listadoDirectorios") || ($vuln eq "divulgacionInformacion") || ($vuln eq "archivosDefecto") || ($vuln eq "archivosPeligrosos") || ( $vuln =~ m/googlehacking/ ) || ($vuln eq "erroresWeb") || ($vuln eq "wpusers") || ($vuln eq "perdidaAutenticacion") || ($vuln eq "exposicionUsuarios") || ($vuln eq "wordpressPass") || ($vuln eq "IPinterna") || ($vuln eq "backupWeb") || ($vuln eq "wordpressPlugin") || ($vuln eq "webshell"))
		{			
			$aplicacionWeb_csv = $aplicacionWeb_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n";			
			$aplicacionWeb_html = $aplicacionWeb_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}
		
		#Activos de informacion - servidores																																																																																																				
		if (($vuln eq "compartidoNFS") || ($vuln eq "enum4linux") || ($vuln eq "shellshock") || ($vuln eq "webdavVulnerable") || ($vuln eq "heartbleed") || ($vuln eq "zimbraXXE") || ($vuln eq "slowloris") || ($vuln eq "CVE15473") || ($vuln eq "directorioLDAP") || ($vuln eq "transferenciaDNS") || ($vuln eq "vrfyHabilitado") || ($vuln eq "openresolver") || ($vuln eq "openrelay") || ($vuln eq "anonymousIPMI") || ($vuln eq "rmiVuln") || ($vuln eq "SSHBypass") || ($vuln eq "intelVuln") || ($vuln eq "HTTPsys") || ($vuln eq "apacheStruts") || ($vuln eq "IISwebdavVulnerable") || ($vuln eq "sambaVuln") || ($vuln eq "jbossVuln") || ($vuln eq "contenidoNoRelacionado") || ($vuln eq "spoof"))
		{			
			$servidores_csv = $servidores_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$servidores_html = $servidores_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;					
		}
		
		#Activos de informacion - baseDatos																																																																																																				
		if (($vuln eq "passwordBD") || ($vuln eq "noSQLDatabases"))
		{			
			$baseDatos_csv = $baseDatos_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$baseDatos_html = $baseDatos_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}
		
		#Activos de informacion - estacionesTrabajo																																																																																																				
		if (($vuln eq "compartidoSMB") || ($vuln eq "ms17010") || ($vuln eq "ms08067") || ($vuln eq "BlueKeep") || ($vuln eq "ms12020") || ($vuln eq "doublepulsar") || ($vuln eq "conficker") || ($vuln eq "VNCbypass") || ($vuln eq "VNCnopass") || ($vuln eq "ransomware") || ($vuln eq "llmnr") )
		{			
			$estacionesTrabajo_csv = $estacionesTrabajo_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$estacionesTrabajo_html = $estacionesTrabajo_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}
		
		#Activos de informacion - sistemaVigilancia																																																																																																				
		if (($vuln eq "vulnDahua") || ($vuln eq "openstreaming") || ($vuln eq "passwordDahua"))
		{			
			$sistemaVigilancia_csv = $sistemaVigilancia_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$sistemaVigilancia_html = $sistemaVigilancia_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}
		
		#Activos de informacion - dispositivosRed																																																																																																				
		if (($vuln eq "passwordMikroTik") || ($vuln eq "winboxVuln") || ($vuln eq "passwordDefecto") || ($vuln eq "snmpCommunity") || ($vuln eq "VPNhandshake") || ($vuln eq "backdoorFabrica") || ($vuln eq "ciscoASAVuln") || ($vuln eq "misfortune") || ($vuln eq "upnpAbierto") || ($vuln eq "poisoning") )
		{			
			$dispositivosRed_csv = $dispositivosRed_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$dispositivosRed_html = $dispositivosRed_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}
		
		#Activos de informacion - Otros																																																																																																				
		if ($vuln eq "ftpAnonymous")
		{			
			$otros_csv = $otros_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;
			$otros_html = $otros_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/vulnerabilidades/$_' target='_blank'>Ver log</a></td></tr>" ;
		}																																																																								
	}
	
	open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
	print SALIDA "~~Pruebas a aplicaciones web \n $aplicacionWeb_csv\n" if ($aplicacionWeb_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a servidores (web, SMB, correo, etc)\n $servidores_csv\n" if ($servidores_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a base de datos \n $baseDatos_csv\n" if ($baseDatos_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a estaciones de trabajo \n $estacionesTrabajo_csv\n" if ($estacionesTrabajo_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a sistemas de vigilancia \n $sistemaVigilancia_csv\n" if ($sistemaVigilancia_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a servicios \n $dispositivosRed_csv\n" if ($dispositivosRed_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	print SALIDA "~~Pruebas a otros dispositivos \n $otros_csv\n" if ($otros_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");
	close (SALIDA);	
	
	
	open (SALIDA,">>reporte-pruebas.html") || die "ERROR: reporte-pruebas.csv\n";
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a aplicaciones web</th></tr>  $aplicacionWeb_html </table><br><br>" if ($aplicacionWeb_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a servidores (web, SMB, correo, etc)</th></tr>  $servidores_html </table><br><br>" if ($servidores_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");	
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a base de datos</th></tr>  $baseDatos_html </table><br><br>" if ($baseDatos_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a estaciones de trabajo</th></tr>  $estacionesTrabajo_html </table><br><br>" if ($estacionesTrabajo_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a sistemas de vigilancia</th></tr>  $sistemaVigilancia_html </table><br><br>" if ($sistemaVigilancia_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a servicios</th></tr>  $dispositivosRed_html </table><br><br>" if ($dispositivosRed_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas a otros dispositivos</th></tr>  $otros_html </table><br><br>" if ($otros_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");
	close (SALIDA);	
	
	############ Passswords ##########
	foreach ( @pruebasCracking_array ) {
		#10.0.0.141_22_passwordDefecto.txt
		my @vulnerabilidad_array = split("_",$_);
		my $ip = @vulnerabilidad_array[0];
		my $port = @vulnerabilidad_array[1];
		my $vuln = @vulnerabilidad_array[2];
		$vuln =~ s/.txt|.html//g; 		
		my ($codVul,$vuln_descripcion) =  buscarDescripcion($vuln,$dominio);				
		$codVul="N/A" if ($codVul eq "ninguna");
		
		$passwords_csv = $passwords_csv."$ip~$port~$codVul~$vuln_descripcion~$vuln\n" ;		
		$passwords_html = $passwords_html."<tr><td>$ip</td><td>$port</td><td>$codVul</td><td>$vuln_descripcion</td><td><a href='$ruta/logs/cracking/$_' target='_blank'>Ver log</a></td></tr>" ;
	}
	open (SALIDA,">>reporte-pruebas.csv") || die "ERROR: reporte-pruebas.csv\n";
	print SALIDA "~~Pruebas de password a servicios y dispositivos (Passwords probados $totalPasswords)\n" if ($passwords_csv ne "IP~Puerto~Código CVE~Prueba realizada\n");		
	close (SALIDA);	
	
	open (SALIDA,">>reporte-pruebas.html") || die "ERROR: reporte-pruebas.html\n";
	print SALIDA "<table border='1'><tr><th colspan='5'>Pruebas de password a servicios y dispositivos (Passwords probados <a href='$ruta/top.txt' target='_blank'>$totalPasswords</a>)</th></tr>  $passwords_html </table><br><br>" if ($passwords_html ne "<tr><th>IP</th><th>Puerto</th><th>Código CVE</th><th>Prueba realizada</th><th>Log</th></tr>\n");	
	close (SALIDA);	
	#############################################################

	
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
	

	########################### Vulnerabilidades por criticidad #################
	
	####################### AGETIC ###################
	#Total vulnerabilidades criticas
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='ms17010' or tipo ='ms08067'  or tipo ='passTomcat' or tipo ='zimbraXXE' or tipo ='doublepulsar' or tipo ='webshell' or tipo ='backdoorFabrica' or tipo ='ransomware' or tipo ='passwordSFI'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_criticas = $row[0];
	$total_vul_criticas = $total_vul_criticas + $vul_criticas;	

	#Total vulnerabilidades altas
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='archivosPeligrosos' or tipo ='mailPass' or tipo ='passwordDefecto' or tipo ='compartidoNFS' or tipo ='BlueKeep' or tipo ='compartidoSMB' or tipo ='passwordHost' or tipo ='logeoRemoto' or tipo ='heartbleed' or tipo ='passwordAdivinado' or tipo ='passwordMikroTik' or tipo ='VNCnopass' or tipo ='VNCbypass' or tipo ='vulnDahua' or tipo ='openrelay' or tipo ='perdidaAutenticacion' or tipo ='spoof' or tipo ='slowloris' or tipo ='wordpressPass' or tipo ='conficker' or tipo ='anonymousIPMI' or tipo ='noSQLDatabases' or tipo ='winboxVuln' or tipo ='rmiVuln' or tipo ='SSHBypass' or tipo ='intelVuln' or tipo ='backupWeb' or tipo ='apacheStruts' or tipo ='webdavVulnerable' or tipo ='IISwebdavVulnerable' or tipo ='shellshock' or tipo ='ciscoASAVuln' or tipo ='sambaVuln' or tipo ='misfortune' or tipo ='jbossVuln' or tipo ='passwordBD' or tipo ='wordpressPlugin'  or tipo ='llmnr' or tipo ='poisoning' ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_altos = $row[0];
	$total_vul_altas = $total_vul_altas + $vul_altos;	

	#Total vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='VPNhandshake' or tipo ='passwordDahua' or tipo ='openstreaming' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='ms12020' or tipo ='debugHabilitado' or tipo ='wpusers' or tipo ='CVE15473' or tipo ='exposicionUsuarios' or tipo ='IPinterna' or tipo ='HTTPsys' or tipo ='ftpAnonymous' or tipo ='vrfyHabilitado' or tipo ='upnpAbierto' or tipo ='contenidoNoRelacionado'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_medios = $row[0];
	$total_vul_medias_agetic = $total_vul_medias_agetic + $vul_medios;	
	####################################################
	
	####################### PRIVADAS ###################
	#Total vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='VPNhandshake' or tipo ='openstreaming'  or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='ACL' or tipo ='openresolver' or tipo ='ms12020' or tipo ='wpusers' or tipo ='exposicionUsuarios' or tipo ='HTTPsys' or tipo ='upnpAbierto'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_medias = $row[0];
	$total_vul_medias_privadas = $total_vul_medias_privadas + $vul_medias;	
	
	#Total vulnerabilidades bajas
	my $sth = $dbh->prepare("select COUNT (DISTINCT TIPO) from VULNERABILIDADES where tipo ='passwordDahua' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity'  or tipo ='listadoDirectorio' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='debugHabilitado' or tipo ='CVE15473' or tipo ='IPinterna' or tipo ='ftpAnonymous' or tipo ='contenidoNoRelacionado'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vul_bajas = $row[0];
	$total_vul_bajas_privadas = $total_vul_bajas_privadas + $vul_bajas;	
	####################################################
	
	
	############################ Servicios afectados por vulnerabilidades  ################# 
	################# AGETIC #####################
	#Servicios afectados por vulnerabilidades criticas
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='ms17010' or tipo ='ms08067' or tipo ='passTomcat'  or tipo ='zimbraXXE' or tipo ='doublepulsar' or tipo ='webshell' or tipo ='backdoorFabrica'  or tipo ='ransomware' or tipo ='passwordSFI'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_criticas = $row[0];
	$total_servicios_vuln_criticas_agetic = $total_servicios_vuln_criticas_agetic + $servicios_vuln_criticas;	

	#Servicios afectados por vulnerabilidades altas
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='archivosPeligrosos' or tipo ='mailPass' or tipo ='passwordDefecto' or tipo ='compartidoNFS' or tipo ='BlueKeep' or tipo ='compartidoSMB' or tipo ='passwordHost' or tipo ='logeoRemoto' or tipo ='heartbleed' or tipo ='adminPassword' or tipo ='rootPassword' or tipo ='ciscoPassword' or tipo ='passwordMikroTik' or tipo ='VNCnopass' or tipo ='VNCbypass' or tipo ='vulnDahua' or tipo ='openrelay' or tipo ='perdidaAutenticacion' or tipo ='spoof' or tipo ='slowloris' or tipo ='wordpressPass' or tipo ='conficker' or tipo ='anonymousIPMI' or tipo ='noSQLDatabases' or tipo ='winboxVuln' or tipo ='rmiVuln' or tipo ='SSHBypass' or tipo ='intelVuln' or tipo ='backupWeb' or tipo ='apacheStruts' or tipo ='webdavVulnerable' or tipo ='IISwebdavVulnerable' or tipo ='shellshock' or tipo ='ciscoASAVuln' or tipo ='sambaVuln' or tipo ='misfortune' or tipo ='jbossVuln' or tipo ='passwordBD' or tipo ='passwordAdivinado' or tipo ='wordpressPlugin' or tipo ='llmnr' or tipo ='poisoning' ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_altos = $row[0];
	$total_servicios_vuln_altas_agetic = $total_servicios_vuln_altas_agetic + $servicios_vuln_altos;	

	#Servicios afectados por vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='VPNhandshake'  or tipo ='passwordDahua' or tipo ='openstreaming' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio'  or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='ms12020' or tipo ='wpusers' or tipo ='CVE15473' or tipo ='exposicionUsuarios' or tipo ='IPinterna' or tipo ='HTTPsys' or tipo ='ftpAnonymous' or tipo ='vrfyHabilitado' or tipo ='upnpAbierto' or tipo ='contenidoNoRelacionado'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_medios = $row[0];
	$total_servicios_vuln_medias_agetic = $total_servicios_vuln_medias_agetic + $servicios_vuln_medios;	
	#################################################
	
	################# PRIVADAS #####################
	#Servicios afectados por vulnerabilidades medias
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='VPNhandshake' or tipo ='openstreaming' or tipo ='directorioLDAP' or tipo ='enum4linux' or tipo ='transferenciaDNS' or tipo ='listadoDirectorio'  or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='ACL' or tipo ='openresolver' or tipo ='ms12020' or tipo ='HTTPsys' or tipo ='upnpAbierto'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_medias = $row[0];
	$total_servicios_vuln_medias_priv = $total_servicios_vuln_medias_priv + $servicios_vuln_medias;	
	
	#Servicios afectados por vulnerabilidades bajas
	my $sth = $dbh->prepare("select COUNT (IP) from VULNERABILIDADES where tipo ='passwordDahua' or tipo ='divulgacionInformacion'  or tipo ='snmpCommunity' or tipo ='listadoDirectorio' or tipo ='enumeracionUsuarios' or tipo ='googlehacking' or tipo ='anonymous' or tipo ='erroresWeb' or tipo ='ACL' or tipo ='archivosDefecto' or tipo ='openresolver' or tipo ='listadoDirectorios' or tipo ='CVE15473' or tipo ='IPinterna' or tipo ='ftpAnonymous' or tipo ='contenidoNoRelacionado'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $servicios_vuln_bajas = $row[0];
	$total_servicios_vuln_bajas_priv = $total_servicios_vuln_bajas_priv + $servicios_vuln_bajas;	
	################################################


	###### Vulnerabilidades por activos ####
	# aplicacionWeb
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='debugHabilitado' or TIPO='listadoDirectorios' or TIPO='archivosDefecto' or TIPO='divulgacionInformacion' or TIPO='archivosPeligrosos' or TIPO='googlehacking' or TIPO='perdidaAutenticacion' or TIPO='erroresWeb' or TIPO='wpusers' or TIPO='exposicionUsuarios'  or TIPO='wordpressPass' or TIPO='IPinterna' or TIPO='webshell'  or TIPO='backupWeb' or TIPO='wordpressPlugin' ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_app = $row[0];
	$aplicacionWeb = $aplicacionWeb + $vuln_app;	
	
	# servidores
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='compartidoNFS' or TIPO='enum4linux' or TIPO='shellshock' or TIPO='webdavVulnerable' or TIPO='heartbleed' or TIPO='zimbraXXE' or TIPO='slowloris' or TIPO='CVE15473' or TIPO='directorioLDAP' or TIPO='transferenciaDNS' or TIPO='vrfyHabilitado' or TIPO='openresolver' or TIPO='openrelay' or TIPO='spoof' or TIPO='openrelay2' or TIPO='anonymousIPMI' or TIPO='rmiVuln' or TIPO='SSHBypass' or TIPO='intelVuln' or TIPO='HTTPsys' or TIPO='apacheStruts' or TIPO='IISwebdavVulnerable' or TIPO='sambaVuln' or TIPO='jbossVuln' or TIPO='passwordSFI' or TIPO='contenidoNoRelacionado'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_serv = $row[0];
	$servidores = $servidores + $vuln_serv;
	
	# base de datos
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordBD' or TIPO='noSQLDatabases' ");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_bd = $row[0];
	$baseDatos = $baseDatos + $vuln_bd;
	
	# estaciones de trabajo
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE  TIPO='compartidoSMB' or TIPO='ms17010' or TIPO='ms08067' or TIPO='BlueKeep' or TIPO='ms12020' or TIPO='doublepulsar' or TIPO='conficker' or TIPO='VNCbypass' or TIPO='VNCnopass' or TIPO='ransomware'  or tipo ='llmnr'");
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
    my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordMikroTik' or TIPO='winboxVuln' or TIPO='passwordDefecto' or TIPO='snmpCommunity' or TIPO='VPNhandshake' or TIPO='backdoorFabrica' or TIPO='ciscoASAVuln' or TIPO='misfortune' or TIPO='upnpAbierto' or TIPO='poisoning'");
	$sth->execute();																					     
	my @row = $sth->fetchrow_array;
	my $vuln_red = $row[0];
	$dispositivosRed = $dispositivosRed + $vuln_red;   
		
    # personal
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordHost' or TIPO='mailPass'");
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
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='passwordMikroTik' or TIPO='passwordAdivinado' or TIPO='passwordHost' or TIPO='passwordDefecto' or TIPO='mailPass' or TIPO='passwordDahua' or TIPO='passwordBD' or TIPO='noSQLDatabases' or TIPO='passwordSFI'");
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_pass = $row[0];	
	$passwordDebil = $passwordDebil + $vuln_pass;
	
	# falta de parches																									     																						    
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='winboxVuln' or TIPO='shellshock' or TIPO='ms17010' or TIPO='ms08067' or TIPO='heartbleed' or TIPO='zimbraXXE' or TIPO='BlueKeep' or TIPO='slowloris' or TIPO='CVE15473' or TIPO='ms12020' or TIPO='vulnDahua' or TIPO='webdavVulnerable' or TIPO='doublepulsar' or TIPO='conficker' or TIPO='SSHBypass' or TIPO='VNCbypass' or TIPO='intelVuln' or TIPO='HTTPsys' or TIPO='apacheStruts' or TIPO='backdoorFabrica' or TIPO='IISwebdavVulnerable' or TIPO='ciscoASAVuln' or TIPO='sambaVuln' or TIPO='misfortune' or TIPO='jbossVuln'" );
	$sth->execute();
	my @row = $sth->fetchrow_array;
	my $vuln_parches = $row[0];	
	$faltaParches = $faltaParches + $vuln_parches;
	
	# Errores de configuracion																		    																								    																   																				   																								     																						    
	my $sth = $dbh->prepare("SELECT count (distinct tipo) FROM VULNERABILIDADES WHERE TIPO='logeoRemoto' or TIPO='compartidoNFS' or TIPO='compartidoSMB' or TIPO='enum4linux' or TIPO='snmpCommunity' or TIPO='directorioLDAP' or TIPO='transferenciaDNS' or TIPO='vrfyHabilitado' or TIPO='ftpAnonymous' or TIPO='openstreaming' or TIPO='VPNhandshake' or TIPO='openresolver' or TIPO='openrelay' or TIPO='openrelay2' or TIPO='spoof' or TIPO='anonymousIPMI' or TIPO='rmiVuln' or TIPO='VNCnopass' or TIPO='upnpAbierto' or TIPO='contenidoNoRelacionado' or TIPO ='llmnr' or TIPO ='poisoning'");
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
		my $codigoVulnerabilidad = $vulnerabilidades->{vuln}->[$i]->{codVul}; 
		my $riesgoAgetic = $vulnerabilidades->{vuln}->[$i]->{riesgoAgetic};        
		my $descripcion = $vulnerabilidades->{vuln}->[$i]->{descripcion}; 
		$descripcion =~ s/SALTOLINEA/<br>/g; 
		
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
		
		$detalles =~ s/DOMINIOENTIDAD/$dominio/g; 						

  
          
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
				$vuln_detalles =~ s/<BLANK>/[vacio]/g;
				$vuln_detalles =~ s/Default RouterOS credentials were not changed. Log in with //g;
				$vuln_detalles =~ s/Login successful!!!//g;
				$vuln_detalles =~ s/\[\+\]/Credenciales:/g;							
				$hosts = $hosts.$ip." ".$vuln_detalles."<br>";
				$filas++;					     
			}			
		}
		
		
		if ($cod eq "passwordSFI")
		{
			while (my @row = $sth->fetchrow_array) {     				
				$ip = $row[0];
				$vuln_detalles = $row[3];	     					
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
				# [FTP] ACCOUNT FOUND: [ftp] Host: 10.0.2.187 User: root Password:  [SUCCESS]
				# ACCOUNT FOUND: [ftp] Host: 10.0.2.187 User: ftp Password:  [SUCCESS]
				
				$ip = $row[0];					
				$vuln_detalles = $row[3];		          
				$vuln_detalles =~ s/Password encontrado://g;				
				$vuln_detalles =~ s/\[FTP\] ACCOUNT FOUND://g;
				$vuln_detalles =~ s/ACCOUNT FOUND://g;
				$vuln_detalles =~ s/[445]//g;	
				$vuln_detalles =~ s/\[SUCCESS\]//g;						
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
				$vuln_detalles =~ s/: \n/:[vacio]/g;
	          	$vuln_detalles =~ s/User/Usuario/g;
	          	$vuln_detalles =~ s/Pass/Contraseña/g; 
				$hosts = $hosts."$ip (WinBox - MikroTik) - $vuln_detalles<br>";
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
		
		if ($cod eq "backdoorFabrica") 
		{
			while (my @row = $sth->fetchrow_array) {     
				$ip = $row[0];
				$port = $row[1];
				$vuln_detalles = $row[3];
				$hosts = $hosts." $ip:$port ($vuln_detalles) <br>";
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
				#ACCOUNT FOUND: [telnet] Host: 192.168.200.19 User: root Password:  [SUCCESS]
				$vuln_detalles =~ s/Password:  \[/Password:\[vacio\] \[/g;
				$vuln_detalles =~ s/ACCOUNT FOUND://g; 
				$vuln_detalles =~ s/User/Usuario/g;
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
				$port = $row[1];
				$vuln_detalles = $row[3];	 	            				
				$vuln_detalles =~ s/\n/<br>\n/g; 				
				$hosts = $hosts."$ip:$port Credenciales: ".$vuln_detalles."<br>";
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
				$hosts = $hosts."Usuarios administradores de wordpress enumerados del host $ip:$port : <br>".$vuln_detalles."<br><br>";
				$filas++;								
			}  						
		}
		
		if (($cod eq "wordpressPlugin"))
		{
			while (my @row = $sth->fetchrow_array) {     		 				
				$ip = $row[0];				
				$port = $row[1];
				$vuln_detalles = $row[3];	 	            				
				$vuln_detalles =~ s/\n/<br>\n/g; 
				$hosts = $hosts." $ip:$port :".$vuln_detalles."<br><br>";
				$filas++;								
			}  						
		}
   

     
		if ( $cod eq "IPinterna" ) 
			{
			while (my @row = $sth->fetchrow_array) {     		 
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				my $vuln_detalles = $row[3];			
				#https-siaco.abc.gob.bo.html: <!--<iframe width=1080 height=560 src=http://192.168.4.35/ frameborder=0 allowfullscreen></iframe>-->				
				
				# Se expone la IP interna por DNS
				if($vuln_detalles =~ /IN    A/m)
				{	 
					$hosts = "El servidor DNS expone las siguientes IPs internas: <br> $vuln_detalles";
					$hosts =~ s/\n/<br>/g;
				}
				else
				# Se expone la IP interna por HTTP(S)
				{
					$vuln_detalles =~ /http(.*?):/;
					my $url_afectada = "http".$1; 				 
					$url_afectada =~ s/.html//g;
					$url_afectada =~ s/-/:\/\//g;
					$vuln_detalles =~ /\/\/(.*?)\//;
					my $ip_interna = $1; 
				
					$hosts = $hosts." La URL $url_afectada expone la IP interna: $ip_interna  <br>";
				}
 


				$filas++;				
				}  						
			}
		
   
		if ( $cod eq "googlehacking" ) 
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
				
		if ($cod eq "listadoDirectorios") 
		{
			while (my @row = $sth->fetchrow_array) 
			{  
				#	Users                                             	READ ONLY
		
				$ip = $row[0];	
				$port = $row[1];	
				$vuln_detalles = $row[3];	
				$vuln_detalles =~ s/\n/<br>/g;
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

				while($vuln_detalles =~ /URL(.*?)\n/g) 
				{$hosts = $hosts." $1 <br>";}												
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
				my $vuln_detalles2 = decode('utf8',$vuln_detalles);	
					
				$vuln_detalles2 =~ s/\\/\\\\/g; 
				#print "vuln_detalles2 $vuln_detalles2 \n";
				
				
				my $usuarios_grupos;				
				if($vuln_detalles2 =~ /Samba/i)
					{$usuarios_grupos = decode('utf8',`echo -e '$vuln_detalles2' | egrep --color=never "Local User" `);}
				else
					{$usuarios_grupos = decode('utf8',`echo -e '$vuln_detalles2' | egrep --color=never "Account:" | cut -d ":" -f5-7`);}
 				
				#print "usuarios_grupos $usuarios_grupos \n";
				#print "usuarios_grupos $usuarios_grupos";				
				#print "enum4linux usuarios_grupos $usuarios_grupos \n";
				$usuarios_grupos =~ s/\n/<br>/g; 
				$hosts = $hosts."IP: ".$ip." usuarios identificados:<br> $usuarios_grupos<br><br>";
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
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				my $url_shellsock = `echo '$vuln_detalles' |grep --color=never "URL"`;	     
				$hosts = $hosts." $url_shellsock <br>";
				$filas++;				
			}       					
		}
		
			
		if ($cod eq "webdavVulnerable") 
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 
					
				$ip = $row[0];				
				$vuln_detalles = $row[3];	
				my @vuln_detalles_array = split(" ",$vuln_detalles);	     
				my $url_webdavVulnerable=@vuln_detalles_array[1];
				#print "url_webdavVulnerable $url_webdavVulnerable \n";
	     
				$hosts = $hosts." $url_webdavVulnerable <br>";
				$filas++;	
			}       						
		}
		
		if ($cod eq "vrfyHabilitado") 
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 				
				$ip = $row[0];	
				$port = $row[1];
				
				my $sth = $dbh->prepare("SELECT VULN FROM VULNERABILIDADES WHERE IP=\"$ip\" AND port=$port AND VULN=\"vrfyHabilitadoEnum\";");
				$sth->execute();
				my @row = $sth->fetchrow_array;
				my $usuarios_vrfy = $row[0];									    
				$hosts = $hosts.":"."$port - Usuarios enumerados:<br> $usuarios_vrfy <br>";
				$filas++;	
			}       						
		}	
		
				
		if ($cod eq "transferenciaDNS") 
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 				
				$ip = $row[0];	
				$port = $row[1];
				$vuln_detalles = $row[3];	
				
				
				$hosts = $hosts."$ip:$port - Archivo de configuración:<br> $vuln_detalles <br><br>";
				$filas++;	
			}       						
		}	
		
		if ($cod eq "noSQLDatabases") 
		{
			while (my @row = $sth->fetchrow_array) 
			{     		 				
				$ip = $row[0];	
				$port = $row[1];
				$vuln_detalles = $row[3];	
				
				
				$hosts = $hosts.":"."$port - Colecciones enumeradas:<br> $vuln_detalles <br>";
				$filas++;	
			}       						
		}	
		
				
		if (($cod eq "archivosPeligrosos") || ($cod eq "archivosDefecto")  || ($cod eq "perdidaAutenticacion") || ($cod eq "webshell") || ($cod eq "backupWeb") || ($cod eq "ciscoASAVuln") || ($cod eq "llmnr") || ($cod eq "poisoning") )
		{  
				while (my @row = $sth->fetchrow_array) {     		 					
				$ip = $row[0];	
				$vuln_detalles = $row[3];	
				$vuln_detalles =~ s/\n/<br>/g; 
				$vuln_detalles =~ s/\(Posible Backdoor\)//g; 
				$vuln_detalles =~ s/\(Mensaje de error\)//g; 
				$vuln_detalles =~ s/TRACE|200//g; 
				#https://sigec.fonadin.gob.bo:443/.git/	, 				    	    
				$hosts = $hosts." $vuln_detalles ";
				$filas++;				
			}       						
		}
   
				
		
		########################################################

		
		# Solo se muestra la IP y el puerto en el campo "host"
		if (($cod eq "ms17010") || ($cod eq "ms08067")  || ($cod eq "vulnDahua") || ($cod eq "passwordDahua")|| ($cod eq "heartbleed") || ($cod eq "directorioLDAP") || ($cod eq "spoof") || ($cod eq "ftpAnonymous") || ($cod eq "openstreaming") || ($cod eq "VPNhandshake")  || ($cod eq "zimbraXXE") || ($cod eq "BlueKeep") || ($cod eq "slowloris") || ($cod eq "openresolver") || ($cod eq "openrelay") || ($cod eq "openrelay2") || ($cod eq "CVE15473") || ($cod eq "ms12020") || ($cod eq "doublepulsar") || ($cod eq "conficker") || ($cod eq "anonymousIPMI")  || ($cod eq "rmiVuln")  || ($cod eq "SSHBypass") || ($cod eq "VNCbypass") || ($cod eq "VNCnopass") || ($cod eq "intelVuln") || ($cod eq "HTTPsys") || ($cod eq "apacheStruts") || ($cod eq "IISwebdavVulnerable") || ($cod eq "sambaVuln") || ($cod eq "misfortune") || ($cod eq "jbossVuln") || ($cod eq "upnpAbierto") || ($cod eq "contenidoNoRelacionado") || ($cod eq "ransomware"))   
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
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Vulnerabilidad:</td><td class='' style='text-align: justify;'>$nombre."; print SALIDA_HTML " ($codigoVulnerabilidad)" if ($codigoVulnerabilidad ne "ninguna"); print SALIDA_HTML "</td>\n";
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
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Recomendación:</td><td class='' style='text-align: justify;'>$recomendacion."; print SALIDA_HTML " Revisar: $referencias" if ($referencias ne "ninguna"); print SALIDA_HTML "</td>\n";
				print SALIDA_HTML "</tr>\n";
				print SALIDA_HTML "<tr>\n";	
				print SALIDA_HTML "<td class='' style='text-align: justify;'>Hosts afectados:</td><td class='' style='text-align: justify;'>$hosts</td>\n";
				print SALIDA_HTML "</tr>\n";										
				print SALIDA_HTML "</table></div>\n<div><br></div> <p></p> \n\n";	
				close (SALIDA_HTML);
						
				# fix para reporte excel		
				$hosts =~ s/<br>/\n/g;
				$hosts =~ s/\n<br>/\n\n/g;
				$hosts =~ s/&nbsp;&nbsp;&nbsp;/\t/g;
				$hosts =~ s/<\/tr><\/table>//g;							
				$hosts =~ s/\n\n\n/\n/g;
				$hosts =~ s/\n\n/\n/g;				
				$hosts =~ s/\t/\n/g;	
				my $nombreMayuscula= uc $nombre;
				$recomendacion =~ s/<br>//g;
				$riesgoInforme =~ s/\n//g;
				$detalles =~ s/SALTOLINEA/\n/g;
#				print "hosts ($hosts) \n";
				open (SALIDA_CSV,">>reporte-sie.csv") || die "ERROR: No puedo abrir el reporte.csv\n";			
				print SALIDA_CSV "$contador~$nombreMayuscula\n";	
				print SALIDA_CSV "~~\n";	
				print SALIDA_CSV "$agente_amenaza~$impacto_tecnico~$impacto_negocio\n";	
				print SALIDA_CSV "ANALISIS DE RIESGO\n";	
				print SALIDA_CSV "PROBABILIDAD: $probabilidad~IMPACTO: $impacto~RIESGO: $riesgoInforme\n";	
				print SALIDA_CSV "DETALLES DE LA PRUEBA\n";	
				print SALIDA_CSV "Host afectados:~\"$hosts\"\n";	
				print SALIDA_CSV "\"$detalles\"\n";	
				print SALIDA_CSV "CONTRAMEDIDAS\n";	
				print SALIDA_CSV "\"$recomendacion\"\n";	
				print SALIDA_CSV "REFERENCIAS\n";	
				print SALIDA_CSV "$referencias\n";	
				print SALIDA_CSV "\n";	
				print SALIDA_CSV "\n";								
				close (SALIDA_CSV);
				
				open (SALIDA_CSV2,">>reporte-bisit.csv") || die "ERROR: No puedo abrir el reporte.csv\n";			
				
				print SALIDA_CSV2 "$nombre\n";	
				print SALIDA_CSV2 "VULNERABILIDAD\n";	
				print SALIDA_CSV2 "$descripcion\n";	
				print SALIDA_CSV2 "FACTOR DE RIESGO\n";	
				print SALIDA_CSV2 "$riesgoInforme ~ CVSS Base Score\n";	
				print SALIDA_CSV2 "PARA CONOCER MAS ACERCA DE LA VULNERABILIDAD, CONSULTE EN INTERNET:\n";	
				print SALIDA_CSV2 "$referencias\n";														
				print SALIDA_CSV2 "EXPLOTACION\n";					
				print SALIDA_CSV2 "\" POSITIVA, $detalles\"\n";
				print SALIDA_CSV2 "HOST AFECTADOS:\n";	
				print SALIDA_CSV2 "\"$hosts\"\n";								
				print SALIDA_CSV2 "CONTRAMEDIDAS\n";	
				print SALIDA_CSV2 "\"$recomendacion\"\n";								
				print SALIDA_CSV2 "\n";								
				close (SALIDA_CSV2);
				
				$contador++;#contador vulnerabilidades
		}#if filas    
	} #for 
} # fin for

my $total_vuln_agetic = $total_vul_criticas + $total_vul_altas + $total_vul_medias_agetic;
open (SALIDA,">>reporte-resumen.csv") || die "ERROR: No puedo abrir el fichero google.html\n";
	print SALIDA "\n\nTotal hosts analizados:;$total_host_analizados\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico:;$total_host_con_vulnerabilidades\n";
	print SALIDA "Vulnerabilidades identificadas descritas en reporte tecnico (host unicos):;$total_host_con_vulnerabilidades_uniq\n\n";
	
	print SALIDA "Estadisticas AGETIC;\n";		
	print SALIDA "Total vulnerabilidades:; $total_vuln_agetic;\n";	
	print SALIDA "Total vulnerabilidades criticas:; $total_vul_criticas;\n";	
	print SALIDA "Total vulnerabilidades altas:;$total_vul_altas\n";
	print SALIDA "Total vulnerabilidades medias:;$total_vul_medias_agetic\n";
	print SALIDA "\n";
	
	print SALIDA "Total servicios con vulnerabilidades criticas:; $total_servicios_vuln_criticas_agetic;\n";
	print SALIDA "Total servicios con vulnerabilidades altas:;$total_servicios_vuln_altas_agetic\n";
	print SALIDA "Total servicios con vulnerabilidades medias:;$total_servicios_vuln_medias_agetic\n";	
	print SALIDA "\n";
	
	print SALIDA "Estadisticas PRIVADAS;\n";	
	print SALIDA "Total vulnerabilidades:; $total_vuln_agetic;\n";	
	print SALIDA "Total vulnerabilidades criticas:; $total_vul_criticas;\n";	
	print SALIDA "Total vulnerabilidades altas:;$total_vul_altas\n";
	print SALIDA "Total vulnerabilidades medias:;$total_vul_medias_privadas\n";
	print SALIDA "Total vulnerabilidades bajas:;$total_vul_bajas_privadas\n";
	print SALIDA "\n";
	
	print SALIDA "Total servicios con vulnerabilidades criticas:; $total_servicios_vuln_criticas_agetic;\n";
	print SALIDA "Total servicios con vulnerabilidades altas:;$total_servicios_vuln_altas_agetic\n";
	print SALIDA "Total servicios con vulnerabilidades medias:;$total_servicios_vuln_bajas_priv\n";	
	print SALIDA "Total servicios con vulnerabilidades bajas:;$total_servicios_vuln_medias_priv\n";	
	
	print SALIDA "\n\n";
	print SALIDA "Total vulnerabilidades externas:; $total_vuln_externas;\n";
	print SALIDA "Total vulnerabilidades internas:;$total_vuln_internas\n";
	print SALIDA "\n";
	print SALIDA "Total vulnerabilidades en aplicaciones web:; $aplicacionWeb;\n";
	print SALIDA "Total vulnerabilidades en servidores:; $servidores;\n";
	print SALIDA "Total vulnerabilidades en baseDatos:; $baseDatos;\n";	
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
	my ($cod,$dominio) = @_;
	my $codVul="ninguna";
	my $descripcion;
	
	switch($cod) {   
   case "googlehacking0"          { $descripcion="Google dork: site:$dominio inurl:add"; }
   case "googlehacking1"          { $descripcion="Google dork: site:$dominio inurl:edit"; }
   case "googlehacking2"          { $descripcion="Google dork: site:$dominio intitle:index.of"; }
   case "googlehacking3"          { $descripcion="Google dork: site:$dominio filetype:sql"; }
   case "googlehacking4"          { $descripcion="Google dork: site:$dominio \"access denied for user\""; }
   case "googlehacking5"          { $descripcion="Google dork: site:$dominio intitle:\"curriculum vitae\""; }
   case "googlehacking6"          { $descripcion="Google dork: site:$dominio passwords|contrasenas|login|contrasena filetype:txt"; }
   case "googlehacking11"          { $descripcion="Google dork: site:trello.com passwords|contrasenas|login|contrasena intext:$DOMINIO"; }
   case "googlehacking13"          { $descripcion="Google dork: site:$dominio \"Undefined index\""; }
   case "googlehacking14"          { $descripcion="Google dork: site:$dominio inurl:storage"; }   
   else              
		{
			for (my $i=0; $i<$total_vulnerabilidades;$i++)
			{     
				my $current_cod = $vulnerabilidades->{vuln}->[$i]->{cod};     		       
				$descripcion = $vulnerabilidades->{vuln}->[$i]->{nombre}; 
				$codVul = $vulnerabilidades->{vuln}->[$i]->{codVul}; 
				#print "cod $cod current_cod $current_cod \n";
				if ($cod eq $current_cod)
					{last;}	
			}#for				
		}#else
  }
  
	
	
	return ($codVul,$descripcion);
}		


sub toAscii{
##see file UTF8vowels.txt
#converts  UTF8 Euro vowels to nearest English equivant  
my $name=$_[0];
$name =~s/\Á/A/g; # 
$name =~s/\É/E/g; # 
$name =~s/\Í/I/g; # 
$name =~s/Ó/O/g; # Oacute
$name =~s/\Ú/U/g; # 
$name =~s/\Ñ/N/g; #

$name =~s/\á/a/g; # 
$name =~s/\é/e/g; # 
$name =~s/\í/i/g; # 
$name =~s/\ó/o/g; # 
$name =~s/\ú/u/g; # 
$name =~s/\ñ/n/g; # 


return $name;
} #endsub store_utf82_encoding

