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



my $archivo_vulnerabilidades = "/usr/share/lanscanner/vulnerabilidades.xml";
my $dominio = $opts{'d'} if $opts{'d'};

 
if (! (-e "resultados.db")){	 
	print "¿Estas ejecutando en el directorio correcto?";
	exit 0;
 }
 

		
################### Load xml ####################
my $xml = new XML::Simple;

# read accounts XML file
$vulnerabilidades = $xml->XMLin($archivo_vulnerabilidades, ForceArray=>['item']);
$total_vulnerabilidades = @{$vulnerabilidades->{vuln}}; 


######################################################

 
my $dsn      = "dbi:SQLite:dbname=resultados.db";
my $user     = "";
my $password = "";
my $dbh = DBI->connect($dsn, $user, $password, {
   PrintError       => 0,
   RaiseError       => 1,
   AutoCommit       => 1,
   FetchHashKeyName => 'NAME_lc',
});
 
# ...
 
my $contador = 1;

my $host_analizados = `wc -l .datos/total-host-vivos.txt | cut -d " " -f1`;

my $sth = $dbh->prepare("SELECT COUNT (DISTINCT IP) FROM VULNERABILIDADES;");
$sth->execute();
my @row = $sth->fetchrow_array;
my $host_con_vulnerabilidades_uniq = $row[0];

my $sth = $dbh->prepare("SELECT COUNT (IP) FROM VULNERABILIDADES;");
$sth->execute();
my @row = $sth->fetchrow_array;
my $host_con_vulnerabilidades = $row[0];

my $riesgos_criticos = 0;
my $riesgos_altos = 0;
my $riesgos_medios = 0;


   
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
	     $vuln_detalles =~ s/ACCOUNT FOUND: \[postgres\]//g; 
	     $vuln_detalles =~ s/\[SUCCESS\]//g;
	     $vuln_detalles =~ s/Host/IP/g;
	     $hosts = $hosts.$vuln_detalles."<br>";
	     $filas++;
	     
         ##### Contabilizar nivel de riesgos ######
         switch ($riesgo) {    	
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
         }
         #############################################
	  }  
   }
   
 
   
   if (($cod eq "googlehacking") || ($cod eq "listadoDirectorio") || ($cod eq "phpmyadminPassword"))
   {
		while (my @row = $sth->fetchrow_array) {     		 
		#	Users                                             	READ ONLY

		 $ip = $row[0];	
	     $vuln_detalles = $row[3];	 	            	     
	     $vuln_detalles =~ s/http/<br>http/g;
	     $hosts = $hosts." $vuln_detalles <br>";
	     $filas++;
         ##### Contabilizar nivel de riesgos ######
          switch ($riesgo) {    	
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
          }
         #############################################
	  }       
   }
   
   if (($cod eq "ms17010") || ($cod eq "ms08067")  || ($cod eq "vulnDahua") || ($cod eq "passwordDahua")|| ($cod eq "enum4linux")|| ($cod eq "heartbleed") || ($cod eq "directorioLDAP") || ($cod eq "spoof") || ($cod eq "transferenciaDNS") || ($cod eq "listadoDirectorio")  || ($cod eq "vrfy") || ($cod eq "anonymous") || ($cod eq "openstreaming") )  
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
			case "Crítico"	{ $riesgos_criticos++ }
			case "Alto"	{ $riesgos_altos++ }
			case "Medio"	{ $riesgos_medios++ }
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
		print SALIDA_HTML "<td class='' style='text-align: justify;'>Nivel de riesgo:</td><td class='' style='text-align: justify;'>$riesgo</td>\n";
		print SALIDA_HTML "</tr>\n";	
		print SALIDA_HTML "<tr>\n";	
		print SALIDA_HTML "<td class='' style='text-align: justify;'>Descripción:</td><td class='' style='text-align: justify;'>$descripcion</td>\n";
		print SALIDA_HTML "</tr>\n";	
		print SALIDA_HTML "<tr>\n";	
		print SALIDA_HTML "<td class='' style='text-align: justify;'>Evidencia:</td><td class='' style='text-align: justify;'> Evidencia $contador</td>\n";
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
   }    
} #for 

open (SALIDA,">>reporte.csv") || die "ERROR: No puedo abrir el fichero google.html\n";
		print SALIDA "\n\nTotal hosts analizados:;$host_analizados";
		print SALIDA "Total hosts con vulnerabilidades:;$host_con_vulnerabilidades\n";
		print SALIDA "Total hosts (unicos) con vulnerabilidades:;$host_con_vulnerabilidades_uniq\n";
		print SALIDA "Total riesgos críticos:; $riesgos_criticos;\n";
		print SALIDA "Total riesgos altos:;$riesgos_altos\n";
		print SALIDA "Total riesgos medios:;$riesgos_medios\n";
		print SALIDA "\n\n";
close (SALIDA);
		
#print "host_analizados ($host_analizados)\n";   
#print "host_con_vulnerabilidades ($host_con_vulnerabilidades)\n";
#print "host_con_vulnerabilidades_uniq ($host_con_vulnerabilidades_uniq)\n";
#print "riesgos_criticos ($riesgos_criticos)\n";
#print "riesgos_altos ($riesgos_altos)\n";
#print "riesgos_medios ($riesgos_medios)\n";
#$dbh->disconnect;

