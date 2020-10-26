#!/usr/bin/python3

import pandas as pd
import openpyxl
from openpyxl.styles import PatternFill, Border, Side, Alignment, Protection, Font
from openpyxl.chart import PieChart3D, Reference 
from openpyxl.chart.shapes import GraphicalProperties
from openpyxl.chart.marker import DataPoint
from openpyxl.chart.label import DataLabelList
import math
import itertools
import csv
from lxml import etree

######## #Vulnerabilidades por riesgo ########
#AGETIC
total_vul_criticas = 0
total_vul_altas = 0;
total_vul_medias_agetic = 0;
#####
# PRIVADAS
total_vul_medias_privadas = 0;
total_vul_bajas_privadas = 0;
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

my $totalPruebas = "";


root = etree.parse("/usr/share/lanscanner/vulnerabilidades.xml").getroot()
imguruser  =  root[index].find("username").text




















