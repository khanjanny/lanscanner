#!/usr/bin/python3

import pandas as pd
import openpyxl
from openpyxl.styles import PatternFill, Border, Side, Alignment, Protection, Font

thin_border = Border(left=Side(style='thin'),
                     right=Side(style='thin'),
                     top=Side(style='thin'),
                     bottom=Side(style='thin'))

italic24Font = Font(size=24, italic=True, bold=True)
Arial10 = Font(name='Arial', size=10)
Arial11Bold = Font(name='Arial', size=11, bold=True)
Calibri10 = Font(name='Calibri', size=10)

Impact22 = Font(name='Impact', size=22)
Impact36 = Font(name='Impact', size=36)

skyBlueFill = PatternFill(start_color='bdd7ee',
                          end_color='bdd7ee',
                          fill_type='solid')

greyFill = PatternFill(start_color='d9d9d9',
                       end_color='d9d9d9',
                       fill_type='solid')

criticoFill = PatternFill(start_color='FF0000',
                          end_color='FF0000',
                          fill_type='solid')

altoFill = PatternFill(start_color='FFC000',
                       end_color='FFC000',
                       fill_type='solid')

medioFill = PatternFill(start_color='FFFF00',
                        end_color='FFFF00',
                        fill_type='solid')

bajoFill = PatternFill(start_color='00B050',
                       end_color='00B050',
                       fill_type='solid')

vulnerabilidadesDF = pd.read_csv("datos.csv", sep='|', encoding='utf-8')

wb = openpyxl.Workbook()  # Create a blank workbook.
sheet = wb['Sheet']
sheet.title = 'index'  # Change title.

for index, row in vulnerabilidadesDF.iterrows():
    contador = row['contador']
    nombre = row['nombre']
    codVul = row['codVul']
    cvss = row['cvss']
    descripcion = row['descripcion']
    agente_amenaza = row['agente_amenaza']
    impacto_tecnico = row['impacto_tecnico']
    impacto_negocio = row['impacto_negocio']
    probabilidad = row['probabilidad']
    impacto = row['impacto']
    riesgoInforme = str(row['riesgoInforme'])
    detalles = row['detalles']
    recomendacion = row['recomendacion']
    referencias = row['referencias']
    hosts = row['hosts']

    print(f"detalles {len(detalles)}")
    print(f"recomendacion {len(recomendacion)}")
    print(f"hosts {len(hosts)}")

    print(nombre)

    wb.create_sheet()
    sheet = wb['Sheet']

    sheet.column_dimensions['A'].width = 22
    sheet.column_dimensions['B'].width = 33
    sheet.column_dimensions['C'].width = 27

    sheet.title = str(contador)
    if ("CRÍTICO" in riesgoInforme):
        sheet['A1'].fill = criticoFill
        sheet['C5'].fill = criticoFill

    if ("ALTO" in riesgoInforme):
        sheet['A1'].fill = altoFill
        sheet['C5'].fill = altoFill

    if ("MEDIO" in riesgoInforme):
        sheet['A1'].fill = medioFill
        sheet['C5'].fill = medioFill

    if ("BAJO" in riesgoInforme):
        sheet['A1'].fill = bajoFill
        sheet['C5'].fill = bajoFill

    # Titulo
    sheet.merge_cells('B1:C1')
    sheet.row_dimensions[1].height = 59
    sheet['A1'].font = Impact36
    sheet['B1'].font = Impact22
    sheet['A1'].border = thin_border
    sheet['B1'].border = thin_border
    sheet['C1'].border = thin_border

    sheet['A1'].alignment = Alignment(horizontal="center", vertical='center')
    sheet['B1'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)

    sheet['A1'] = str(contador)
    sheet['B1'] = str(nombre).upper()

    # grafico
    sheet.row_dimensions[2].height = 76.5
    img = openpyxl.drawing.image.Image('/usr/share/lanscanner/image.png')
    
    sheet.add_image(img, "D2")
    sheet['A2'].border = thin_border
    sheet['B2'].border = thin_border
    sheet['C2'].border = thin_border
    sheet.merge_cells('A2:C2')

    # texto del grafico
    sheet.row_dimensions[3].height = 53.2
    sheet['A3'].font = Arial10
    sheet['B3'].font = Arial10
    sheet['C3'].font = Arial10

    sheet['A3'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['B3'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['C3'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)

    sheet['A3'].border = thin_border
    sheet['B3'].border = thin_border
    sheet['C3'].border = thin_border

    sheet['A3'] = str(agente_amenaza)
    sheet['B3'] = str(impacto_tecnico)
    sheet['C3'] = str(impacto_negocio)

    # ANALISIS DE RIESGO LABEL
    sheet.merge_cells('A4:C4')
    sheet.row_dimensions[4].height = 29
    sheet['A4'].font = Arial11Bold

    sheet['A4'].border = thin_border
    sheet['B4'].border = thin_border
    sheet['C4'].border = thin_border

    sheet['A4'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['A4'] = "ANALISIS DE RIESGO"
    sheet['A4'].fill = greyFill

    # Riesgos
    sheet.row_dimensions[5].height = 34.5
    sheet['A5'].font = Arial10
    sheet['B5'].font = Arial10
    sheet['C5'].font = Arial11Bold

    sheet['A5'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['B5'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['C5'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)

    sheet['A5'].border = thin_border
    sheet['B5'].border = thin_border
    sheet['C5'].border = thin_border

    sheet['A5'] = "PROBABILIDAD: " + str(probabilidad)
    sheet['B5'] = "IMPACTO:" + str(impacto)
    sheet['C5'] = "RIESGO:" + str(riesgoInforme)

    # DETALLES DE LA PRUEBA LABEL
    sheet.merge_cells('A6:C6')
    sheet.row_dimensions[6].height = 29
    sheet['A6'].font = Arial11Bold

    sheet['A6'].border = thin_border
    sheet['B6'].border = thin_border
    sheet['C6'].border = thin_border

    sheet['A6'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['A6'] = "DETALLES DE LA PRUEBA"
    sheet['A6'].fill = greyFill

    # HOSTS LABEL
    hostHeight1 = 20 + 20 * (len(hosts)//80)
    countNL = hosts.count("SALTOLINEA")
    hostHeight2 = (countNL + 1) * 20
    if hostHeight1 > hostHeight2:
        hostHeight = hostHeight1
    else:
        hostHeight = hostHeight2


    sheet['A7'].font = Arial11Bold
    sheet['B7'].font = Calibri10

    sheet['A7'].border = thin_border
    sheet['B7'].border = thin_border
    sheet['C7'].border = thin_border

    sheet['A7'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['A7'] = "Hosts:"
    sheet.row_dimensions[7].height = hostHeight
    sheet.merge_cells('B7:C7')
    sheet['B7'].alignment = Alignment(horizontal="left", vertical='center', wrap_text=True)
    hosts = hosts.replace("SALTOLINEA", "\n")
    sheet['B7'] = hosts

    # DETALLES DE LA PRUEBA
    cellHeight = 20 + 20 * (len(detalles)//80)
    sheet.row_dimensions[8].height = cellHeight

    sheet.merge_cells('A8:C8')
    sheet.row_dimensions[8].height = cellHeight
    sheet['A8'].font = Arial10

    sheet['A8'].border = thin_border
    sheet['B8'].border = thin_border
    sheet['C8'].border = thin_border

    sheet['A8'].alignment = Alignment(horizontal="justify", vertical='center', wrap_text=True)
    detalles = detalles.replace("SALTOLINEA", "\n")
    sheet['A8'] = detalles

    # CONTRAMEDIDAS - LABEL
    sheet.merge_cells('A9:C9')
    sheet.row_dimensions[9].height = 29
    sheet['A9'].font = Arial11Bold

    sheet['A9'].border = thin_border
    sheet['B9'].border = thin_border
    sheet['C9'].border = thin_border

    sheet['A9'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['A9'] = "CONTRAMEDIDAS"
    sheet['A9'].fill = greyFill

    # CONTRAMEDIDAS
    sheet.merge_cells('A10:C10')
    cellHeight = 20 + 20 * (len(recomendacion)//80)
    
    print(f"cellHeight recomendacion {cellHeight}")
    print(f"len recomendacion {len(recomendacion)}")
    
    sheet.row_dimensions[10].height = cellHeight
    sheet['A10'].font = Arial10

    sheet['A10'].border = thin_border
    sheet['B10'].border = thin_border
    sheet['C10'].border = thin_border

    sheet['A10'].alignment = Alignment(horizontal="justify", vertical='center', wrap_text=True)
    recomendacion = recomendacion.replace("SALTOLINEA", "\n")
    sheet['A10'] = recomendacion

    # REFERENCIAS - LABEL
    sheet.merge_cells('A11:C11')
    sheet.row_dimensions[11].height = 29
    sheet['A11'].font = Arial11Bold

    sheet['A11'].border = thin_border
    sheet['B11'].border = thin_border
    sheet['C11'].border = thin_border

    sheet['A11'].alignment = Alignment(horizontal="center", vertical='center', wrap_text=True)
    sheet['A11'] = "REFERENCIAS"
    sheet['A11'].fill = greyFill

    # REFERENCIAS
    sheet.merge_cells('A12:C12')
    cellHeight = 20 + 20 * (len(referencias)//80)
    sheet.row_dimensions[12].height = cellHeight
    sheet['A12'].font = Arial10

    sheet['A12'].border = thin_border
    sheet['B12'].border = thin_border
    sheet['C12'].border = thin_border

    sheet['A12'].alignment = Alignment(horizontal="justify", vertical='center', wrap_text=True)
    referencias = referencias.replace("SALTOLINEA", "\n")
    referencias = referencias.replace("TAB", "\t")
    sheet['A12'] = referencias
    print("\n")
    wb.save('informe.xlsx')
