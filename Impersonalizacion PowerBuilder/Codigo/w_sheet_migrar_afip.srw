$PBExportHeader$w_sheet_migrar_afip.srw
$PBExportComments$ventana para actualizacion masiva del listado del BCRA
forward
global type w_sheet_migrar_afip from window
end type
type ole_xceedzip from olecustomcontrol within w_sheet_migrar_afip
end type
type dw_paddata from datawindow within w_sheet_migrar_afip
end type
type st_dia from statictext within w_sheet_migrar_afip
end type
type em_dia from editmask within w_sheet_migrar_afip
end type
type st_proceso from statictext within w_sheet_migrar_afip
end type
type st_path from statictext within w_sheet_migrar_afip
end type
type sle_path from singlelineedit within w_sheet_migrar_afip
end type
type st_anio from statictext within w_sheet_migrar_afip
end type
type st_mes from statictext within w_sheet_migrar_afip
end type
type em_anio from editmask within w_sheet_migrar_afip
end type
type em_mes from editmask within w_sheet_migrar_afip
end type
type st_1 from statictext within w_sheet_migrar_afip
end type
type sle_errores from singlelineedit within w_sheet_migrar_afip
end type
type st_5 from statictext within w_sheet_migrar_afip
end type
type mle_import from multilineedit within w_sheet_migrar_afip
end type
type st_4 from statictext within w_sheet_migrar_afip
end type
type cb_cancelar_proceso from commandbutton within w_sheet_migrar_afip
end type
type st_3 from statictext within w_sheet_migrar_afip
end type
type mle_status from multilineedit within w_sheet_migrar_afip
end type
type luo_progress from uo_progress within w_sheet_migrar_afip
end type
type cb_procesar from commandbutton within w_sheet_migrar_afip
end type
type st_2 from statictext within w_sheet_migrar_afip
end type
type cb_buscar from commandbutton within w_sheet_migrar_afip
end type
type sle_archivo from singlelineedit within w_sheet_migrar_afip
end type
type gb_1 from groupbox within w_sheet_migrar_afip
end type
type em_regs from editmask within w_sheet_migrar_afip
end type
type gb_2 from groupbox within w_sheet_migrar_afip
end type
end forward

global type w_sheet_migrar_afip from window
integer x = 823
integer y = 360
integer width = 3630
integer height = 2180
boolean titlebar = true
string title = "Generación de los archivos AFIP"
boolean controlmenu = true
boolean minbox = true
boolean maxbox = true
boolean resizable = true
long backcolor = 79741120
event ue_buscar ( )
event ue_procesar ( )
event ue_imprimir ( )
event ue_guardar ( )
event ue_procesar_pack ( )
event ue_test_pack ( )
event ue_procesar_old ( )
event ue_test_copiaimpersonalizada ( )
event ue_test_copiaimpersonalizada2 ( )
ole_xceedzip ole_xceedzip
dw_paddata dw_paddata
st_dia st_dia
em_dia em_dia
st_proceso st_proceso
st_path st_path
sle_path sle_path
st_anio st_anio
st_mes st_mes
em_anio em_anio
em_mes em_mes
st_1 st_1
sle_errores sle_errores
st_5 st_5
mle_import mle_import
st_4 st_4
cb_cancelar_proceso cb_cancelar_proceso
st_3 st_3
mle_status mle_status
luo_progress luo_progress
cb_procesar cb_procesar
st_2 st_2
cb_buscar cb_buscar
sle_archivo sle_archivo
gb_1 gb_1
em_regs em_regs
gb_2 gb_2
end type
global w_sheet_migrar_afip w_sheet_migrar_afip

type prototypes

end prototypes

type variables
Boolean ib_ret
Boolean ib_cancelar = True

// Año y Mes de Proceso
string is_anio_mes_dia

//recurso compartido en el Servidor
string is_recursocomp

//directorio de trabajo
string is_temppath

//directorio de archivo de datos
string is_filepath

//archivo a procesar
string is_filename

//inicio status
time it_inicio_status

//log importaciones
string is_log_import
string	is_proceso

end variables

forward prototypes
private subroutine wf_status (string ls_texto, string ls_status, long ll_rcount)
public function integer wf_borrar_archivo (string ls_archivo)
public function integer wf_copiar_a_temp (string ls_desde, string ls_archivo_desde, string ls_hasta, string ls_archivo_hasta)
public function integer wf_validar_parametros ()
public function integer wf_compactar_tabladbf (string as_nombretabla)
end prototypes

event ue_buscar;Integer		li_ret
String		ls_caminoarch, ls_nombrearch

ls_caminoarch = "d:\"
ls_nombrearch = "cendeu"

IF is_proceso = 'C' THEN
	li_ret = GetFileOpenName("Seleccion de archivo : ", ls_caminoarch, ls_nombrearch, &
									"exe", "Aplicación de Interfáz (padfyj.zip), padfyj.zip")
ELSEIF is_proceso = 'S' THEN
	li_ret = GetFileOpenName("Seleccion de archivo : ", ls_caminoarch, ls_nombrearch, &
									"exe", "Aplicación de Interfáz (20*.zip), 20*.zip")
END IF
IF li_ret = 1 THEN 
	sle_archivo.text = ls_caminoarch
	is_filename=ls_nombrearch
	is_filepath = Left(ls_caminoarch, pos(ls_caminoarch, ls_nombrearch) - 1)
End If

end event

event ue_procesar();/*********************************************************************************************/
// Este evento dispara el proceso de carga del archivo de interfáz tanto semanal como cuatrimestral de la AFIP
// El cuatrimestral no se proformatea, solo se deszipea y se envian los .txt a MAinframe para que se procesen allí
// tabla paddata.dbf mantiene informacion de los procesos ejecutados del padron de AFIP
// tabla padnove.dbf mantiene informacion de los registros de novedades (Altas y Bajas) 
// de los procesos del padron de AFIP. Acumula Semanales hasta que llega un Cuatrimestral
/*********************************************************************************************/

uo_syncproc luo_sync
long ll_regs, ll_total_regs, ll_tot_arch_deszip
integer li_ret, i, li_paso
string ls_err_str, ls_tot_archivos_cuatrimestral

pointer oldpointer
string ls_temppath_trabajo

string ls_sololeer, ls_linea,ls_path_Log,ls_path, ls_anio_mes_dia, ls_ejecutar
long	li_filenum, li_filenum_log,li_filenum_txt, li_filenum_data, ll_filas

string  ls_marca, ls_denomina,ls_identifica, ls_fecha,ls_fecha_max, ls_null
long ll_altas, ll_bajas
string ls_altas, ls_bajas
boolean 	lb_eof

ib_cancelar=false

mle_status.text=""
mle_import.text=""
is_log_import=""
luo_progress.SetValue(0)
sle_errores.text = "0"
em_regs.text="0"

if MessageBox(this.Title, "Está Ud seguro de Procesar?",Exclamation!,YesNo!) = 2 then Return


oldpointer = setpointer (HourGlass!)
is_recursocomp = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "RecursoCompartido","")
//Para cuando utilizao un recurso compartido con el path completo
//is_temppath = "\\" + gs_hostname + "\" + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "Path","")
//ls_temppath_trabajo = "\\" + gs_hostname + "\"  + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathTrabajo","")
//ls_path_Log = "\\" + gs_hostname + "\" + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathLog","")

//Para cuando en vez del recurso compartido utilizo directamente un path a una carpeta
is_temppath = is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "Path","")
ls_temppath_trabajo =  is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathTrabajo","")
ls_path_Log =  is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathLog","")

li_filenum_log = FileOpen(ls_path_Log + "log.txt", LINEmODE!, Write!, LockWrite!, Append!)
if li_filenum_log < 1 then
	MessageBox("Error", "No se puede abrir el archivo log.txt para escribir. Cierre todas las ventanas e intente nuevamente.")
	Return
end if

FileWrite(li_filenum_log, "***********************************")
if is_proceso = 'C' then 
	FileWrite(li_filenum_log, "Comenzando proceso AFIP Cuatrimestral - usuario: "+gs_username+" ("+string(datetime(today(),now()))+")")
elseif is_proceso = 'S' then 
	FileWrite(li_filenum_log, "Comenzando proceso AFIP Semanal - usuario: "+gs_username+" ("+string(datetime(today(),now()))+")")
end if

wf_status("Validando parámetros ...", "I", 0)
FileWrite(li_filenum_log, "Validando parámetros ...("+string(datetime(today(),now()))+")")
if wf_validar_parametros() < 0 then 
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	return
end if
wf_status("Validando parámetros ...OK", "E", 0)
FileWrite(li_filenum_log, "Validando parámetros ...OK("+string(datetime(today(),now()))+")")
ls_path = sle_archivo.Text
ls_anio_mes_dia = is_anio_mes_dia 

//Antes que nada, borrar si existieran los archivos que van a ser descompactados.
wf_status("Borrando archivos Temporarios ...", "I", 0)
FileWrite(li_filenum_log, "Borrando archivos Temporarios...("+string(datetime(today(),now()))+")")
//el siguiente lo genera directamente en Mainframe
wf_borrar_archivo(is_temppath + "paddata.txt")
wf_borrar_archivo(is_temppath + "padnove.txt")
if is_proceso = 'C' then
	ls_path = mid(ls_path,1,Pos (ls_path, "padfyj.zip" , 1 )-1)
	i=0
	do while FileExists(ls_temppath_trabajo+"padfyj_"+string(i)+".txt")
		wf_borrar_archivo(ls_temppath_trabajo+"padfyj_"+string(i)+".txt")
		i++
	loop
//	for i=0 to 9
//		wf_borrar_archivo(ls_temppath_trabajo+"padfyj_"+string(i)+".txt")
//	next
	wf_borrar_archivo(is_temppath + "afipct")
elseif is_proceso = 'S' then
	ls_path = mid(ls_path,1,Pos ( ls_path, ls_anio_mes_dia+".zip" , 1 )-1)
	wf_borrar_archivo(ls_temppath_trabajo+ls_anio_mes_dia+".zip")
	wf_borrar_archivo(ls_temppath_trabajo+"afipst")
end if
wf_status("Borrando archivos Temporarios OK.", "E",0)
FileWrite(li_filenum_log, "Borrando archivos Temporarios OK ("+string(datetime(today(),now()))+")")


luo_sync = CREATE uo_syncproc
luo_sync.of_setwindow('hide')

/******************** Compactar la el archivo de la tabla padnove.dbf *******************/
FileWrite(li_filenum_log, "Compactando el archivo de la tabla padnove [pack padnove] " + sqlca.sqlerrtext + " (" + string(datetime(today(),now())) + ")")
if wf_compactar_tabladbf("padnove") <> 0 then
	MessageBox("Error", "pack padnove "+sqlca.sqlerrtext+" Proceso Abortado.")
	RollBack USING sqlca;
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
else
	Commit USING sqlca;
	wf_status("Pack padnove OK", "I", 0)
	FileWrite(li_filenum_log, "Pack padnove OK. ("+string(datetime(today(),now()))+")")
end if	
/****************************************************************************************/

SELECT max(paddata.fecha)
INto :ls_fecha_max 
FROM paddata  
WHERE paddata.marca = 'P' USING sqlca  ;

if sqlca.sqlcode = -1 then
	RollBack USING sqlca;
	FileWrite(li_filenum_log, "Count(*) sobre padnove. (" + string(datetime(today(),now())) + ")")
	MessageBox("Error", "count(*) sobre padnove. Proceso Abortado.")
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if	
if not isnull(ls_fecha_max) and ls_fecha_max > ls_anio_mes_dia then
	MessageBox(this.Title, "Ya existen filas con fecha posterior al proceso. Proceso Cancelado!!!.")
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Ya existen filas con fecha posterior al proceso!!!. (" + string(datetime(today(),now())) + ")")
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if	

	
if is_proceso = 'C' then
//	ls_path = mid(ls_path,1,Pos ( ls_path, "padfyj.zip" , 1 )-1)
	// Borro todos los registros de padnove !!!
	DELETE FROM padnove  USING sqlca  ;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "DELETE sobre padnove....C" + sqlca.sqlerrtext + " (" +string(datetime(today(),now())) + ")")
		RollBack USING sqlca;
		wf_status("Proceso abortado.", "E",0)
		MessageBox("Error", "DELETE sobre padnove....C"+sqlca.sqlerrtext+" Proceso Abortado.")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
		wf_status("Borro todos los registros de padnove !!!...OK", "I", 0)
		FileWrite(li_filenum_log, "Borro todos los registros de padnove !!! ("+string(datetime(today(),now()))+")")
	end if	
	
	SetNull(ls_null)
	INSERT INto padnove  
		( fecha,marca,identifica,denomina )  
	VALUES ( :ls_anio_mes_dia, :ls_null,:ls_null,:ls_null )  
	USING sqlca;
	if sqlca.sqlcode <> 0 then
		RollBack USING sqlca;
		FileWrite(li_filenum_log, "Insert sobre padnove-C. " + sqlca.sqlerrtext + " (" + string(datetime(today(),now())) + ")")
		wf_status("Proceso abortado.", "E",0)
		MessageBox("Error", "Insert sobre padnove-C. "+sqlca.sqlerrtext+" Proceso Abortado.")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if

	/******************************************************/
	/* Copiar archivo padfyj.zip a directorio de trabajo  \Data                         */
	/******************************************************/
	if FileExists(ls_path+"padfyj.zip") then 		
		wf_status("Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo ...", "I", 0)
		wf_status("Este proceso puede demorar unos minutos...", "I", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo ...("+string(datetime(today(),now()))+")")
		if wf_copiar_a_temp(ls_path,"padfyj.zip",ls_temppath_trabajo,"padfyj.zip") < 0 then 	
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Error copiando archivo Copiando archivo " + ls_path+"padfyj.zip a directorio de trabajo. ("+string(datetime(today(),now()))+")")
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			return
		end if
		wf_status("Copiando archivo padfyj.zip a directorio de trabajo OK.", "F", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo OK. ("+string(datetime(today(),now()))+")")
	end if
	/*******************************************************/
	
	/****************************************************************************/
	/* Descomprimir archivo padfyj.zip Cuatrimestral en directorio de trabajo  \Data                                    */
	/****************************************************************************/
	wf_status("Descomprimiendo archivos padfyj.zip en directorio de trabajo.", "I", 0)
	wf_status("Este proceso puede demorar varios minutos...", "I", 0)
	
	//hago visible la barra de progreso y seteo el paso a 1 (x default es 10)
	luo_progress.visible = true
	luo_progress.setstep(1)
	// reseteo y fijo el limite superior a la barra de progreso
	luo_progress.SetRange(0, 100)
	luo_progress.SetValue(0)
	
	st_4.text = "Archivo:"
	st_1.text = "de:"
	ole_xceedzip.object.ZipFilename = ls_temppath_trabajo + "padfyj.zip" 
	ole_xceedzip.object.FilesToProcess = "" 
	ole_xceedzip.object.UnzipToFolder = ls_temppath_trabajo
	ole_xceedzip.object.IgnoredExtraHeaders = 4	//xehSecurityDescriptor - Store/Retrieve the Windows NT file security information header.
	//oldpointer = SetPointer(HourGlass!)
	li_ret = ole_xceedzip.object.Unzip()
	//setpointer(oldpointer)
	st_4.text= "Leídos:"
	st_1.text = "Archivo:"
	
//	if FileExists(ls_temppath_trabajo+"padfyj.zip") then 		
//		ls_ejecutar = mid(ls_temppath_trabajo,1,pos(ls_temppath_trabajo,"Data")-1)+"\exe\pkunzip -o " + ls_temppath_trabajo + "padfyj.zip" + + " " + ls_temppath_trabajo
//		luo_sync.of_RunAndWait(ls_ejecutar)
//		if not FileExists(ls_temppath_trabajo+"padfyj.zip") then
//			FileWrite(li_filenum_log, "Error descompactando "+ls_temppath_trabajo+"padfyj.zip .Falta de espacio en disco. Proceso Abortado. ("+string(datetime(today(),now()))+")")
//			wf_status("Error descompactando - Proceso abortado.", "E",0)
//			MessageBox("Error", "Error descompactando "+ls_temppath_trabajo+"padfyj.zip .Falta de espacio en disco. Proceso Abortado.")
//			wf_status("Proceso abortado.", "E",0)
//			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
//			FileClose(li_filenum_log)
//			setpointer (oldpointer)			
//			Return
//		end if	
//	end if

	//guardo en variable la cantidad de archivos que venian en el zip
	ll_tot_arch_deszip = Long(em_regs.text)
	wf_status("Descomprimiendo archivos padfyj.zip en directorio de trabajo OK.", "F", 0)

	
	/****************************************************************************/
elseif is_proceso = 'S' then
    SELECT Count(*)
    INto :ll_filas
    FROM padnove  
   WHERE padnove.fecha = :ls_anio_mes_dia USING sqlca  ;
	if sqlca.sqlcode = -1 then
		FileWrite(li_filenum_log, "Error haciendo un Count(*) sobre padnove. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "count(*) sobre padnove. Proceso Abortado."+sqlca.sqlerrtext)
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	if ll_filas > 0 then
		if MessageBox(this.Title, "Ya existen filas con ésa fecha!!!, Desea Reprocesar?",Exclamation!,YesNo!) = 2 then 
			FileWrite(li_filenum_log, "Ya existen filas con ésa fecha. ("+string(datetime(today(),now()))+")")
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			wf_status("Proceso abortado.", "E",0)
			setpointer (oldpointer)
			Return
		else
			// Borro todos los registros de ésa semana de paddata !!!
			DELETE FROM paddata WHERE paddata.marca = 'S' and paddata.fecha = :ls_anio_mes_dia  USING sqlca  ;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "DELETE sobre paddata."+sqlca.sqlerrtext+" Proceso Abortado. ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "DELETE sobre paddata."+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				Commit USING sqlca;
				wf_status("Reproceso - Se borraron previamente los registros....paddata", "I", 0)
				FileWrite(li_filenum_log, "Reproceso-Se borraron previamente los registros paddata. ("+string(datetime(today(),now()))+")")
			end if	
			// Borro todos los registros B !!!
			DELETE FROM padnove  WHERE padnove.fecha = :ls_anio_mes_dia USING sqlca  ;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "DELETE sobre padnove " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				MessageBox("Error", "DELETE sobre padnove"+sqlca.sqlerrtext+" Proceso Abortado.")
				Return
			else
				Commit USING sqlca;
				wf_status("Reproceso-Se borraron previamente los registros....padnove", "I", 0)
				FileWrite(li_filenum_log, "Reproceso-Se borraron previamente los registros....padnove. ("+string(datetime(today(),now()))+")")
			end if	
		end if
	end if
	
	/****************************************************************/
	/* Copiar archivo semanal yyyymmdd.zip a directorio de trabajo  */
	/****************************************************************/
	//	ls_path = mid(ls_path,1,Pos ( ls_path, ls_anio_mes_dia+".zip" , 1 )-1)
	wf_status("Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo ...("+string(datetime(today(),now()))+")")

	if wf_copiar_a_temp(ls_path,ls_anio_mes_dia+".zip",ls_temppath_trabajo,ls_anio_mes_dia+".zip") < 0 then 	
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		return
	end if
	wf_status("Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo OK.", "F", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo OK. ("+string(datetime(today(),now()))+")")
	
	/****************************************************************/
	
	/****************************************************************************/
	/* Descomprimir archivo yyyymmdd.zip semanal en directorio de trabajo   */
	/****************************************************************************/
	wf_status("Descomprimiendo archivo "+ ls_anio_mes_dia +".zip en directorio de trabajo.", "I", 0)
	wf_status("Este proceso puede demorar varios minutos...", "I", 0)
	
	//hago visible la barra de progreso y seteo el paso a 1 (x default es 10)
	luo_progress.visible = true
	luo_progress.setstep(1)
	// reseteo y fijo el limite superior a la barra de progreso
	luo_progress.SetRange(0, 100)
	luo_progress.SetValue(0)
	
	st_4.text= "Archivo:"
	st_1.text = "de:"
	ole_xceedzip.object.ZipFilename = ls_temppath_trabajo + ls_anio_mes_dia+".zip"
	ole_xceedzip.object.FilesToProcess = "" 
	ole_xceedzip.object.UnzipToFolder = ls_temppath_trabajo
	ole_xceedzip.object.IgnoredExtraHeaders = 4	//xehSecurityDescriptor - Store/Retrieve the Windows NT file security information header.
	//oldpointer = SetPointer(HourGlass!)
	li_ret = ole_xceedzip.object.Unzip()
	//setpointer(oldpointer)
	st_4.text= "Leídos:"
	st_1.text = "Errores:"
	//ls_ejecutar = mid(ls_temppath_trabajo,1,pos(ls_temppath_trabajo,"Data")-1)+"\exe\pkunzip -o " + ls_temppath_trabajo + ls_anio_mes_dia+".zip" + " " + ls_temppath_trabajo
	//luo_sync.of_RunAndWait(ls_ejecutar)
	wf_status("Descomprimiendo archivo "+ ls_anio_mes_dia +".zip en directorio de trabajo OK.", "F", 0)

	/****************************************************************************/

	// 1ro leer el archivo detalle.txt
	ls_sololeer = ls_temppath_trabajo + "detalle.txt"
	if not FileExists(ls_temppath_trabajo+"detalle.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +" detalle.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo " + ls_temppath_trabajo + " detalle.txt. ")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo detalle.txt para Leer. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo detalle.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	if FileRead(li_filenum,ls_linea) > 0 then // 2006-08-20 Altas 157467
		ls_fecha = mid(ls_linea,1,4)+mid(ls_linea,6,2)+mid(ls_linea,9,2)
		ll_altas = long(mid(ls_linea,18,8))
		if ls_fecha <> ls_anio_mes_dia then
			FileWrite(li_filenum_log, "La Fecha informada no concuerda con los archivos. ("+string(datetime(today(),now()))+")")
			MessageBox(this.title,"La Fecha informada no concuerda con los archivos!")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		else
			FileWrite(li_filenum_log, "Archivo Detalles, Altas: "+string(ll_altas)+" ("+string(datetime(today(),now()))+")")
		end if	
	end if
	if FileRead(li_filenum,ls_linea) > 0 then //	2006-08-20 Bajas 158286
		ls_fecha = mid(ls_linea,1,4)+mid(ls_linea,6,2)+mid(ls_linea,9,2)
		ll_bajas = long(mid(ls_linea,18,8))
		if ls_fecha <> ls_anio_mes_dia then
			FileWrite(li_filenum_log, "La Fecha informada no concuerda con los archivos. ("+string(datetime(today(),now()))+")")
			MessageBox(this.title,"La Fecha informada no concuerda con los archivos!")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		else
			FileWrite(li_filenum_log, "Archivo Detalles, Bajas: "+string(ll_bajas)+" ("+string(datetime(today(),now()))+")")
		end if	
	end if
	FileClose(li_filenum)
	// 2ro leo novedades.txt
	lb_eof = FALSE
	ls_sololeer = ls_temppath_trabajo + "novedades.txt"
	if not FileExists(ls_temppath_trabajo+"novedades.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +"novedades.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo "+ls_temppath_trabajo +"novedades.txt. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo novedades.txt para Leer. ("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo novedades.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	ls_marca = 'N'
	ll_filas = 0
	sle_errores.Text = "0"
	if ll_altas > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_altas / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_altas)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	wf_status("Insertando Novedades-Altas....", "I", 0)
	
	do
		if FileRead(li_filenum,ls_linea) > 0 then
			ls_identifica = mid(ls_linea,1,11)
			ls_denomina = mid(ls_linea,12,55)
		  	INSERT INto padnove  
         	( fecha,marca,identifica,denomina )  
  			VALUES ( :ls_anio_mes_dia, :ls_marca,:ls_identifica,
			  :ls_denomina )  
  			USING sqlca;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "Insert sobre padnove-N. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "Insert sobre padnove-N. "+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				yield()
				ll_filas++
				em_regs.Text = string(ll_filas)
				luo_progress.SetValue(ll_filas / li_paso)
			end if	
		else
			lb_eof = TRUE
		end if
	loop until lb_eof
	luo_progress.SetValue(32767)
	
	if ll_filas <> ll_altas then
		FileWrite(li_filenum_log, "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-altas. ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-altas. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileWrite(li_filenum_log, "Insert en Archivo Novedades, Altas: "+string(ll_altas)+" ("+string(datetime(today(),now()))+")")
		Commit USING sqlca;
	end if
	wf_status("Insertando Novedades-Altas: "+string(ll_altas)+"....OK", "E", 0)
	FileClose(li_filenum)
	// 3ro leo bajas.txt
	lb_eof = FALSE
	ls_sololeer = ls_temppath_trabajo + "bajas.txt"
	if not FileExists(ls_temppath_trabajo+"bajas.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +"bajas.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo "+ls_temppath_trabajo +"bajas.txt. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo bajas.txt para Leer. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo bajas.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	ls_marca = 'B'
	SetNull(ls_denomina)
	ll_filas = 0
	if ll_bajas > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_bajas / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_bajas)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	wf_status("Insertando Novedades-Bajas....", "I", 0)
	do
		if FileRead(li_filenum,ls_linea) > 0 then
			ls_identifica = mid(ls_linea,1,11)
		  	INSERT INto padnove  
         	( fecha,marca,identifica,denomina )  
  			VALUES ( :ls_anio_mes_dia, :ls_marca,:ls_identifica,
			  :ls_denomina )  
  			USING sqlca;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "Insert sobre padnove-B. "+sqlca.sqlerrtext+" ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "Insert sobre padnove-B. "+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				yield()
				ll_filas++
				em_regs.Text = string(ll_filas)
				luo_progress.SetValue(ll_filas / li_paso)
			end if	
		else
			lb_eof = TRUE
		end if
	loop until lb_eof
	luo_progress.SetValue(32767)
	
	if ll_filas <> ll_bajas then
		FileWrite(li_filenum_log, "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-bajas. ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-bajas. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileWrite(li_filenum_log, "Insert en Archivo Novedades, Bajas: "+string(ll_bajas)+" ("+string(datetime(today(),now()))+")")
		Commit USING sqlca;
		if sqlca.sqlcode <> 0 then
			FileWrite(li_filenum_log, "Error en Commit. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
			RollBack USING sqlca;
			MessageBox("Error", "Commit. "+sqlca.sqlerrtext+" Proceso Abortado.")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		end if
	end if
	wf_status("Insertando Novedades-Bajas: "+string(ll_bajas)+"....OK", "E", 0)
	FileClose(li_filenum)
end if
DESTROY luo_sync


/***********************************************************/
/*  ARMADO DE ARCHIVOS TXT DESDE EL DIRECtoRIO DE TRABAJO  */
/***********************************************************/

wf_borrar_archivo(is_temppath+"padnove.txt")
wf_status("Generando archivo padnove.txt en directorio de trabajo ...", "I", 0)
//FileWrite(li_filenum_log, "Generando archivo padnove.txt en directorio de trabajo ...("+string(datetime(today(),now()))+")")

li_filenum_data = FileOpen(is_temppath + "padnove.txt", LINEmODE!, Write!, LockWrite!, Replace!)
if li_filenum_data < 1 then
	MessageBox("Error", "No se puede abrir el archivo padnove.txt para escribir. Avise a Sistemas.")
	FileWrite(li_filenum_log, "No se puede abrir el archivo padnove.txt para escribir.")
	wf_status("Proceso abortado.", "E", 0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if

sle_errores.Text = "0"

if is_proceso = 'C' then
	/****************************************************************************************************************/	
	/*El archivo cuatrimestral con novedades no se procesa mas en Plataforma baja, se pasan a mainframe directamente los archivos descomprimidos del .zip */	
	/****************************************************************************************************************/	
	// el codigo de procesamiento del cuatrimestral puede verse en ue_procesar_old()
	/***************************************************************************************************/	
elseif is_proceso = 'S' then
	//Ahora Completo PADNOVE en Access y PADNOVE.TXT
	SELECT Count(*)
   	INto :ll_total_regs
  	FROM padnove  
  	USING sqlca  ;
	if sqlca.sqlcode = -1 then
		FileWrite(li_filenum_log, "Error haciendo un Count(*) sobre padnove. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "count(*) sobre padnove. Proceso Abortado."+sqlca.sqlerrtext)
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
		
	DECLARE cur_padnove CURSOR for  
  	SELECT padnove.fecha,padnove.marca,padnove.identifica,padnove.denomina 
    FROM padnove 
	 ORDER BY padnove.fecha,padnove.marca,padnove.identifica using (sqlca) ;
	
	ll_regs = 0
	if ll_total_regs > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_total_regs / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_total_regs)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	
	OPEN cur_padnove;
	if sqlca.sqlcode >= 0 then
		FETCH cur_padnove INto :ls_anio_mes_dia, :ls_marca,:ls_identifica, :ls_denomina;
		do while sqlca.sqlcode = 0
			if IsNull(ls_marca) then ls_marca=''
			if IsNull(ls_identifica) then ls_identifica=''
			if IsNull(ls_denomina) then ls_denomina=''
			FileWrite(li_filenum_data, ls_anio_mes_dia+ls_marca+ls_identifica+ls_denomina)
			yield()
			ll_regs ++
			luo_progress.SetValue(ll_regs / li_paso)
			em_regs.Text = string(ll_regs)
			FETCH cur_padnove INto :ls_anio_mes_dia, :ls_marca,:ls_identifica, :ls_denomina;
		loop
		luo_progress.SetValue(32767)
	else	 
		FileWrite(li_filenum_log, "No se pudo leer padnove " + string(sqlca.sqlcode) + "(" + string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, sqlca.sqlerrtext+ "("+string(datetime(today(),now()))+")")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		wf_status("Proceso abortado.", "E", 0)
		Return
	end if
	CLOSE cur_padnove;
	FileClose(li_filenum_data)	
	FileWrite(li_filenum_log, "Archivo padnove.txt generado. ("+string(datetime(today(),now()))+")")
	wf_status("Generando archivo padnove.txt en directorio de trabajo ...OK.", "F", 0)
	FileWrite(li_filenum_log, "Generando archivo padnove.txt en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")
end if

//Ahora Completo PADDATA en Access y PADDATA.TXT
wf_borrar_archivo(is_temppath+"paddata.txt")
wf_status("Generando archivo paddata.txt en directorio de trabajo ...", "I", 0)
//FileWrite(li_filenum_log, "Generando archivo paddata.txt en directorio de trabajo ...("+string(datetime(today(),now()))+")")

li_filenum_data = FileOpen(is_temppath + "paddata.txt", LINEmODE!, Write!, LockWrite!, Replace!)
if li_filenum_data < 1 then
	MessageBox("Error", "No se puede abrir el archivo paddata.txt para escribir. Avise a Sistemas.")
	FileWrite(li_filenum_log, "No se puede abrir el archivo paddata.txt para escribir.")
	wf_status("Proceso abortado.", "E", 0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if

if is_proceso = 'C' then 
//	FileWrite(li_filenum_data, ls_anio_mes_dia+"P"+"0000000000000000")
	ls_tot_archivos_cuatrimestral = String (ll_tot_arch_deszip, "0000000000000000")
	FileWrite(li_filenum_data, ls_anio_mes_dia+"P" + 	ls_tot_archivos_cuatrimestral)
	INSERT INto paddata  ( fecha,marca,bajas,altas  ) 
	VALUES ( :ls_anio_mes_dia, 'P',0,0)  USING sqlca;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "Insert sobre paddata. " + sqlca.sqlerrtext + " (" + string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "Insert sobre paddata. " + sqlca.sqlerrtext + " Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
	end if	
elseif is_proceso = 'S' then
	INSERT INto paddata  ( fecha,marca,bajas,altas  ) 
	VALUES ( :ls_anio_mes_dia, 'S',:ll_bajas,:ll_altas)  USING sqlca;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "Insert sobre paddata-Semanal. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "Insert sobre paddata-Semanal. "+sqlca.sqlerrtext+" Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
	end if
	/**/
	DECLARE cur_paddata CURSOR for  
  	SELECT paddata.fecha,paddata.marca,paddata.bajas,paddata.altas 
    FROM paddata /*WHERE paddata.marca = 'S' */ using (sqlca) ;
	 
	ll_regs = 0
	
	OPEN cur_paddata;
	if sqlca.sqlcode >= 0 then
		FETCH cur_paddata INto :ls_anio_mes_dia,:ls_marca,:ll_bajas,:ll_altas;
		do while sqlca.sqlcode = 0
			ls_bajas = string(ll_bajas,"00000000")
			ls_altas = string(ll_altas,"00000000")
			FileWrite(li_filenum_data, ls_anio_mes_dia+ls_marca+ls_bajas+ls_altas)
			yield()
			ll_regs++
			em_regs.Text = string(ll_regs)
			FETCH cur_paddata INto :ls_anio_mes_dia,:ls_marca,:ll_bajas,:ll_altas;
		loop
	else	 
		FileWrite(li_filenum_log, "No se pudo leer paddata "+string(sqlca.sqlcode)+ "("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, sqlca.sqlerrtext+ "("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		wf_status("Proceso abortado.", "E", 0)
		Return
	end if
	CLOSE cur_paddata;
end if	
FileClose(li_filenum_data)	
FileWrite(li_filenum_log, "Archivo paddata.txt generado. ("+string(datetime(today(),now()))+")")

wf_status("Generando archivo paddata.txt en directorio de trabajo ...OK.", "F", 0)
FileWrite(li_filenum_log, "Generando archivo paddata.txt en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")

if is_proceso = 'C' then
	wf_status("Generando trigger afipct en directorio de trabajo ...", "I", 0)
	FileWrite(li_filenum_log, "Generando  trigger afipct en directorio de trabajo ...("+string(datetime(today(),now()))+")")
	li_filenum_data = FileOpen(is_temppath + "afipct", LINEmODE!, Write!, LockWrite!, Replace!)
	if li_filenum_data < 1 then
		MessageBox("Error", "No se puede generar el trigger afipct. Avise a Sistemas.")
		FileWrite(li_filenum_log, "No se puede generar el trigger afipct.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileClose(li_filenum_data)	
	end if
	wf_status("Generando trigger afipct en directorio de trabajo ...OK.", "F", 0)
	FileWrite(li_filenum_log, "Generando trigger afipct en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")
else //if is_proceso = 'S' then
	wf_status("Generando trigger afipst en directorio de trabajo ...", "I", 0)
	FileWrite(li_filenum_log, "Generando  trigger afipst en directorio de trabajo ...("+string(datetime(today(),now()))+")")
	li_filenum_data = FileOpen(is_temppath + "afipst", LINEmODE!, Write!, LockWrite!, Replace!)
	if li_filenum_data < 1 then
		MessageBox("Error", "No se puede generar el trigger afipst. Avise a Sistemas.")
		FileWrite(li_filenum_log, "No se puede generar el trigger afipst.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileClose(li_filenum_data)	
	end if
	wf_status("Generando trigger afipst en directorio de trabajo ...OK.", "F", 0)
	FileWrite(li_filenum_log, "Generando trigger afipst en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")
end if

/************************************************************************/
/***********     REALIZO toDA LA OPERACION PARA COPIAR EN LA RED ********/
/************************************************************************/
string ls_ret, ls_run, ls_PathFin,ls_PathTrigger, ls_PathPassword,ls_netuser,ls_password
string ls_letra_mapeo, ls_key, ls_in, ls_accesibilidad_destino
uo_syncproc uo_sp

uo_sp = create  uo_syncproc

ls_PathFin = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathFin","")
if gs_hostname = "BKB046309D" then
	ls_PathPassword =  ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathPassword","")
else
//	ls_PathPassword = "\\" + gs_hostname + "\" + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathPassword","")
	ls_PathPassword = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathPassword","")
end if
ls_letra_mapeo = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "LetraMapeo","") 
ls_key=ProfileString(gs_aplicacion_inifile, "CONSTANTES", "key","") 

//Setear el directorio de los fuentes donde esta la dll pues sino falla la llamada a la misma en modo debug
ls_err_str = GetCurrentDirectory()
li_ret = ChangeDirectory (gs_currdir)


// Leo y desencripto usuario
ls_netuser="        "
ls_in = ProfileString(ls_PathPassword , "PARAMETROS", "NetUsuario","")
ls_netuser =  uf_getpass(ls_in,ls_key)
ls_netuser=trim(ls_netuser)

// Leo y desencripto password
ls_password="        "
ls_in = ProfileString(ls_PathPassword , "PARAMETROS", "NetPassword","")
ls_password =  uf_getpass(ls_in,ls_key)
ls_password = trim(ls_password)


// Realizo el Desmapeo de la letra seteada por el ini - MAPEO
// previamente guardo si existiera un mapeo previo para reestablecerlo.
string ls_path_desmapeo, ls_tmp, ls_unc
Ulong      ll_size, lul_null
long ll_rc
int li_hasta
int  j

SetNull(ls_null)
for i=1 to 30
	SetNull(is_letra_array[i])
	SetNull(is_unc_array[i])
next

ls_tmp = ls_letra_mapeo+":\"
//li_ret = GetDriveTypeW(ls_tmp)
if GetDriveTypeW(ls_tmp) = 4 then // tipo 4 es recurso de red
	// Antes me fijo si la letra asignada tiene algún mapeo
	ls_tmp = upper(left(ls_tmp,2))
	ll_size = 255
	ls_unc = Space(ll_size)
	ll_rc = WNetGetConnectionW(ls_tmp, ls_unc, ll_size)
	// Realizo la operacion de Desmapeo
	// Antes guardo la letra y unc para mapear luego
	is_letra_array[1] = ls_tmp
	is_unc_array[1] = ls_unc
	ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)
	if ll_rc = 0 then
		ls_ret="Se ha efectuado el De-Mapeo "+ls_tmp+"-"+ls_unc
		FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
	end if
end if
// Recursivamente debo llamar a ésta función para que desmapee previamente las posibles conecciones
// \\la2buadfs01
// \\la2buadfs01\transmision
// \\la2buadfs01\transmision\DESA
// \\la2buadfs01\transmision\DESA\CENDEU
// etc...
//si existieran, las guarda en un arreglo para reestablecerlas luego.
ls_path_desmapeo = ls_PathFin
li_hasta = 3
do while li_hasta > 0
	li_hasta = pos(ls_PathFin,'\',li_hasta)
	if li_hasta > 0 then
		ls_path_desmapeo = mid(ls_PathFin,1, li_hasta - 1)
		// Debo averiguar la 1ra posicion del vector que es nulo		
		j=UpperBound(is_letra_array)
		for i=2 to j
			if Isnull(is_letra_array[i]) then j=i
		next
		uf_desmapeo_recurso(ls_path_desmapeo,j,li_filenum_log)
		li_hasta ++
	end if
loop
// Realice los desmapeos

//* Realizo la conexion a la red con la letra seteada en el ini al path final donde se copiaran los archivos
ll_rc = uf_mapeo_recurso_2(ls_tmp, ls_PathFin,ls_netuser,ls_password, ls_err_str)
if ll_rc = 0 then
	ls_ret="Se ha efectuado el Mapeo "+ls_tmp+" "+ls_PathFin
	FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
else
	ls_ret="Error en el Mapeo a los servidores" 
//	FileWrite(li_filenum_log, ls_ret+"-Codigo "+String(ll_rc)+"  "+ls_tmp+" "+ls_PathFin+" "+ls_netuser+" "+ls_password+"-"+string(datetime(today(),now())))
	FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str +" - "+ls_tmp+" "+ls_PathFin+" "+ls_netuser+"-"+string(datetime(today(),now())))
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	MessageBox("La conexión falló",  ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str)
	wf_status("La conexión falló: " + ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str, "E", 0)
	wf_status("Proceso abortado.", "E", 0)
	GOto RESTAURO_CONECCIONES
end if

// Verifica Acceso Destino
ls_accesibilidad_destino = uf_path_accesible(ls_temppath_trabajo,ls_letra_mapeo)
ls_accesibilidad_destino = trim(ls_accesibilidad_destino)
if ls_accesibilidad_destino <> ""  then
	FileWrite(li_filenum_log, "Verificando Accesibilidad Destino - ERROR - AVISE A SISTEMAS: " + ls_accesibilidad_destino)
	Messagebox("Atención!","Error al Acceder al Directorio Destino para copia Final." + "~r~n" + ls_accesibilidad_destino, Exclamation! )
	GOto RESTAURO_CONECCIONES
else 
	//Copia archivos a destino
	wf_status("Copiando archivo "+is_temppath+"paddata.txt a directorio destino ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"paddata.txt a directorio destino ...("+string(datetime(today(),now()))+")")
	if wf_copiar_a_temp(is_temppath,"\paddata.txt",ls_PathFin,"\paddata.txt") < 0 then 	
		wf_status("Proceso abortado - Archivo paddata.txt.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado - Archivo paddata.txt. ("+string(datetime(today(),now()))+")")
		GOto RESTAURO_CONECCIONES
	end if
	wf_status("Copiando archivo "+is_temppath+"paddata.txt a directorio destino OK.", "F", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"paddata.txt a directorio destino OK. ("+string(datetime(today(),now()))+")")

	wf_status("Copiando archivo "+is_temppath+"padnove.txt a directorio destino ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padnove.txt a directorio destino ...("+string(datetime(today(),now()))+")")
	if wf_copiar_a_temp(is_temppath,"\padnove.txt",ls_PathFin,"\padnove.txt") < 0 then 	
		wf_status("Proceso abortado - Archivo padnove.txt.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado - Archivo padnove.txt. ("+string(datetime(today(),now()))+")")
		GOto RESTAURO_CONECCIONES
	end if
	wf_status("Copiando archivo "+is_temppath+"padnove.txt a directorio destino OK.", "F", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padnove.txt a directorio destino OK. ("+string(datetime(today(),now()))+")")

	if is_proceso = 'C' then 
		for i=0 to ll_tot_arch_deszip - 1
			wf_status("Copiando archivo "+ls_temppath_trabajo+"padfyj_"+string(i)+".txt a directorio destino ...", "I", 0)
			FileWrite(li_filenum_log, "Copiando archivo "+ls_temppath_trabajo+"padfyj_"+string(i)+".txt a directorio destino ...("+string(datetime(today(),now()))+")")
			if wf_copiar_a_temp(ls_temppath_trabajo,"\padfyj_"+string(i)+".txt",ls_PathFin,"\padfyj_"+string(i)+".txt") < 0 then 	
				wf_status("Proceso abortado - Archivo padfyj_"+string(i)+".txt.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado - Archivo padfyj_"+string(i)+".txt. ("+string(datetime(today(),now()))+")")
				GOto RESTAURO_CONECCIONES
			end if
		next	
		wf_status("Copiando archivos "+is_temppath+"padfyj_i.txt a directorio destino OK.", "F", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padfyj_i.txt a directorio destino OK. ("+string(datetime(today(),now()))+")")
	 	
		wf_status("Copiando trigger "+is_temppath+"afipct a directorio destino ...", "I", 0)
		FileWrite(li_filenum_log, "Generando trigger "+is_temppath+"afipct a directorio destino ...("+string(datetime(today(),now()))+")")
		if wf_copiar_a_temp(is_temppath,"\afipct",ls_PathFin,"\afipct") < 0 then 	
			wf_status("Proceso abortado - Generando trigger afipct.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado - Generando trigger afict. ("+string(datetime(today(),now()))+")")
			GOto RESTAURO_CONECCIONES
		end if
		
		//elimino el mapeo anterior para mapear a donde debo dejar el trigger
		ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)	
	
		//* Realizo la conexion a la red con la letra seteada en el ini al path donde se copiara el tirgger
		ll_rc = uf_mapeo_recurso_2(ls_tmp, ls_PathTrigger,ls_netuser,ls_password,ls_err_str)
		IF ll_rc = 0 THEN
			ls_ret="Se ha efectuado el Mapeo " + ls_tmp + " " + ls_PathTrigger + " " + ls_netuser
			FileWrite(li_filenum_log, ls_ret + " - " + string(datetime(today(),now())))
		ELSE
			ls_ret="Error en el Mapeo a los servidores~r~n" 
			FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str + " - " + string(datetime(today(),now())))
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			MessageBox("La conexión falló", ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str ) 	//+ "~r~n" +  ls_netuser + " " + ls_password)
			wf_status("La conexión falló: " + ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str, "E", 0)
			wf_status("Proceso abortado.", "E", 0)
			GOTO RESTAURO_CONECCIONES
		END IF
		//copio el trigger
		wf_status("Copiando trigger "+is_temppath+"afipct a directorio destino OK.", "F", 0)
		FileWrite(li_filenum_log, "Copiando trigger "+is_temppath+"afipct a directorio destino OK. ("+string(datetime(today(),now()))+")")
	else
		//elimino el mapeo anterior para mapear a donde debo dejar el trigger
		ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)	
		//* Realizo la conexion a la red con la letra seteada en el ini al path donde se copiara el tirgger
		ll_rc = uf_mapeo_recurso_2(ls_tmp, ls_PathTrigger,ls_netuser,ls_password,ls_err_str)
		IF ll_rc = 0 THEN
			ls_ret="Se ha efectuado el Mapeo " + ls_tmp + " " + ls_PathTrigger + " " + ls_netuser
			FileWrite(li_filenum_log, ls_ret + " - " + string(datetime(today(),now())))
		ELSE
			ls_ret="Error en el Mapeo a los servidores~r~n" 
			FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str + " - " + string(datetime(today(),now())))
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			MessageBox("La conexión falló", ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str ) 	//+ "~r~n" +  ls_netuser + " " + ls_password)
			wf_status("La conexión falló: " + ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str, "E", 0)
			wf_status("Proceso abortado.", "E", 0)
			GOTO RESTAURO_CONECCIONES
		END IF		
	 	//copio el trigger
		wf_status("Copiando trigger "+is_temppath+"afipst a directorio destino ...", "I", 0)
		FileWrite(li_filenum_log, "Generando trigger "+is_temppath+"afipst a directorio destino ...("+string(datetime(today(),now()))+")")
		if wf_copiar_a_temp(is_temppath,"\afipst",ls_PathFin,"\afipct") < 0 then 	
			wf_status("Proceso abortado - Generando trigger afipst.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado - Generando trigger afipct. ("+string(datetime(today(),now()))+")")
			GOto RESTAURO_CONECCIONES
		end if	
		wf_status("Copiando trigger "+is_temppath+"afipst a directorio destino OK.", "F", 0)
		FileWrite(li_filenum_log, "Copiando trigger "+is_temppath+"afipst a directorio destino OK. ("+string(datetime(today(),now()))+")")
	end if
end if	

wf_borrar_archivo(ls_temppath_trabajo+"padfyj.zip")
for i=0 to ll_tot_arch_deszip - 1
	wf_borrar_archivo(ls_temppath_trabajo+"padfyj_"+string(i)+".txt")
next

wf_borrar_archivo(ls_temppath_trabajo+"bajas.txt")
wf_borrar_archivo(ls_temppath_trabajo+"detalle.txt")
wf_borrar_archivo(ls_temppath_trabajo+"novedades.txt")
wf_borrar_archivo(ls_temppath_trabajo+ls_anio_mes_dia+".zip")

RESTAURO_CONECCIONES:
	// Cancelo la letra mapeada en el ini
	ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)
	if ll_rc = 0 then
		ls_ret="Se ha efectuado el De-Mapeo "+ls_tmp
		FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
	end if
	
	string ls_root
	// Restauro todas las conecciones si las hubiera
	j = UpperBound(is_letra_array)
	for i=1 to j
		ls_root =  	is_letra_array[i]
		ls_unc = is_unc_array[i]
		if not isnull(ls_root) then
			ll_rc = uf_mapeo_recurso_2(ls_root, ls_unc,ls_null,ls_null, ls_err_str)
			if ll_rc = 0 then
				ls_ret="Se ha efectuado el Mapeo "+ls_root+" "+ls_unc
				FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
			else
				ls_ret="Error en el Mapeo a los servidores~r~n" 
				FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str + " - " + string(datetime(today(),now())))
				FileClose(li_filenum_log)
				MessageBox("La RE-conexión falló", ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str)			
			end if
		end if
	next
wf_status("PROCESO FINALIZADO.", "I", 0)
FileWrite(li_filenum_log, "PROCESO FINALIZAdo-"+string(datetime(today(),now())))
FileClose(li_filenum_log)
Commit USING sqlca;
luo_progress.SetValue(0)
dw_paddata.SetTransObject(SQLCA)
dw_paddata.Retrieve()
Setpointer (oldpointer)
end event

event ue_test_pack();string ls_fecha_max, ls_anio_mes_dia, ls_null
pointer oldpointer
oldpointer = SetPointer(HourGlass!)

if wf_compactar_tabladbf("padnove") <> 0 then
	MessageBox("Error", "pack padnove "+sqlca.sqlerrtext+" Proceso Abortado.")
	RollBack USING sqlca;
	wf_status("Proceso abortado.", "E",0)
//	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
//	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
else
	Commit USING sqlca;
	wf_status("Pack padnove OK", "I", 0)
//	FileWrite(li_filenum_log, "Pack padnove OK. ("+string(datetime(today(),now()))+")")
end if	

////EXECUTE immediate "pack padnove" USING sqlca  ;
//EXECUTE immediate "SET EXCLUSIVE ON;PACK padnove" USING sqlca;
//EXECUTE immediate "SET EXCLUSIVE OFF" USING sqlca  ;
//if sqlca.sqlcode <> 0 then
//	MessageBox("Error", "pack padnove "+sqlca.sqlerrtext+" Proceso Abortado.")
//	RollBack USING sqlca;
//	wf_status("Proceso abortado.", "E",0)
//	setpointer (oldpointer)
//	Return
//else
//	Commit USING sqlca;
//	wf_status("Pack padnove OK", "I", 0)
//end if	
//
//disconnect using SQLCA;
//SQLCA.DBMS = ProfileString(gs_aplicacion_inifile, "Database", "DBMS","")
//SQLCA.Lock = "RC"
//SQLCA.DbParm = ProfileString(gs_aplicacion_inifile, "Database", "DbParm", "")
//Connect using SQLCA ;
//
//
//SELECT max(paddata.fecha)
//INto :ls_fecha_max 
//FROM paddata  
//WHERE paddata.marca = 'P' USING sqlca  ;
//
//if sqlca.sqlcode = -1 then
//	RollBack USING sqlca;
//	MessageBox("Error", "count(*) sobre padnove. Proceso Abortado.")
//	wf_status("Proceso abortado.", "E",0)
//	setpointer (oldpointer)
//	Return
//end if	
//	
//	
//if is_proceso = 'C' then
//	// Borro todos los registros de padnove !!!
//	DELETE FROM padnove  USING sqlca  ;
//	if sqlca.sqlcode <> 0 then
//		RollBack USING sqlca;
//		wf_status("Proceso abortado.", "E",0)
//		MessageBox("Error", "DELETE sobre padnove....C"+sqlca.sqlerrtext+" Proceso Abortado.")
//		setpointer (oldpointer)
//		Return
//	else
//		Commit USING sqlca;
//		wf_status("Borro todos los registros de padnove !!!...OK", "I", 0)
//	end if	
//	
//	SetNull(ls_null)
//	INSERT INto padnove  
//		( fecha,marca,identifica,denomina )  
//	VALUES ( :ls_anio_mes_dia, :ls_null,:ls_null,:ls_null )  
//	USING sqlca;
//	if sqlca.sqlcode <> 0 then
//		RollBack USING sqlca;
//		wf_status("Proceso abortado.", "E",0)
//		MessageBox("Error", "Insert sobre padnove-C. "+sqlca.sqlerrtext+" Proceso Abortado.")
//		setpointer (oldpointer)
//		Return
//	end if
//end if


/*

USE nombredetutabla EXCLUSIVE; PACK 

*/
end event

event ue_procesar_old();/*********************************************************************************************/
// Este evento dispara el proceso de carga del archivo de interfáz de la AFIP cuatrimestral y Semanal
// No es el que se utiliza ahora, ya que el cuatrimestral en este caso no solo descomprime el .zip , sino que ademas formatea y 
//.pega en un unico archivo los 10 enviando el resultado a maninframe.
// tabla paddata.dbf mantiene informacion de los procesos ejecutados del padron de AFIP
// tabla padnove.dbf mantiene informacion de los registros de novedades (Altas y Bajas) 
// de los procesos del padron de AFIP. Acumula Semanales hasta que llega un Cuatrimestral
/*********************************************************************************************/

uo_syncproc luo_sync
long ll_regs, ll_total_regs
integer li_ret, i, li_paso
string ls_err_str

pointer oldpointer
string ls_temppath_trabajo

string ls_sololeer, ls_linea,ls_path_Log,ls_path, ls_anio_mes_dia, ls_ejecutar
long	li_filenum, li_filenum_log,li_filenum_txt, li_filenum_data, ll_filas

string  ls_marca, ls_denomina,ls_identifica, ls_fecha,ls_fecha_max, ls_null
long ll_altas, ll_bajas
string ls_altas, ls_bajas
boolean 	lb_eof

ib_cancelar=false

mle_status.text=""
mle_import.text=""
is_log_import=""
luo_progress.SetValue(0)
sle_errores.text = "0"
em_regs.text="0"

if MessageBox(this.Title, "Está Ud seguro de Procesar?",Exclamation!,YesNo!) = 2 then Return


oldpointer = setpointer (HourGlass!)
is_recursocomp = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "RecursoCompartido","")
is_temppath = "\\" + gs_hostname + "\" + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "Path","")
ls_temppath_trabajo = "\\" + gs_hostname + "\"  + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathTrabajo","")
ls_path_Log = "\\" + gs_hostname + "\" + is_recursocomp + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathLog","")

li_filenum_log = FileOpen(ls_path_Log + "log.txt", LINEmODE!, Write!, LockWrite!, Append!)
if li_filenum_log < 1 then
	MessageBox("Error", "No se puede abrir el archivo log.txt para escribir. Cierre todas las ventanas e intente nuevamente.")
	Return
end if

FileWrite(li_filenum_log, "***********************************")
if is_proceso = 'C' then 
	FileWrite(li_filenum_log, "Comenzando proceso AFIP Cuatrimestral - usuario: "+gs_username+" ("+string(datetime(today(),now()))+")")
elseif is_proceso = 'S' then 
	FileWrite(li_filenum_log, "Comenzando proceso AFIP Semanal - usuario: "+gs_username+" ("+string(datetime(today(),now()))+")")
end if

wf_status("Validando parámetros ...", "I", 0)
FileWrite(li_filenum_log, "Validando parámetros ...("+string(datetime(today(),now()))+")")
if wf_validar_parametros() < 0 then 
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	return
end if
wf_status("Validando parámetros ...OK", "E", 0)
FileWrite(li_filenum_log, "Validando parámetros ...OK("+string(datetime(today(),now()))+")")
ls_path = sle_archivo.Text
ls_anio_mes_dia = is_anio_mes_dia

//Antes que nada, borrar si existieran los archivos que van a ser descompactados.
wf_status("Borrando archivos Temporarios ...", "I", 0)
FileWrite(li_filenum_log, "Borrando archivos Temporarios...("+string(datetime(today(),now()))+")")
wf_borrar_archivo(is_temppath + "padfyj.txt")
wf_borrar_archivo(is_temppath + "paddata.txt")
wf_borrar_archivo(is_temppath + "padnove.txt")
//wf_borrar_archivo(ls_temppath_trabajo+"afipdata.txt")
if is_proceso = 'C' then
	ls_path = mid(ls_path,1,Pos (ls_path, "padfyj_1.txt" , 1 )-1)
	for i=0 to 9
		wf_borrar_archivo(ls_temppath_trabajo+"padfyj_"+string(i)+".txt")
	next
elseif is_proceso = 'S' then
	ls_path = mid(ls_path,1,Pos ( ls_path, ls_anio_mes_dia+".zip" , 1 )-1)
	wf_borrar_archivo(ls_temppath_trabajo+ls_anio_mes_dia+".zip")
end if
wf_status("Borrando archivos Temporarios OK.", "E",0)
FileWrite(li_filenum_log, "Borrando archivos Temporarios OK ("+string(datetime(today(),now()))+")")


luo_sync = CREATE uo_syncproc
luo_sync.of_setwindow('hide')

/******************** Compactar la el archivo de la tabla padnove.dbf *******************/
FileWrite(li_filenum_log, "Compactando el archivo de la tabla padnove [pack padnove] " + sqlca.sqlerrtext + " (" + string(datetime(today(),now())) + ")")
if wf_compactar_tabladbf("padnove") <> 0 then
	MessageBox("Error", "pack padnove "+sqlca.sqlerrtext+" Proceso Abortado.")
	RollBack USING sqlca;
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
else
	Commit USING sqlca;
	wf_status("Pack padnove OK", "I", 0)
	FileWrite(li_filenum_log, "Pack padnove OK. ("+string(datetime(today(),now()))+")")
end if	
/****************************************************************************************/

SELECT max(paddata.fecha)
INto :ls_fecha_max 
FROM paddata  
WHERE paddata.marca = 'P' USING sqlca  ;

if sqlca.sqlcode = -1 then
	RollBack USING sqlca;
	FileWrite(li_filenum_log, "Count(*) sobre padnove. (" + string(datetime(today(),now())) + ")")
	MessageBox("Error", "count(*) sobre padnove. Proceso Abortado.")
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if	
if not isnull(ls_fecha_max) and ls_fecha_max > ls_anio_mes_dia then
	MessageBox(this.Title, "Ya existen filas con fecha posterior al proceso. Proceso Cancelado!!!.")
	wf_status("Proceso abortado.", "E",0)
	FileWrite(li_filenum_log, "Ya existen filas con fecha posterior al proceso!!!. (" + string(datetime(today(),now())) + ")")
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if	

	
if is_proceso = 'C' then
	// Borro todos los registros de padnove !!!
	DELETE FROM padnove  USING sqlca  ;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "DELETE sobre padnove....C" + sqlca.sqlerrtext + " (" +string(datetime(today(),now())) + ")")
		RollBack USING sqlca;
		wf_status("Proceso abortado.", "E",0)
		MessageBox("Error", "DELETE sobre padnove....C"+sqlca.sqlerrtext+" Proceso Abortado.")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
		wf_status("Borro todos los registros de padnove !!!...OK", "I", 0)
		FileWrite(li_filenum_log, "Borro todos los registros de padnove !!! ("+string(datetime(today(),now()))+")")
	end if	
	
	SetNull(ls_null)
	INSERT INto padnove  
		( fecha,marca,identifica,denomina )  
	VALUES ( :ls_anio_mes_dia, :ls_null,:ls_null,:ls_null )  
	USING sqlca;
	if sqlca.sqlcode <> 0 then
		RollBack USING sqlca;
		FileWrite(li_filenum_log, "Insert sobre padnove-C. " + sqlca.sqlerrtext + " (" + string(datetime(today(),now())) + ")")
		wf_status("Proceso abortado.", "E",0)
		MessageBox("Error", "Insert sobre padnove-C. "+sqlca.sqlerrtext+" Proceso Abortado.")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if

	/******************************************************/
	/* Copiar archivo padfyj.zip a directorio de trabajo  */
	/******************************************************/
	if FileExists(ls_path+"padfyj.zip") then 		
		wf_status("Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo ...", "I", 0)
		wf_status("Este proceso puede demorar unos minutos...", "I", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo ...("+string(datetime(today(),now()))+")")
		if wf_copiar_a_temp(ls_path,"padfyj.zip",ls_temppath_trabajo,"padfyj.zip") < 0 then 	
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Error copiando archivo Copiando archivo " + ls_path+"padfyj.zip a directorio de trabajo. ("+string(datetime(today(),now()))+")")
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			return
		end if
		wf_status("Copiando archivo padfyj.zip a directorio de trabajo OK.", "F", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+ls_path+"padfyj.zip a directorio de trabajo OK. ("+string(datetime(today(),now()))+")")
	end if
	/*******************************************************/
	
	/****************************************************************************/
	/* Descomprimir archivo padfyj.zip Cuatrimestral en directorio de trabajo   */
	/****************************************************************************/
	wf_status("Descomprimiendo archivos padfyj.zip en directorio de trabajo.", "I", 0)
	wf_status("Este proceso puede demorar varios minutos...", "I", 0)
	
	//hago visible la barra de progreso y seteo el paso a 1 (x default es 10)
	luo_progress.visible = true
	luo_progress.setstep(1)
	// reseteo y fijo el limite superior a la barra de progreso
	luo_progress.SetRange(0, 100)
	luo_progress.SetValue(0)
	
	st_4.text = "Archivo:"
	st_1.text = "de:"
	ole_xceedzip.object.ZipFilename = ls_temppath_trabajo + "padfyj.zip" 
	ole_xceedzip.object.FilesToProcess = "" 
	ole_xceedzip.object.UnzipToFolder = ls_temppath_trabajo
	ole_xceedzip.object.IgnoredExtraHeaders = 4	//xehSecurityDescriptor - Store/Retrieve the Windows NT file security information header.
	//oldpointer = SetPointer(HourGlass!)
	li_ret = ole_xceedzip.object.Unzip()
	//setpointer(oldpointer)
	st_4.text= "Leídos:"
	st_1.text = "Archivo:"
	
	wf_status("Descomprimiendo archivos padfyj.zip en directorio de trabajo OK.", "F", 0)
	/****************************************************************************/
elseif is_proceso = 'S' then
    SELECT Count(*)
    INto :ll_filas
    FROM padnove  
   WHERE padnove.fecha = :ls_anio_mes_dia USING sqlca  ;
	if sqlca.sqlcode = -1 then
		FileWrite(li_filenum_log, "Error haciendo un Count(*) sobre padnove. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "count(*) sobre padnove. Proceso Abortado."+sqlca.sqlerrtext)
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	if ll_filas > 0 then
		if MessageBox(this.Title, "Ya existen filas con ésa fecha!!!, Desea Reprocesar?",Exclamation!,YesNo!) = 2 then 
			FileWrite(li_filenum_log, "Ya existen filas con ésa fecha. ("+string(datetime(today(),now()))+")")
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			wf_status("Proceso abortado.", "E",0)
			setpointer (oldpointer)
			Return
		else
			// Borro todos los registros de ésa semana de paddata !!!
			DELETE FROM paddata WHERE paddata.marca = 'S' and paddata.fecha = :ls_anio_mes_dia  USING sqlca  ;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "DELETE sobre paddata."+sqlca.sqlerrtext+" Proceso Abortado. ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "DELETE sobre paddata."+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				Commit USING sqlca;
				wf_status("Reproceso - Se borraron previamente los registros....paddata", "I", 0)
				FileWrite(li_filenum_log, "Reproceso-Se borraron previamente los registros paddata. ("+string(datetime(today(),now()))+")")
			end if	
			// Borro todos los registros B !!!
			DELETE FROM padnove  WHERE padnove.fecha = :ls_anio_mes_dia USING sqlca  ;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "DELETE sobre padnove " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				MessageBox("Error", "DELETE sobre padnove"+sqlca.sqlerrtext+" Proceso Abortado.")
				Return
			else
				Commit USING sqlca;
				wf_status("Reproceso-Se borraron previamente los registros....padnove", "I", 0)
				FileWrite(li_filenum_log, "Reproceso-Se borraron previamente los registros....padnove. ("+string(datetime(today(),now()))+")")
			end if	
		end if
	end if
	
	/****************************************************************/
	/* Copiar archivo semanal yyyymmdd.zip a directorio de trabajo  */
	/****************************************************************/
	//	ls_path = mid(ls_path,1,Pos ( ls_path, ls_anio_mes_dia+".zip" , 1 )-1)
	wf_status("Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo ...("+string(datetime(today(),now()))+")")

	if wf_copiar_a_temp(ls_path,ls_anio_mes_dia+".zip",ls_temppath_trabajo,ls_anio_mes_dia+".zip") < 0 then 	
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		return
	end if
	wf_status("Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo OK.", "F", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+ls_path+ls_anio_mes_dia+".zip a directorio de trabajo OK. ("+string(datetime(today(),now()))+")")
	
	/****************************************************************/
	
	/****************************************************************************/
	/* Descomprimir archivo yyyymmdd.zip semanal en directorio de trabajo   */
	/****************************************************************************/
	wf_status("Descomprimiendo archivo "+ ls_anio_mes_dia +".zip en directorio de trabajo.", "I", 0)
	wf_status("Este proceso puede demorar varios minutos...", "I", 0)
	
	//hago visible la barra de progreso y seteo el paso a 1 (x default es 10)
	luo_progress.visible = true
	luo_progress.setstep(1)
	// reseteo y fijo el limite superior a la barra de progreso
	luo_progress.SetRange(0, 100)
	luo_progress.SetValue(0)
	
	st_4.text= "Archivo:"
	st_1.text = "de:"
	ole_xceedzip.object.ZipFilename = ls_temppath_trabajo + ls_anio_mes_dia+".zip"
	ole_xceedzip.object.FilesToProcess = "" 
	ole_xceedzip.object.UnzipToFolder = ls_temppath_trabajo
	ole_xceedzip.object.IgnoredExtraHeaders = 4	//xehSecurityDescriptor - Store/Retrieve the Windows NT file security information header.
	//oldpointer = SetPointer(HourGlass!)
	li_ret = ole_xceedzip.object.Unzip()
	//setpointer(oldpointer)
	st_4.text= "Leídos:"
	st_1.text = "Errores:"
	//ls_ejecutar = mid(ls_temppath_trabajo,1,pos(ls_temppath_trabajo,"Data")-1)+"\exe\pkunzip -o " + ls_temppath_trabajo + ls_anio_mes_dia+".zip" + " " + ls_temppath_trabajo
	//luo_sync.of_RunAndWait(ls_ejecutar)
	wf_status("Descomprimiendo archivo "+ ls_anio_mes_dia +".zip en directorio de trabajo OK.", "F", 0)

	/****************************************************************************/

	// 1ro leer el archivo detalle.txt
	ls_sololeer = ls_temppath_trabajo + "detalle.txt"
	if not FileExists(ls_temppath_trabajo+"detalle.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +" detalle.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo " + ls_temppath_trabajo + " detalle.txt. ")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo detalle.txt para Leer. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo detalle.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	if FileRead(li_filenum,ls_linea) > 0 then // 2006-08-20 Altas 157467
		ls_fecha = mid(ls_linea,1,4)+mid(ls_linea,6,2)+mid(ls_linea,9,2)
		ll_altas = long(mid(ls_linea,18,8))
		if ls_fecha <> ls_anio_mes_dia then
			FileWrite(li_filenum_log, "La Fecha informada no concuerda con los archivos. ("+string(datetime(today(),now()))+")")
			MessageBox(this.title,"La Fecha informada no concuerda con los archivos!")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		else
			FileWrite(li_filenum_log, "Archivo Detalles, Altas: "+string(ll_altas)+" ("+string(datetime(today(),now()))+")")
		end if	
	end if
	if FileRead(li_filenum,ls_linea) > 0 then //	2006-08-20 Bajas 158286
		ls_fecha = mid(ls_linea,1,4)+mid(ls_linea,6,2)+mid(ls_linea,9,2)
		ll_bajas = long(mid(ls_linea,18,8))
		if ls_fecha <> ls_anio_mes_dia then
			FileWrite(li_filenum_log, "La Fecha informada no concuerda con los archivos. ("+string(datetime(today(),now()))+")")
			MessageBox(this.title,"La Fecha informada no concuerda con los archivos!")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		else
			FileWrite(li_filenum_log, "Archivo Detalles, Bajas: "+string(ll_bajas)+" ("+string(datetime(today(),now()))+")")
		end if	
	end if
	FileClose(li_filenum)
	// 2ro leo novedades.txt
	lb_eof = FALSE
	ls_sololeer = ls_temppath_trabajo + "novedades.txt"
	if not FileExists(ls_temppath_trabajo+"novedades.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +"novedades.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo "+ls_temppath_trabajo +"novedades.txt. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo novedades.txt para Leer. ("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo novedades.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	ls_marca = 'N'
	ll_filas = 0
	sle_errores.Text = "0"
	if ll_altas > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_altas / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_altas)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	wf_status("Insertando Novedades-Altas....", "I", 0)
	
	do
		if FileRead(li_filenum,ls_linea) > 0 then
			ls_identifica = mid(ls_linea,1,11)
			ls_denomina = mid(ls_linea,12,55)
		  	INSERT INto padnove  
         	( fecha,marca,identifica,denomina )  
  			VALUES ( :ls_anio_mes_dia, :ls_marca,:ls_identifica,
			  :ls_denomina )  
  			USING sqlca;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "Insert sobre padnove-N. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "Insert sobre padnove-N. "+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				yield()
				ll_filas++
				em_regs.Text = string(ll_filas)
				luo_progress.SetValue(ll_filas / li_paso)
			end if	
		else
			lb_eof = TRUE
		end if
	loop until lb_eof
	luo_progress.SetValue(32767)
	
	if ll_filas <> ll_altas then
		FileWrite(li_filenum_log, "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-altas. ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-altas. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileWrite(li_filenum_log, "Insert en Archivo Novedades, Altas: "+string(ll_altas)+" ("+string(datetime(today(),now()))+")")
		Commit USING sqlca;
	end if
	wf_status("Insertando Novedades-Altas: "+string(ll_altas)+"....OK", "E", 0)
	FileClose(li_filenum)
	// 3ro leo bajas.txt
	lb_eof = FALSE
	ls_sololeer = ls_temppath_trabajo + "bajas.txt"
	if not FileExists(ls_temppath_trabajo+"bajas.txt") then
		FileWrite(li_filenum_log, "No existe el archivo "+ls_temppath_trabajo +"bajas.txt. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No existe el archivo "+ls_temppath_trabajo +"bajas.txt. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
	li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!, LockRead!)
	if li_filenum < 1 then
		FileWrite(li_filenum_log, "No se puede abrir el archivo bajas.txt para Leer. ("+string(datetime(today(),now()))+")")
		MessageBox("Error", "No se puede abrir el archivo bajas.txt para Leer. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	ls_marca = 'B'
	SetNull(ls_denomina)
	ll_filas = 0
	if ll_bajas > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_bajas / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_bajas)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	wf_status("Insertando Novedades-Bajas....", "I", 0)
	do
		if FileRead(li_filenum,ls_linea) > 0 then
			ls_identifica = mid(ls_linea,1,11)
		  	INSERT INto padnove  
         	( fecha,marca,identifica,denomina )  
  			VALUES ( :ls_anio_mes_dia, :ls_marca,:ls_identifica,
			  :ls_denomina )  
  			USING sqlca;
			if sqlca.sqlcode <> 0 then
				FileWrite(li_filenum_log, "Insert sobre padnove-B. "+sqlca.sqlerrtext+" ("+string(datetime(today(),now()))+")")
				RollBack USING sqlca;
				MessageBox("Error", "Insert sobre padnove-B. "+sqlca.sqlerrtext+" Proceso Abortado.")
				wf_status("Proceso abortado.", "E", 0)
				FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
				FileClose(li_filenum_log)
				setpointer (oldpointer)
				Return
			else
				yield()
				ll_filas++
				em_regs.Text = string(ll_filas)
				luo_progress.SetValue(ll_filas / li_paso)
			end if	
		else
			lb_eof = TRUE
		end if
	loop until lb_eof
	luo_progress.SetValue(32767)
	
	if ll_filas <> ll_bajas then
		FileWrite(li_filenum_log, "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-bajas. ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "La Cantidad de Insert sobre padnove es diferente a la informada en detalle-bajas. Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		FileWrite(li_filenum_log, "Insert en Archivo Novedades, Bajas: "+string(ll_bajas)+" ("+string(datetime(today(),now()))+")")
		Commit USING sqlca;
		if sqlca.sqlcode <> 0 then
			FileWrite(li_filenum_log, "Error en Commit. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
			RollBack USING sqlca;
			MessageBox("Error", "Commit. "+sqlca.sqlerrtext+" Proceso Abortado.")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)
			Return
		end if
	end if
	wf_status("Insertando Novedades-Bajas: "+string(ll_bajas)+"....OK", "E", 0)
	FileClose(li_filenum)
end if
DESTROY luo_sync


/***********************************************************/
/*  ARMADO DE ARCHIVOS TXT DESDE EL DIRECtoRIO DE TRABAJO  */
/***********************************************************/

wf_borrar_archivo(is_temppath+"padnove.txt")
wf_status("Generando archivo padnove.txt en directorio de trabajo ...", "I", 0)
//FileWrite(li_filenum_log, "Generando archivo padnove.txt en directorio de trabajo ...("+string(datetime(today(),now()))+")")

li_filenum_data = FileOpen(is_temppath + "padnove.txt", LINEmODE!, Write!, LockWrite!, Replace!)
if li_filenum_data < 1 then
	MessageBox("Error", "No se puede abrir el archivo padnove.txt para escribir. Avise a Sistemas.")
	FileWrite(li_filenum_log, "No se puede abrir el archivo padnove.txt para escribir.")
	wf_status("Proceso abortado.", "E", 0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if

sle_errores.Text = "0"

if is_proceso = 'C' then
	//Ahora Completo PADNOVE en DBF y PADNOVE.TXT
	FileWrite(li_filenum_data, ls_anio_mes_dia)
	FileClose(li_filenum_data)	
	FileWrite(li_filenum_log, "Archivo padnove.txt generado. ("+string(datetime(today(),now()))+")")
	wf_status("Generando archivo padnove.txt en directorio de trabajo ...OK.", "F", 0)
//	FileWrite(li_filenum_log, "Generando archivo padnove.txt en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")
	//Ahora Completo padfyj.TXT
	li_filenum_txt = FileOpen(is_temppath + "padfyj.txt", LINEmODE!, Write!, LockWrite!, Append!)
	if li_filenum_txt < 1 then
		MessageBox("Error", "No se puede abrir el archivo padfyj.txt para escribir. Cierre todas las ventanas e intente nuevamente.")
		FileWrite(li_filenum_log, "No se puede abrir el archivo padfyj.txt para escribir.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if
	wf_status("Generando archivo "+is_temppath+"padfyj.txt...", "I", 0)
	
	for i=0 to 9
		lb_eof = FALSE
		ll_filas = 0
		if not FileExists(ls_temppath_trabajo+"padfyj_" + string(i) + ".txt") then 		EXIT
		ll_total_regs = Filelength(ls_temppath_trabajo+"padfyj_" + string(i) + ".txt")
		ll_total_regs = Filelength(ls_temppath_trabajo+"padfyj_" + string(i) + ".txt") / 191
		wf_status("Procesando el archivo padfyj_" + string(i) + ".txt de 10 archivos...", "I", 0)
		ls_sololeer = ls_temppath_trabajo + "padfyj_"+ string(i) + ".txt"
		li_filenum = FileOpen(ls_sololeer, LINEmODE!, Read!)//, LockRead!)
		if li_filenum < 1 then
			FileWrite(li_filenum_log, "No se puede abrir el archivo padfyj_"+string(i)+".txt para Leer. Proceso Abortado. ("+string(datetime(today(),now()))+")")
			MessageBox("Error", "No se puede abrir el archivo padfyj.txt para Leer. Proceso Abortado.")
			wf_status("Proceso abortado.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
			FileClose(li_filenum_log)
			setpointer (oldpointer)			
			Return
		else
			FileWrite(li_filenum_log, "Leyendo Archivo "+ls_sololeer+" ("+string(datetime(today(),now()))+")")
		end if
		
		//estimo la cantidad de registros en el archivo para setear la barra de progreso
		//considerando que cada registro tiene 192 bytes
		if ll_total_regs > 32767 then
			luo_progress.SetRange(0, 32767)
			li_paso = (ll_total_regs / 32767) + 1
		else 
			luo_progress.SetRange(0, ll_total_regs)
			li_paso = 1
		end if		
		
		luo_progress.SetValue(0)
		//archivo a leer
		sle_errores.Text = String(i + 1)
		do
			if FileRead(li_filenum,ls_linea) > 0 then
				FileWrite(li_filenum_txt,mid(ls_linea,1,65))
				yield()
				ll_filas++
				luo_progress.SetValue(ll_filas / li_paso)
//				if Mod (ll_filas, 1000) = 0 then 
//					em_regs.Text = string(ll_filas)
//				end if
			else
				lb_eof = TRUE
			end if
		loop until lb_eof
		luo_progress.SetValue(32767)
		FileClose(li_filenum)
		wf_status("Archivo padfyj_"+string(i)+".txt de 10 archivos procesado... OK", "F", 0)
	next 
	FileClose(li_filenum_txt)
	wf_status("Generando archivo "+is_temppath+"padfyj.txt... OK.", "F", 0)
	FileWrite(li_filenum_log, "Archivo padfyj.txt Generado! ("+string(datetime(today(),now()))+")")
elseif is_proceso = 'S' then
	//Ahora Completo PADNOVE en Access y PADNOVE.TXT
	SELECT Count(*)
   	INto :ll_total_regs
  	FROM padnove  
  	USING sqlca  ;
	if sqlca.sqlcode = -1 then
		FileWrite(li_filenum_log, "Error haciendo un Count(*) sobre padnove. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "count(*) sobre padnove. Proceso Abortado."+sqlca.sqlerrtext)
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	end if	
		
	DECLARE cur_padnove CURSOR for  
  	SELECT padnove.fecha,padnove.marca,padnove.identifica,padnove.denomina 
    FROM padnove 
	 ORDER BY padnove.fecha,padnove.marca,padnove.identifica using (sqlca) ;
	
	ll_regs = 0
	if ll_total_regs > 32767 then
		luo_progress.SetRange(0, 32767)
		li_paso = (ll_total_regs / 32767) + 1
	else 
		luo_progress.SetRange(0, ll_total_regs)
		li_paso = 1
	end if
	luo_progress.SetValue(0)
	
	OPEN cur_padnove;
	if sqlca.sqlcode >= 0 then
		FETCH cur_padnove INto :ls_anio_mes_dia, :ls_marca,:ls_identifica, :ls_denomina;
		do while sqlca.sqlcode = 0
			if IsNull(ls_marca) then ls_marca=''
			if IsNull(ls_identifica) then ls_identifica=''
			if IsNull(ls_denomina) then ls_denomina=''
			FileWrite(li_filenum_data, ls_anio_mes_dia+ls_marca+ls_identifica+ls_denomina)
			yield()
			ll_regs ++
			luo_progress.SetValue(ll_regs / li_paso)
			em_regs.Text = string(ll_regs)
			FETCH cur_padnove INto :ls_anio_mes_dia, :ls_marca,:ls_identifica, :ls_denomina;
		loop
		luo_progress.SetValue(32767)
	else	 
		FileWrite(li_filenum_log, "No se pudo leer padnove " + string(sqlca.sqlcode) + "(" + string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, sqlca.sqlerrtext+ "("+string(datetime(today(),now()))+")")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		wf_status("Proceso abortado.", "E", 0)
		Return
	end if
	CLOSE cur_padnove;
	FileClose(li_filenum_data)	
	FileWrite(li_filenum_log, "Archivo padnove.txt generado. ("+string(datetime(today(),now()))+")")
	wf_status("Generando archivo padnove.txt en directorio de trabajo ...OK.", "F", 0)
	FileWrite(li_filenum_log, "Generando archivo padnove.txt en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")
end if

//Ahora Completo PADDATA en Access y PADDATA.TXT
wf_borrar_archivo(is_temppath+"paddata.txt")
wf_status("Generando archivo paddata.txt en directorio de trabajo ...", "I", 0)
//FileWrite(li_filenum_log, "Generando archivo paddata.txt en directorio de trabajo ...("+string(datetime(today(),now()))+")")

li_filenum_data = FileOpen(is_temppath + "paddata.txt", LINEmODE!, Write!, LockWrite!, Replace!)
if li_filenum_data < 1 then
	MessageBox("Error", "No se puede abrir el archivo paddata.txt para escribir. Avise a Sistemas.")
	FileWrite(li_filenum_log, "No se puede abrir el archivo paddata.txt para escribir.")
	wf_status("Proceso abortado.", "E", 0)
	FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
	FileClose(li_filenum_log)
	setpointer (oldpointer)
	Return
end if
if is_proceso = 'C' then 
	FileWrite(li_filenum_data, ls_anio_mes_dia+"P"+"0000000000000000")
	INSERT INto paddata  ( fecha,marca,bajas,altas  ) 
	VALUES ( :ls_anio_mes_dia, 'P',0,0)  USING sqlca;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "Insert sobre paddata. " + sqlca.sqlerrtext + " (" + string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "Insert sobre paddata. " + sqlca.sqlerrtext + " Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
	end if	
elseif is_proceso = 'S' then
	INSERT INto paddata  ( fecha,marca,bajas,altas  ) 
	VALUES ( :ls_anio_mes_dia, 'S',:ll_bajas,:ll_altas)  USING sqlca;
	if sqlca.sqlcode <> 0 then
		FileWrite(li_filenum_log, "Insert sobre paddata-Semanal. " + sqlca.sqlerrtext + " ("+string(datetime(today(),now()))+")")
		RollBack USING sqlca;
		MessageBox("Error", "Insert sobre paddata-Semanal. "+sqlca.sqlerrtext+" Proceso Abortado.")
		wf_status("Proceso abortado.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		Return
	else
		Commit USING sqlca;
	end if
	/**/
	DECLARE cur_paddata CURSOR for  
  	SELECT paddata.fecha,paddata.marca,paddata.bajas,paddata.altas 
    FROM paddata /*WHERE paddata.marca = 'S' */ using (sqlca) ;
	 
	ll_regs = 0
	
	OPEN cur_paddata;
	if sqlca.sqlcode >= 0 then
		FETCH cur_paddata INto :ls_anio_mes_dia,:ls_marca,:ll_bajas,:ll_altas;
		do while sqlca.sqlcode = 0
			ls_bajas = string(ll_bajas,"00000000")
			ls_altas = string(ll_altas,"00000000")
			FileWrite(li_filenum_data, ls_anio_mes_dia+ls_marca+ls_bajas+ls_altas)
			yield()
			ll_regs++
			em_regs.Text = string(ll_regs)
			FETCH cur_paddata INto :ls_anio_mes_dia,:ls_marca,:ll_bajas,:ll_altas;
		loop
	else	 
		FileWrite(li_filenum_log, "No se pudo leer paddata "+string(sqlca.sqlcode)+ "("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, sqlca.sqlerrtext+ "("+string(datetime(today(),now()))+")")
		FileWrite(li_filenum_log, "Proceso abortado. ("+string(datetime(today(),now()))+")")
		FileClose(li_filenum_log)
		setpointer (oldpointer)
		wf_status("Proceso abortado.", "E", 0)
		Return
	end if
	CLOSE cur_paddata;
end if	
FileClose(li_filenum_data)	
FileWrite(li_filenum_log, "Archivo paddata.txt generado. ("+string(datetime(today(),now()))+")")

wf_status("Generando archivo paddata.txt en directorio de trabajo ...OK.", "F", 0)

//FileWrite(li_filenum_log, "Generando archivo paddata.txt en directorio de trabajo..OK. ("+string(datetime(today(),now()))+")")

/************************************************************************/
//setpointer (oldpointer)
//wf_borrar_archivo(is_temppath+"afipdata.txt")
//
//li_filenum_data = FileOpen(is_temppath + "afipdata.txt", LINEmODE!, Write!, LockWrite!, Replace!)
//if li_filenum_data < 1 then
//	MessageBox("Error", "No se puede abrir el archivo afipdata.txt para escribir. Avise a Sistemas.")
//	FileWrite(li_filenum_log, "No se puede abrir el archivo afipdata.txt para escribir.")
//	Return
//else
//	FileWrite(li_filenum_data, "Año-Mes-Dia proceso: "+ls_anio_mes_dia+"-"+string(datetime(today(),now())))
//	FileClose(li_filenum_data)	
//end if


/************************************************************************/
/***********     REALIZO toDA LA OPERACION PARA COPIAR EN LA RED ********/
/************************************************************************/
string ls_ret, ls_run, ls_PathFin,ls_PathPassword,ls_netuser,ls_password
string ls_letra_mapeo, ls_key, ls_in, ls_accesibilidad_destino
uo_syncproc uo_sp

uo_sp = create  uo_syncproc

ls_PathFin = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathFin","")
if gs_hostname = "BKB046309D" then
	ls_PathPassword =  ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathPassword","")
else
	ls_PathPassword = "\\" + gs_hostname + "\" + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "PathPassword","")
end if
ls_letra_mapeo = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "LetraMapeo","") 
ls_key=ProfileString(gs_aplicacion_inifile, "CONSTANTES", "key","") 

//Setear el directorio de los fuentes donde esta la dll pues sino falla la llamada a la misma en modo debug
ls_err_str = GetCurrentDirectory()
li_ret = ChangeDirectory (gs_currdir)


// Leo y desencripto usuario
ls_netuser="        "
ls_in = ProfileString(ls_PathPassword , "PARAMETROS", "NetUsuario","")
ls_netuser =  uf_getpass(ls_in,ls_key)
ls_netuser=trim(ls_netuser)

// Leo y desencripto password
ls_password="        "
ls_in = ProfileString(ls_PathPassword , "PARAMETROS", "NetPassword","")
ls_password =  uf_getpass(ls_in,ls_key)
ls_password = trim(ls_password)


// Realizo el Desmapeo de la letra seteada por el ini - MAPEO
// previamente guardo si existiera un mapeo previo para reestablecerlo.
string ls_path_desmapeo, ls_tmp, ls_unc
Ulong      ll_size, lul_null
long ll_rc
int li_hasta
int  j

SetNull(ls_null)
for i=1 to 30
	SetNull(is_letra_array[i])
	SetNull(is_unc_array[i])
next

ls_tmp = ls_letra_mapeo+":"
if GetDriveTypeA (ls_tmp) = 4 then // tipo 4 es recurso de red
	// Antes me fijo si la letra asignada tiene algún mapeo
	ls_tmp = upper(left(ls_tmp,2))
	ll_size = 255
	ls_unc = Space(ll_size)
	ll_rc = WNetGetConnectionW(ls_tmp, ls_unc, ll_size)
	// Realizo la operacion de Desmapeo
	// Antes guardo la letra y unc para mapear luego
	is_letra_array[1] = ls_tmp
	is_unc_array[1] = ls_unc
	ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)
	if ll_rc = 0 then
		ls_ret="Se ha efectuado el De-Mapeo "+ls_tmp+"-"+ls_unc
		FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
	end if
end if
// Recursivamente debo llamar a ésta función para que desmapee las posibles conecciones
// previamente si existieran las guardo para reestablecerlas luego.
ls_path_desmapeo = ls_PathFin
li_hasta = 3
do while li_hasta > 0
	li_hasta = pos(ls_PathFin,'\',li_hasta)
	if li_hasta > 0 then
		ls_path_desmapeo = mid(ls_PathFin,1, li_hasta - 1)
		// Debo averiguar la 1ra posicion del vector que es nulo		
		j=UpperBound(is_letra_array)
		for i=2 to j
			if Isnull(is_letra_array[i]) then j=i
		next
		uf_desmapeo_recurso(ls_path_desmapeo,j,li_filenum_log)
		li_hasta ++
	end if
loop
// Realice los desmapeos

//* Realizo la conexion a la red con la letra seteada en el ini
ll_rc = uf_mapeo_recurso_2(ls_tmp, ls_PathFin,ls_netuser,ls_password, ls_err_str)
if ll_rc = 0 then
	ls_ret="Se ha efectuado el Mapeo "+ls_tmp+" "+ls_PathFin
	FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
else
	ls_ret="Error en el Mapeo a los servidores" 
//	FileWrite(li_filenum_log, ls_ret+"-Codigo "+String(ll_rc)+"  "+ls_tmp+" "+ls_PathFin+" "+ls_netuser+" "+ls_password+"-"+string(datetime(today(),now())))
	FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str +" - "+ls_tmp+" "+ls_PathFin+" "+ls_netuser+"-"+string(datetime(today(),now())))
	FileClose(li_filenum_log)
	MessageBox("La conexión falló",  ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str)
	GOto RESTAURO_CONECCIONES
end if

// Verifica Acceso Destino
ls_accesibilidad_destino = uf_path_accesible(ls_temppath_trabajo,ls_letra_mapeo)
ls_accesibilidad_destino = trim(ls_accesibilidad_destino)
if ls_accesibilidad_destino <> ""  then
	FileWrite(li_filenum_log, "Verificando Accesibilidad Destino - ERROR - AVISE A SISTEMAS: " + ls_accesibilidad_destino)
	Messagebox("Atención!","Error al Acceder al Directorio Destino para copia Final." + "~r~n" + ls_accesibilidad_destino, Exclamation! )
	GOto RESTAURO_CONECCIONES
else 
	//Copia archivos a destino
	wf_status("Copiando archivo "+is_temppath+"paddata.txt a directorio destino ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"paddata.txt a directorio destino ...("+string(datetime(today(),now()))+")")
	if wf_copiar_a_temp(is_temppath,"\paddata.txt",ls_PathFin,"\paddata.txt") < 0 then 	
		wf_status("Proceso abortado - Archivo paddata.txt.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado - Archivo paddata.txt. ("+string(datetime(today(),now()))+")")
		GOto RESTAURO_CONECCIONES
	end if
	wf_status("Copiando archivo "+is_temppath+"padnove.txt a directorio destino ...", "I", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padnove.txt a directorio destino ...("+string(datetime(today(),now()))+")")
	if wf_copiar_a_temp(is_temppath,"\padnove.txt",ls_PathFin,"\padnove.txt") < 0 then 	
		wf_status("Proceso abortado - Archivo padnove.txt.", "E", 0)
		FileWrite(li_filenum_log, "Proceso abortado - Archivo padnove.txt. ("+string(datetime(today(),now()))+")")
		GOto RESTAURO_CONECCIONES
	end if
//	wf_status("Copiando archivo "+is_temppath+"afipdata.txt a directorio destino ...", "I", 0)
//	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"afipdata.txt a directorio destino ...("+string(datetime(today(),now()))+")")
//	if wf_copiar_a_temp(is_temppath,"\afipdata.txt",ls_PathFin,"\afipdata.txt") < 0 then 	
//		wf_status("Proceso abortado - Archivo afipdata.txt.", "E", 0)
//		FileWrite(li_filenum_log, "Proceso abortado - Archivo afipdata.txt. ("+string(datetime(today(),now()))+")")
//		GOto RESTAURO_CONECCIONES
//	end if

	if is_proceso = 'C' then 
		wf_status("Copiando archivo "+is_temppath+"padfyj.txt a directorio destino ...", "I", 0)
		FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padfyj.txt a directorio destino ...("+string(datetime(today(),now()))+")")
		if wf_copiar_a_temp(is_temppath,"\padfyj.txt",ls_PathFin,"\padfyj.txt") < 0 then 	
			wf_status("Proceso abortado - Archivo padfyj.txt.", "E", 0)
			FileWrite(li_filenum_log, "Proceso abortado - Archivo padfyj.txt. ("+string(datetime(today(),now()))+")")
			GOto RESTAURO_CONECCIONES
		end if
	end if

	wf_status("Copiando archivos *.txt a directorio destino OK.", "F", 0)
	FileWrite(li_filenum_log, "Copiando archivo "+is_temppath+"padfyj.txt a directorio destino OK. ("+string(datetime(today(),now()))+")")
end if	
//wf_borrar_archivo(is_temppath+"padfyj.txt")
//wf_borrar_archivo(is_temppath+"paddata.txt")
//wf_borrar_archivo(is_temppath+"padnove.txt")
//wf_borrar_archivo(is_temppath+"afipdata.txt")
for i=1 to 10
	wf_borrar_archivo(ls_temppath_trabajo+"padfyj"+string(i)+".exe")
	wf_borrar_archivo(ls_temppath_trabajo+"PADFYJ"+string(i)+".TXT")
next
wf_borrar_archivo(ls_temppath_trabajo+"bajas.txt")
wf_borrar_archivo(ls_temppath_trabajo+"detalle.txt")
wf_borrar_archivo(ls_temppath_trabajo+"novedades.txt")
wf_borrar_archivo(ls_temppath_trabajo+ls_anio_mes_dia+".zip")

RESTAURO_CONECCIONES:
	// Cancelo la letra mapeada en el ini
	ll_rc = WNetCancelConnection2W(ls_tmp,1, 1)
	if ll_rc = 0 then
		ls_ret="Se ha efectuado el De-Mapeo "+ls_tmp
		FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
	end if
	
	string ls_root
	// Restauro todas las conecciones si las hubiera
	j = UpperBound(is_letra_array)
	for i=1 to j
		ls_root =  	is_letra_array[i]
		ls_unc = is_unc_array[i]
		if not isnull(ls_root) then
			ll_rc = uf_mapeo_recurso_2(ls_root, ls_unc,ls_null,ls_null, ls_err_str)
			if ll_rc = 0 then
				ls_ret="Se ha efectuado el Mapeo "+ls_root+" "+ls_unc
				FileWrite(li_filenum_log, ls_ret+"-"+string(datetime(today(),now())))
			else
				ls_ret="Error en el Mapeo a los servidores~r~n" 
				FileWrite(li_filenum_log, ls_ret+" - Codigo " + String(ll_rc) + " - " + ls_err_str + " - " + string(datetime(today(),now())))
				FileClose(li_filenum_log)
				MessageBox("La RE-conexión falló", ls_ret + "Codigo de error: " + String(ll_rc) + "~r~n" +  ls_err_str)			
			end if
		end if
	next
wf_status("PROCESO FINALIZADO.", "I", 0)
FileWrite(li_filenum_log, "PROCESO FINALIZAdo-"+string(datetime(today(),now())))
FileClose(li_filenum_log)
Commit USING sqlca;
luo_progress.SetValue(0)
dw_paddata.SetTransObject(SQLCA)
dw_paddata.Retrieve()
Setpointer (oldpointer)
end event

event ue_test_copiaimpersonalizada();//OLEObject luo_CI
//luo_CI = create OLEObject

OLEObject luo_CI
int li_codret
//string ls_userName, ls_domainName,ls_Password, ls_fileName, ls_pathNameOri, ls_pathNameDest

luo_CI = create OLEObject
li_codret = luo_CI.ConnectToNewObject("CopiaImpers.copiaImpers")

if li_codret <> 0 then
	destroy luo_CI
	messagebox("Error","error al instalar componemte OLE.")
	return
else
	luo_CI.SayHy()
	int li_test = 20
	li_test = luo_CI.AddTenToParameter(li_test)
	messagebox("Resultado: ", String(li_test))
	string ls_test 
	ls_test = luo_CI.GiveMeDate()
	messagebox("Resultado: ", ls_test)
	string ls_userName = "tix43959"
	string ls_domainName = "ARDP"
	string ls_Password = "Ito95906"
	string ls_fileName = "\padnove.txt"
	string ls_pathNameOri = "d:\CENDEU\temp"
	string ls_pathNameDest = "\\la2buadfs01\TRANSMISION\DESA\SALIDA\CENDEU"
	li_test = luo_CI.Copia_Impersonalizada(ls_userName, ls_domainName,ls_Password, ls_fileName, ls_pathNameOri, ls_pathNameDest)
	destroy luo_CI
end if
end event

event ue_test_copiaimpersonalizada2();//Function Boolean LogonUserW (string lpszUsername, String lpszDomain, string lpszPassword, Long dwLogonType, Long dwLogonProvider, REF uLong phToken) LIBRARY "advapi32.dll" 
//Function boolean ImpersonateLoggedOnUser( ulong hToken ) library "advapi32.dll;Ansi"
//Function boolean RevertToSelf() library "RevertToSelf;Ansi"
//Function long CloseHandle (long hObject) Library "kernel32"


boolean blnResult 

string userid, domain, password
long lngLogonType = 0
long lngLogonProvider = 2
ulong ilElevatedAccessHandle

blnResult = LogonUserW(userid, Domain, Password,lngLogonType,lngLogonProvider,ilElevatedAccessHandle) 
blnResult = ImpersonateLoggedOnUser(ilElevatedAccessHandle) 

//...

blnResult = RevertToSelf()
CloseHandle(ilElevatedAccessHandle)
end event

private subroutine wf_status (string ls_texto, string ls_status, long ll_rcount);/*********************************************************************************************/
// Escribe en un datawindow de la ventana el stado actual del procesamiento
// Se esta utilizando en este caso
/*********************************************************************************************/

integer ll_duracion
time lt_hora

//con el yield() permito que se chequee la cola de mensajes ante posibles eventos 
yield()

ll_duracion=0
lt_hora=now()

if right(ls_texto, 3)="..." then
	it_inicio_status=lt_hora
else
	ll_duracion=secondsafter(it_inicio_status, lt_hora)
end if

ls_texto=string(lt_hora, "hh:mm:ss") + " - " + ls_texto
if not isnull(ll_rcount) and ll_rcount>0 then
	ls_texto= ls_texto + " (" + string(ll_rcount) + " regs)"
end if
mle_status.text+= ls_texto + "~r~n"
mle_status.scroll(2000000000)

//al usar yield() debo volver a setear el puntero a HourGlass 
SetPointer(HourGlass!)
end subroutine

public function integer wf_borrar_archivo (string ls_archivo);/*********************************************************************************************/
// para renombrar/mover el archivo de interfáz a un directorio de trabajo
/*********************************************************************************************/

string ls_ret
integer li_ret
uo_external uo_ext

uo_ext = create uo_external

li_ret=0
li_ret=uo_ext.SetFileAttributesA(ls_archivo,128)
if li_ret <>1 then
	//messagebox(ls_ret,"No se pudo SETEAR "+ls_archivo+" en el directorio de trabajo")
	li_ret=-1
else
	IF not FileDelete(ls_archivo) THEN
		//messagebox(ls_ret,"No se pudo Borrar "+ls_archivo+" en el directorio de trabajo")
		li_ret=-1
	END IF
end if

destroy uo_ext

return li_ret
end function

public function integer wf_copiar_a_temp (string ls_desde, string ls_archivo_desde, string ls_hasta, string ls_archivo_hasta);/*********************************************************************************************/
// Copia el archivo de interfáz a un directorio de trabajo
// No se está utilizando en este caso
/*********************************************************************************************/

string ls_ret
integer li_ret
uo_external uo_ext

uo_ext = create uo_external

li_ret=0

ls_ret=uo_ext.copy(ls_desde + ls_archivo_desde, ls_hasta + ls_archivo_hasta, true)
if ls_ret <>"" then
	messagebox(ls_ret,"No se pudo copiar el "+ls_archivo_desde+" de datos al directorio de trabajo")
	li_ret=-1
end if


//quitar el atributo ReadOnly a los archivos seteantro a 128 = Normal
li_ret=uo_ext.SetFileAttributesA(ls_hasta + ls_archivo_hasta, 128)
if li_ret = 0 then
	messagebox(ls_ret,"No se pudo quitar el read only a "+ls_archivo_desde+" en el directorio de trabajo")
	li_ret=-1
end if

destroy uo_ext

return li_ret
end function

public function integer wf_validar_parametros ();/*********************************************************************************************/
// Valida si el archivo de interfáz se especifico
// Se utiliza en este caso
/*********************************************************************************************/
long ll_mes, ll_anio, ll_dia
string ls_path

//if isnull(is_filepath) or is_filepath="" then
//	messagebox("Atención","Debe completar el campo 'Archivo de datos'")
//	sle_archivo.setfocus()
//	return -1
//end if
//ll_dia = dec(em_dia.Text)
//ll_mes = dec(em_mes.Text)
//ll_anio = dec(em_anio.Text)
//
//if isnull(ll_dia) or ll_dia=0 or ll_dia > 31 or ll_dia < 1 then
//	messagebox("Atención","Error en el campo 'Dia' "+string(ll_dia))
//	sle_archivo.setfocus()
//	return -1
//end if
//if isnull(ll_mes) or ll_mes=0 or ll_mes > 12 or ll_mes < 1 then
//	messagebox("Atención","Error en el campo 'Mes' "+string(ll_mes))
//	sle_archivo.setfocus()
//	return -1
//end if
//if isnull(ll_anio) or ll_anio=0 or ll_anio < 2000 then
//	messagebox("Atención","Error el campo 'Año' "+string(ll_anio))
//	sle_archivo.setfocus()
//	return -1
//end if

is_anio_mes_dia = em_anio.Text + em_mes.Text + em_dia.Text
//IF is_proceso = 'S' THEN
//	ls_path = mid(ls_path,1,Pos ( ls_path, is_anio_mes_dia+".zip" , 1 )-1)
//	IF not FileExists(ls_path+is_anio_mes_dia+".zip") THEN 
//		messagebox("Atención","El nombre del archivo es incorrecto o no se encuentra.")
//		sle_archivo.setfocus()
//		return -1
//	END IF		
//END IF


if right(is_temppath,1)<>"\" then is_temppath=is_temppath + "\"
return 0
end function

public function integer wf_compactar_tabladbf (string as_nombretabla);/*******************************************************************************/
/* para compactar el archivo de una tabla dbf utilizando el comando PACK       */ 
/* y asegurarme que no este tomado lo que retorna el error indicando que el    */ 
/* archivo esta en uso                                                         */ 
/*                                                                             */
/* SQLSTATE = 37000                                                            */
/* [Microsoft][ODBC Visual FoxPro Driver]File is in use.                       */
/*                                                                             */
/* es necesario desconectarse de la base volverse a                            */
/* conectar, ejecutar el comando PACK                                          */
/*******************************************************************************/

pointer oldpointer = SetPointer(HourGlass!)
string ls_sql

disconnect using SQLCA;

SQLCA.DBMS = ProfileString(gs_aplicacion_inifile, "Database", "DBMS","")
SQLCA.Lock = "RC"
SQLCA.DbParm = ProfileString(gs_aplicacion_inifile, "Database", "DbParm", "")
Connect using SQLCA ;

if SQLCA.SQLCode <> 0 then
	uf_sql_error("Inicio de Sesión")
	return -1
end if

ls_sql = "SET EXCLUSIVE ON; PACK " + as_nombretabla
choose case as_nombretabla 
	case "padnove" 
		EXECUTE immediate "SET EXCLUSIVE ON; PACK padnove" USING sqlca;
	case "paddata"
		EXECUTE immediate "SET EXCLUSIVE ON; PACK paddata" USING sqlca;
end choose 
if sqlca.sqlcode <> 0 then
	uf_sql_error("Compactando archivo de tabla")
	RollBack USING sqlca;
	setpointer (oldpointer)
	Return -1
else
	Commit USING sqlca;
end if	

EXECUTE immediate "SET EXCLUSIVE OFF" USING sqlca;

//disconnect using SQLCA;
//SQLCA.DBMS = ProfileString(gs_aplicacion_inifile, "Database", "DBMS","")
//SQLCA.Lock = "RC"
//SQLCA.DbParm = ProfileString(gs_aplicacion_inifile, "Database", "DbParm", "")
//Connect using SQLCA ;

return 0
end function

on w_sheet_migrar_afip.create
this.ole_xceedzip=create ole_xceedzip
this.dw_paddata=create dw_paddata
this.st_dia=create st_dia
this.em_dia=create em_dia
this.st_proceso=create st_proceso
this.st_path=create st_path
this.sle_path=create sle_path
this.st_anio=create st_anio
this.st_mes=create st_mes
this.em_anio=create em_anio
this.em_mes=create em_mes
this.st_1=create st_1
this.sle_errores=create sle_errores
this.st_5=create st_5
this.mle_import=create mle_import
this.st_4=create st_4
this.cb_cancelar_proceso=create cb_cancelar_proceso
this.st_3=create st_3
this.mle_status=create mle_status
this.luo_progress=create luo_progress
this.cb_procesar=create cb_procesar
this.st_2=create st_2
this.cb_buscar=create cb_buscar
this.sle_archivo=create sle_archivo
this.gb_1=create gb_1
this.em_regs=create em_regs
this.gb_2=create gb_2
this.Control[]={this.ole_xceedzip,&
this.dw_paddata,&
this.st_dia,&
this.em_dia,&
this.st_proceso,&
this.st_path,&
this.sle_path,&
this.st_anio,&
this.st_mes,&
this.em_anio,&
this.em_mes,&
this.st_1,&
this.sle_errores,&
this.st_5,&
this.mle_import,&
this.st_4,&
this.cb_cancelar_proceso,&
this.st_3,&
this.mle_status,&
this.luo_progress,&
this.cb_procesar,&
this.st_2,&
this.cb_buscar,&
this.sle_archivo,&
this.gb_1,&
this.em_regs,&
this.gb_2}
end on

on w_sheet_migrar_afip.destroy
destroy(this.ole_xceedzip)
destroy(this.dw_paddata)
destroy(this.st_dia)
destroy(this.em_dia)
destroy(this.st_proceso)
destroy(this.st_path)
destroy(this.sle_path)
destroy(this.st_anio)
destroy(this.st_mes)
destroy(this.em_anio)
destroy(this.em_mes)
destroy(this.st_1)
destroy(this.sle_errores)
destroy(this.st_5)
destroy(this.mle_import)
destroy(this.st_4)
destroy(this.cb_cancelar_proceso)
destroy(this.st_3)
destroy(this.mle_status)
destroy(this.luo_progress)
destroy(this.cb_procesar)
destroy(this.st_2)
destroy(this.cb_buscar)
destroy(this.sle_archivo)
destroy(this.gb_1)
destroy(this.em_regs)
destroy(this.gb_2)
end on

event open;//en caso que utilice un directorio temporal tomado del .ini para dejar el archivo de log 
//este dir temp pudo ser leido del ini al momento de loguearse y haber sido guardado en 
//una var global
//
//is_temppath = gs_temppath

//en este caso se toma el temporal idem al de entrada de la interfáz


cb_cancelar_proceso.enabled = False
//Para cuando utilizao un recurso compartido con el path completo
//sle_path.Text = "\\" + gs_hostname + "\" + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "RecursoCompartido","") + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "Path","")
sle_path.Text = ProfileString(gs_aplicacion_inifile, "CONSTANTES", "RecursoCompartido","") + ProfileString(gs_aplicacion_inifile, "CONSTANTES", "Path","")


is_proceso = Message.StringParm	
IF is_proceso = 'C' THEN
	st_proceso.Text = "Proceso CUATRIMESTRAL"
ELSEIF is_proceso = 'S' THEN	
	st_proceso.Text = "Proceso SEMANAL"
END IF
dw_paddata.SetTransObject(SQLCA)
dw_paddata.Retrieve()

ib_ret = ole_xceedzip.Object.License("ZIP60-D57K2-S7UCA-G8NA")
if not ib_ret then
	MessageBox("Error", "Licencia no aceptada. " + "ZIP60-D57K2-S7UCA-G8NA")
end if
end event

event activate;//m_frame.m_edicion.m_buscar.Visible = True
//m_frame.m_edicion.m_buscar.ToolbarItemVisible = True
//m_frame.m_archivo.m_procesar.Visible = True
//m_frame.m_archivo.m_procesar.ToolbarItemVisible = True


end event

event close;//uf_iniciamenu()
end event

type ole_xceedzip from olecustomcontrol within w_sheet_migrar_afip
event listingfile ( string sfilename,  string scomment,  long lsize,  long lcompressedsize,  integer ncompressionratio,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber,  boolean bexcluded,  integer xreason )
event previewingfile ( string sfilename,  string ssourcefilename,  long lsize,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  boolean bexcluded,  integer xreason )
event insertdisk ( long ldisknumber,  ref boolean bdiskinserted )
event zippreprocessingfile ( ref string sfilename,  ref string scomment,  string ssourcefilename,  long lsize,  ref integer xattributes,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  ref integer xmethod,  ref boolean bencrypted,  ref string spassword,  ref boolean bexcluded,  integer xreason,  boolean bexisting )
event unzippreprocessingfile ( string sfilename,  string scomment,  ref string sdestfilename,  long lsize,  long lcompressedsize,  ref integer xattributes,  long lcrc,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  integer xmethod,  boolean bencrypted,  ref string spassword,  long ldisknumber,  ref boolean bexcluded,  integer xreason,  boolean bexisting,  ref integer xdestination )
event skippingfile ( string sfilename,  string scomment,  string sfilenameondisk,  long lsize,  long lcompressedsize,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  integer xreason )
event removingfile ( string sfilename,  string scomment,  long lsize,  long lcompressedsize,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted )
event testingfile ( string sfilename,  string scomment,  long lsize,  long lcompressedsize,  integer ncompressionratio,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber )
event filestatus ( string sfilename,  long lsize,  long lcompressedsize,  long lbytesprocessed,  integer nbytespercent,  integer ncompressionratio,  boolean bfilecompleted )
event globalstatus ( long lfilestotal,  long lfilesprocessed,  long lfilesskipped,  integer nfilespercent,  long lbytestotal,  long lbytesprocessed,  long lbytesskipped,  integer nbytespercent,  long lbytesoutput,  integer ncompressionratio )
event disknotempty ( ref integer xaction )
event processcompleted ( long lfilestotal,  long lfilesprocessed,  long lfilesskipped,  long lbytestotal,  long lbytesprocessed,  long lbytesskipped,  long lbytesoutput,  integer ncompressionratio,  integer xresult )
event zipcomment ( ref string scomment )
event querymemoryfile ( ref long lusertag,  ref string sfilename,  ref string scomment,  ref integer xattributes,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  ref boolean bencrypted,  ref string spassword,  ref boolean bfileprovided )
event zippingmemoryfile ( long lusertag,  string sfilename,  ref any vadatatocompress,  ref boolean bendofdata )
event unzippingmemoryfile ( string sfilename,  any vauncompresseddata,  boolean bendofdata )
event warning ( string sfilename,  integer xwarning )
event invalidpassword ( string sfilename,  ref string snewpassword,  ref boolean bretry )
event replacingfile ( string sfilename,  string scomment,  long lsize,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  string sorigfilename,  long lorigsize,  integer xorigattributes,  datetime dtoriglastmodified,  datetime dtoriglastaccessed,  datetime dtorigcreated,  ref boolean breplacefile )
event zipcontentsstatus ( long lfilestotal,  long lfilesread,  integer nfilespercent )
event deletingfile ( string sfilename,  long lsize,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  ref boolean bdonotdelete )
event convertpreprocessingfile ( string sfilename,  ref string scomment,  ref string sdestfilename,  long lsize,  long lcompressedsize,  ref integer xattributes,  long lcrc,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber,  ref boolean bexcluded,  integer xreason,  boolean bexisting )
event listingfile64 ( string sfilename,  string scomment,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  integer ncompressionratio,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber,  boolean bexcluded,  integer xreason )
event previewingfile64 ( string sfilename,  string ssourcefilename,  long lsizelow,  long lsizehigh,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  boolean bexcluded,  integer xreason )
event zippreprocessingfile64 ( ref string sfilename,  ref string scomment,  string ssourcefilename,  long lsizelow,  long lsizehigh,  ref integer xattributes,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  ref integer xmethod,  ref boolean bencrypted,  ref string spassword,  ref boolean bexcluded,  integer xreason,  boolean bexisting )
event unzippreprocessingfile64 ( string sfilename,  string scomment,  ref string sdestfilename,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  ref integer xattributes,  long lcrc,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  integer xmethod,  boolean bencrypted,  ref string spassword,  long ldisknumber,  ref boolean bexcluded,  integer xreason,  boolean bexisting,  ref integer xdestination )
event skippingfile64 ( string sfilename,  string scomment,  string sfilenameondisk,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  integer xreason )
event removingfile64 ( string sfilename,  string scomment,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted )
event testingfile64 ( string sfilename,  string scomment,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  integer ncompressionratio,  integer xattributes,  long lcrc,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber )
event filestatus64 ( string sfilename,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  long lbytesprocessedlow,  long lbytesprocessedhigh,  integer nbytespercent,  integer ncompressionratio,  boolean bfilecompleted )
event globalstatus64 ( long lfilestotal,  long lfilesprocessed,  long lfilesskipped,  integer nfilespercent,  long lbytestotallow,  long lbytestotalhigh,  long lbytesprocessedlow,  long lbytesprocessedhigh,  long lbytesskippedlow,  long lbytesskippedhigh,  integer nbytespercent,  long lbytesoutputlow,  long lbytesoutputhigh,  integer ncompressionratio )
event processcompleted64 ( long lfilestotal,  long lfilesprocessed,  long lfilesskipped,  long lbytestotallow,  long lbytestotalhigh,  long lbytesprocessedlow,  long lbytesprocessedhigh,  long lbytesskippedlow,  long lbytesskippedhigh,  long lbytesoutputlow,  long lbytesoutputhigh,  integer ncompressionratio,  integer xresult )
event replacingfile64 ( string sfilename,  string scomment,  long lsizelow,  long lsizehigh,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  string sorigfilename,  long lorigsizelow,  long lorigsizehigh,  integer xorigattributes,  datetime dtoriglastmodified,  datetime dtoriglastaccessed,  datetime dtorigcreated,  ref boolean breplacefile )
event deletingfile64 ( string sfilename,  long lsizelow,  long lsizehigh,  integer xattributes,  datetime dtlastmodified,  datetime dtlastaccessed,  datetime dtcreated,  ref boolean bdonotdelete )
event convertpreprocessingfile64 ( string sfilename,  ref string scomment,  ref string sdestfilename,  long lsizelow,  long lsizehigh,  long lcompressedsizelow,  long lcompressedsizehigh,  ref integer xattributes,  long lcrc,  ref datetime dtlastmodified,  ref datetime dtlastaccessed,  ref datetime dtcreated,  integer xmethod,  boolean bencrypted,  long ldisknumber,  ref boolean bexcluded,  integer xreason,  boolean bexisting )
event writingzipcontentsstatus ( integer nfilespercent )
event movingtempfilestatus ( integer nbytespercent )
integer x = 3026
integer y = 512
integer width = 146
integer height = 128
integer taborder = 90
borderstyle borderstyle = stylelowered!
boolean focusrectangle = false
string binarykey = "w_sheet_migrar_afip.win"
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
end type

event globalstatus(long lfilestotal, long lfilesprocessed, long lfilesskipped, integer nfilespercent, long lbytestotal, long lbytesprocessed, long lbytesskipped, integer nbytespercent, long lbytesoutput, integer ncompressionratio);em_regs.text = String(lfilesprocessed)
sle_errores.text = String (lfilestotal)
//sle_porcentaje.text = String(nBytesPercent)
luo_progress.SetValue(nBytesPercent)
end event

type dw_paddata from datawindow within w_sheet_migrar_afip
integer x = 1874
integer y = 1208
integer width = 1632
integer height = 752
integer taborder = 130
string title = "none"
string dataobject = "dw_paddata"
boolean vscrollbar = true
boolean border = false
boolean livescroll = true
end type

type st_dia from statictext within w_sheet_migrar_afip
integer x = 169
integer y = 172
integer width = 151
integer height = 84
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Dia:"
boolean focusrectangle = false
end type

type em_dia from editmask within w_sheet_migrar_afip
integer x = 343
integer y = 172
integer width = 146
integer height = 84
integer taborder = 10
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 16777215
alignment alignment = center!
borderstyle borderstyle = stylelowered!
string mask = "00"
string minmax = "1~~12"
end type

type st_proceso from statictext within w_sheet_migrar_afip
integer x = 251
integer y = 36
integer width = 887
integer height = 104
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 16711680
long backcolor = 67108864
boolean focusrectangle = false
end type

type st_path from statictext within w_sheet_migrar_afip
integer x = 1362
integer y = 316
integer width = 667
integer height = 76
integer textsize = -10
integer weight = 700
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long backcolor = 77571519
boolean enabled = false
string text = "Ubicación de Archivos"
boolean focusrectangle = false
end type

type sle_path from singlelineedit within w_sheet_migrar_afip
integer x = 1371
integer y = 408
integer width = 1477
integer height = 92
integer taborder = 50
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long backcolor = 33554431
boolean enabled = false
boolean displayonly = true
borderstyle borderstyle = stylelowered!
boolean hideselection = false
end type

type st_anio from statictext within w_sheet_migrar_afip
integer x = 855
integer y = 172
integer width = 151
integer height = 84
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Año:"
boolean focusrectangle = false
end type

type st_mes from statictext within w_sheet_migrar_afip
integer x = 512
integer y = 172
integer width = 151
integer height = 84
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Mes:"
boolean focusrectangle = false
end type

type em_anio from editmask within w_sheet_migrar_afip
integer x = 1029
integer y = 172
integer width = 192
integer height = 84
integer taborder = 30
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 16777215
alignment alignment = center!
borderstyle borderstyle = stylelowered!
string mask = "0000"
end type

type em_mes from editmask within w_sheet_migrar_afip
integer x = 686
integer y = 172
integer width = 146
integer height = 84
integer taborder = 20
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 16777215
alignment alignment = center!
borderstyle borderstyle = stylelowered!
string mask = "00"
string minmax = "1~~12"
end type

type st_1 from statictext within w_sheet_migrar_afip
integer x = 2679
integer y = 852
integer width = 242
integer height = 72
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Errores:"
boolean focusrectangle = false
end type

type sle_errores from singlelineedit within w_sheet_migrar_afip
integer x = 2930
integer y = 852
integer width = 334
integer height = 72
integer taborder = 100
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 79741120
boolean border = false
boolean autohscroll = false
boolean displayonly = true
end type

type st_5 from statictext within w_sheet_migrar_afip
integer x = 46
integer y = 1592
integer width = 896
integer height = 68
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Resultados de la importación: "
boolean focusrectangle = false
end type

type mle_import from multilineedit within w_sheet_migrar_afip
integer x = 37
integer y = 1672
integer width = 1755
integer height = 304
integer taborder = 120
integer textsize = -8
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
boolean hscrollbar = true
boolean vscrollbar = true
boolean autohscroll = true
boolean autovscroll = true
boolean displayonly = true
borderstyle borderstyle = stylelowered!
end type

type st_4 from statictext within w_sheet_migrar_afip
integer x = 1911
integer y = 852
integer width = 247
integer height = 72
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Leídos:"
boolean focusrectangle = false
end type

type cb_cancelar_proceso from commandbutton within w_sheet_migrar_afip
boolean visible = false
integer x = 2770
integer y = 432
integer width = 517
integer height = 92
integer taborder = 70
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
string text = "Cancelar proceso"
end type

event clicked;ib_cancelar=true
end event

type st_3 from statictext within w_sheet_migrar_afip
integer x = 37
integer y = 508
integer width = 649
integer height = 68
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Status del proceso:"
boolean focusrectangle = false
end type

type mle_status from multilineedit within w_sheet_migrar_afip
integer x = 37
integer y = 588
integer width = 1755
integer height = 944
integer taborder = 110
integer textsize = -8
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
boolean hscrollbar = true
boolean vscrollbar = true
boolean autohscroll = true
boolean autovscroll = true
boolean displayonly = true
borderstyle borderstyle = stylelowered!
end type

type luo_progress from uo_progress within w_sheet_migrar_afip
integer x = 1911
integer y = 972
integer width = 1362
integer height = 56
boolean border = true
borderstyle borderstyle = stylelowered!
end type

on luo_progress.destroy
call uo_progress::destroy
end on

event valuechanged;//em_regs.text=string(oldvalue)
end event

type cb_procesar from commandbutton within w_sheet_migrar_afip
integer x = 1874
integer y = 596
integer width = 517
integer height = 92
integer taborder = 60
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
string text = "Procesar"
end type

event clicked;//parent.TriggerEvent ('ue_procesar')
//parent.TriggerEvent ('ue_test_pack')
parent.TriggerEvent ('ue_test_copiaImpersonalizada')
end event

type st_2 from statictext within w_sheet_migrar_afip
integer x = 1362
integer y = 56
integer width = 539
integer height = 84
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
boolean enabled = false
string text = "Archivo de datos:"
boolean focusrectangle = false
end type

type cb_buscar from commandbutton within w_sheet_migrar_afip
integer x = 2917
integer y = 144
integer width = 398
integer height = 92
integer taborder = 40
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
string text = "Buscar ..."
end type

event clicked;parent.TriggerEvent ('ue_buscar')
end event

type sle_archivo from singlelineedit within w_sheet_migrar_afip
integer x = 1371
integer y = 144
integer width = 1477
integer height = 92
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 79741120
boolean enabled = false
boolean displayonly = true
borderstyle borderstyle = stylelowered!
end type

type gb_1 from groupbox within w_sheet_migrar_afip
integer x = 1330
integer width = 2053
integer height = 288
integer textsize = -10
integer weight = 400
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
end type

type em_regs from editmask within w_sheet_migrar_afip
integer x = 2167
integer y = 852
integer width = 430
integer height = 72
integer taborder = 80
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 79741120
string text = "none"
boolean border = false
alignment alignment = right!
string mask = "###,###,###"
end type

type gb_2 from groupbox within w_sheet_migrar_afip
integer x = 1874
integer y = 748
integer width = 1435
integer height = 304
integer taborder = 90
integer textsize = -10
integer weight = 700
fontcharset fontcharset = ansi!
fontpitch fontpitch = variable!
fontfamily fontfamily = swiss!
string facename = "Arial"
long textcolor = 33554432
long backcolor = 67108864
string text = "Avance del proceso de conversion"
end type


Start of PowerBuilder Binary Data Section : Do NOT Edit
06w_sheet_migrar_afip.bin 
2700000a00e011cfd0e11ab1a1000000000000000000000000000000000003003e0009fffe000000060000000000000000000000010000000100000000000010000000000200000001fffffffe0000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffdfffffffefffffffefffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff006f00520074006f004500200074006e00790072000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000050016ffffffffffffffff00000001000000000000000000000000000000000000000000000000000000006dbacd9001d1d59400000003000002000000000000500003004f0042005800430054005300450052004d0041000000000000000000000000000000000000000000000000000000000000000000000000000000000102001affffffff00000002ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000f600000000004200500043004f00530058004f00540041005200450047000000000000000000000000000000000000000000000000000000000000000000000000000000000001001affffffffffffffff00000003db79769011d240e06000d59b72e32a08000000006dbaa68001d1d5946dbacd9001d1d594000000000000000000000000006f00430074006e006e00650073007400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001020012ffffffffffffffffffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000004000000f600000000000000010000000200000003fffffffe000000050000000600000007fffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
28ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000030000020008000000000006000300080000000000020003000000000000001800030008000000000002000800000000000200070000000000004000000000000007924080000003414600000000000000030003000000000000ffff000b0000000b0000000b0000000b0000000b0000000b0002000800000000ffff000b0002000800000000000200080000000000020003000300000000000a0000000b0000000b0002000800000000000200080000000000020008000000000000000300080000000000020008000000000002000b000000080000000000020008000000000002000800000000000200080000000000020000000000000000000000000000030000020008000000000006000300080000000000020003000000000000001800030008000000000002000800000000000200070000000000004000000000000007924080000003414600000000000000030003000000000000ffff000b0000000b0000000b0000000b0000000b0000000b0002000800000000ffff000b0002000800000000000200080000000000020003000300000000000a0000000b0000000b0002000800000000000200080000000000020008000000000000000300080000000000020008000000000002000b00000008000000000002000800000000000200080000000000020008000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
16w_sheet_migrar_afip.bin 
End of PowerBuilder Binary Data Section : No Source Expected After This Point
