@echo off
setlocal ENABLEDELAYEDEXPANSION
set CONSOLE_MODE=1


REM call :test_vuln_env_path
call :test_vuln_scheduled_tasks

pause
goto :eof


REM ==========================  VULN MODULES ========================== 
	
REM Test if the path in the environment PATH variable are writable
REM Return 1 if at least one path is writable, 0 else. Return -1 if something wrong happen (to implement)
:test_vuln_env_path
	setlocal
	set MODULE_NAME=TEST_ENV_PATH_TEST
	set START_FLAG=####################   STARTING PATH VAR ANALYZE   #####################
	set END_FLAG=#####################   END OF PATH VAR ANALYZE   #####################
	set allPathProcessed=true
	set /A it=1
	
	if %CONSOLE_MODE%==1 echo %START_FLAG%
	:bcl_env_path
	set allPathProcessed=true
	for /F "delims=; tokens=%it%" %%i in ("%PATH%") do (
		set allPathProcessed=false
		call :test_write_rights "%%i"
		if !ERRORLEVEL! NEQ -1 call :process_scan_results_module "%MODULE_NAME%" "%%i" "!ERRORLEVEL!"
		set /A it=1+%it%
		if %it%==100 goto :end_test_vuln_env_path
	)
	if !allPathProcessed!==false goto :bcl_env_path
	if %CONSOLE_MODE%==1 echo %END_FLAG%
	endlocal
	EXIT /B 0
	:end_test_vuln_env_path
		call :error_log_module "%MODULE_NAME%" "Error when calling the module"
		endlocal
		EXIT /B -1


REM Test if group of criticals path are writable
REM Return 1 if at least one path is writable, 0 else. Return -1 if something wrong happen (to implement)
:test_vuln_criticals_local_path
	setlocal
	set MODULE_NAME=TEST_CRITICAL_PATH	

	for %%i in
	(

	REM #### CRITICALS PATH HERE ####

	) do (
		call :test_write_rights %%i
		if !ERRORLEVEL! NEQ -1 call :process_scan_results_module "%MODULE_NAME%" "%%i" "!ERRORLEVEL!"
	)
	
	:end_test_vuln_criticals_local_path
	call :error_log_module "%MODULE_NAME%" "Error when calling the module"
	endlocal
	EXIT /B -1
	
	

REM  Test if the path use for scheduled tasks are writable 
:test_vuln_scheduled_tasks
	setlocal
	set MODULE_NAME=TEST_SCHEDULED_TASKS
	set START_FLAG=####################   STARTING SCHEDULED TASKS ANALYZE   #####################
	set END_FLAG=#####################   END OF SCHEDULED TASKS ANALYZE   #####################
	set FILE_PATH=sch_analyse.txt
	if %CONSOLE_MODE%==1 echo %START_FLAG%
	schtasks /Query /XML | findstr /R "^.*<Command>.*$" >%FILE_PATH%
	for /F "delims=" %%i IN (sch_analyse.txt) do (
		set path_to_clear=%%i
		set path_to_clear=!path_to_clear:   =!
		set path_to_clear=!path_to_clear:^<Command^>=!
		set path_to_clear=!path_to_clear:^</Command^>=!
		set path_task=!path_to_clear:"=!
		REM RAF/TODO : Suppression du nom de fichier pour tester le chemin
		REM ================
		REM ICI
		REM ================
		call :test_write_rights "!path_task!"
		call :process_scan_results_module "%MODULE_NAME%" "!path_task!" "!ERRORLEVEL!"
	)
	REM del %FILE_PATH%
	if %CONSOLE_MODE%==1 echo %END_FLAG%
	endlocal
	EXIT /B 0
	:end_test_vuln_modulename
	call :error_log_module "%MODULE_NAME%" "Error when calling the module"
	endlocal
	EXIT /B -1



	
REM  ==== <PATERN VULN MODULE> ====
:test_vuln_modulename
	setlocal
	set MODULE_NAME=TEST_MODULENAME
	
	
	

	:end_test_vuln_modulename
		call :error_log_module "%MODULE_NAME%" "Error when calling the module"
		endlocal
		EXIT /B -1


REM  === </PATERN VULN MODULE > ==== 

REM ==========================  SECONDARY MODULES ========================== 	

REM Test if a path is writable
REM Input : path to test
REM Output : 1 if the path is writable, 0 else, -1 if something wrong happen
:test_write_rights
	setlocal
	set MODULE_NAME=TEST_WRITE_RIGHTS
	set WRITED_FOLDER_NAME_TEST=data_WOW64
	set PATH_TEST_WRITE_RIGHTS=%~1
	
	mkdir "%PATH_TEST_WRITE_RIGHTS%\%WRITED_FOLDER_NAME_TEST%">nul 2>nul
	if !ERRORLEVEL!==1 (
		endlocal
		EXIT /B 0
	)
	if !ERRORLEVEL!==0 (
		rd "%PATH_TEST_WRITE_RIGHTS%\%WRITED_FOLDER_NAME_TEST%"
		endlocal
		EXIT /B 1
	)
	:end_test_write_rights
	call :error_log_module "%MODULE_NAME%" "Error when testing the write rights with folder %PATH_TEST_WRITE_RIGHTS%"
	endlocal
	EXIT /B -1


REM Get the scan result of a module and send it on the adapted output with the good format
REM Input:	module name
REM			module message
REM			scan result : success 1  /  fail 0
REM Output:	0, -1 if something wrong happen		
:process_scan_results_module
	setlocal
	set MODULE_NAME=PROCESS_SCAN_RESULTS_MODULE
	set VULN_INDICATION=[VULN]
	set PROTECTED_INDICATION=[PROTECTED]
	set VULN_FILENAME=vuln.txt
	set PROTECTED_FILENAME=protected.txt
	set VULN_MODULE_TO_PROCESS=%~1
	set VULN_MODULE_MESSAGE=%~2
	set VULN_MODULE_RESULT=%~3
	if %VULN_MODULE_RESULT%==0 (
		call :output_writing_module "%PROTECTED_INDICATION%[%VULN_MODULE_TO_PROCESS%]%VULN_MODULE_MESSAGE%" "%PROTECTED_FILENAME%"
		endlocal
		EXIT /B 0
	)
	if %VULN_MODULE_RESULT%==1 (
		call :output_writing_module "%VULN_INDICATION%[%VULN_MODULE_TO_PROCESS%]%VULN_MODULE_MESSAGE%" "%VULN_FILENAME%"
		endlocal
		EXIT /B 0
	)
	:end_process_scan_results_module
	call :error_log_module "%MODULE_NAME%" "Error when processing data with parent module %VULN_MODULE_TO_PROCESS% with module message %VULN_MODULE_MESSAGE%"
	endlocal
	EXIT /B -1

	
REM Write a content on different output stream
REM It's only use for the main messages (like vuln results)
REM Input:	message to write
REM			file destination for the output
REM Output:	0: success
REM			1: error while writing in the output file  (to implement)
REM			-1: something wrong happen
:output_writing_module
	setlocal
	set MODULE_NAME=OUTPUT_WRITING_MODULE
	set CONSOLE_OUTPUT=1
	set OUTPUT_MESSAGE=%~1
	set OUTPUT_FILE=%~2
	if %CONSOLE_OUTPUT%==1 echo %OUTPUT_MESSAGE%
	echo %OUTPUT_MESSAGE%>>%OUTPUT_FILE%
	if !ERRORLEVEL!==0 EXIT /B 0
	:end_output_writing_module
	call :error_log_module "%MODULE_NAME%" "Error when calling the module with message : '%OUTPUT_MESSAGE%' and destination file '%OUTPUT_FILE%' "
	endlocal
	EXIT /B -1
	

REM Write error messages in the error file
REM Input:	name of the module where the error happen
REM			error message
REM Output:	0 or -1 if something wrong happen
:error_log_module
	setlocal
	set MODULE_NAME=error_log_module
	set ERROR_FILE=err.log
	set ERROR_MODULE_NAME=%~1
	set ERROR_MESSAGE=%~2
	echo %ERROR_MODULE_NAME%	Error :   %ERROR_MESSAGE%>>err.log
	if !ERRORLEVEL!==0 EXIT /B 0
	:end_error_module
	call :error_log_module "%MODULE_NAME%", "Error when calling the module with module name '%ERROR_MODULE_NAME%' and error message '%ERROR_MESSAGE%'"
	endlocal
	EXIT /B -1

	
	
:eof
EXIT 0