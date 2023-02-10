@echo off
REM --------------------------------------------------------
REM Copyright (C) 2021 Splunk Inc. All Rights Reserved.
REM --------------------------------------------------------

setlocal EnableDelayedExpansion

REM Get the current date and time into a variable
for /f "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /value 2^>nul`) do if '.%%i.'=='.LocalDateTime.' set date_time=%%j
set date_time=%date_time:~0,4%-%date_time:~4,2%-%date_time:~6,2% %date_time:~8,2%:%date_time:~10,2%:%date_time:~12,6%

REM Get the Tasklist command output and store array with pid and processname
for /f "tokens=1,2 delims=," %%T in ('tasklist /nh  /fo csv') do (
     set topic[%%~U]=%%~T
)

REM Get the list of open ports by running netstat and filtering the results to those that contain actual ports (dropping the header)
for /f "tokens=*" %%G in ('netstat -nao ^| findstr /r "LISTENING"') do (call :output_ports "%%G")
goto :eof

:output_ports

	REM Parse the ports list
	for /f "tokens=1,2,4,5 delims= " %%A in (%1) do (
		set protocol=%%A
		set dest=%%B
		set status=%%C
		set pid=%%D
		set appname=!topic[%%D]!
	)

	REM Skip the header
	if "!protocol!"=="Proto" goto :eof
	if "!protocol!"=="Active" goto :eof

	REM Parse the each port
	for /f "tokens=1,2,3 delims=:" %%A in ("%dest%") do (
		set dest_ip=%%A
		set dest_port=%%B
		set alt_dest_port=%%C

		REM Some entries will exist in the [::]:0 format and thus throw off the parsing. Correct for this:
		if "!dest_port!" == "]" set dest_port=!alt_dest_port!
	)

	REM Replace the dest IP with the empty IP range if necessary
	if "!dest_ip!"=="[" set dest_ip=[::]

	REM Print out the result
	echo %date_time% transport=%protocol% dest_ip=%dest_ip% dest_port=%dest_port% pid=!pid! appname=%appname%
