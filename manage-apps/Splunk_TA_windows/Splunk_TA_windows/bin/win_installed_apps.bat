@echo off
REM --------------------------------------------------------
REM Copyright (C) 2021 Splunk Inc. All Rights Reserved.
REM --------------------------------------------------------

setlocal EnableDelayedExpansion

REM For each app key, print out the name of the app and any parameters under the entry
for /f "tokens=*" %%G in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" ^| findstr "Uninstall\\"') do (call :output_reg "%%G" 72)

REM Do the same as above but with 32-bit apps, first checking if the key exists
reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
  for /f "tokens=*" %%G in ('reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall" ^| findstr "Uninstall\\"') do (call :output_reg "%%G" 84)
)

goto :eof

:output_reg


	REM Echo an empty line to indicate that this is a new entry
	@echo.

	REM Get the current date and time into into a variable
	for /f "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /value 2^>nul`) do if '.%%i.'=='.LocalDateTime.' set date_time=%%j
	set date_time=%date_time:~0,4%-%date_time:~4,2%-%date_time:~6,2% %date_time:~8,2%:%date_time:~10,2%:%date_time:~12,6%

	REM Print out the date & time
	@echo %date_time%

	REM Add the enumerated key
	@echo Installed application enumerated from %1

	REM Get the name of the app from the last segment in the registry path
	set app_name=%1

	REM Strips out the first x characters (from input) of the path in order to get just the app name
	set "app_name=!app_name:~%2%,150!"

	REM Strip the last quote
	set "app_name=!app_name:~0,-1!"

	REM Store a count value so that we can avoid printing the first entry
	set count=0

	REM This variable determines if the display name was found
	set display_name_found=0

	REM Now get the sub-keys
        for /F "tokens=1,2*" %%A in ('reg query %1') do (
           set /a count+=1

        REM Skip the entry if it just repeats the name we are querying for or if it is blank or if is "<NO" (which indicates the item has no name)

        REM Note that the display name was already found
           if %%A==DisplayName (
              set /a display_name_found=1
              echo %%A="%%C"
           ) else (

             REM Skip the entry if it just repeats the name we are querying for or if it is blank or if is "<NO" (which indicates the item has no name)
             if not "%%A" == %1 if not "%%A" == "" if not "%%A" == "<NO" if not "%%C" == "" if not %%A==DisplayName echo %%A=%%C
           )
        )
	REM If the display name was not found, then use the name of the registry path name instead
	if !display_name_found!==0 echo DisplayName="%app_name%"
