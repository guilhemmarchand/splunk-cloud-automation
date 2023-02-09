@echo off
REM --------------------------------------------------------
REM Copyright (C) 2021 Splunk Inc. All Rights Reserved.
REM --------------------------------------------------------

setlocal EnableDelayedExpansion

REM Get the last current time synchronization status
REM
REM Example:
REM
REM     Successful sync:
REM         Last Successful Sync Time: 1/22/2014 12:06:43 PM
REM     Unsuccessful sync:
REM         Last Successful Sync Time: unspecified

REM Get the date & time
for /f "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /value 2^>nul`) do if '.%%i.'=='.LocalDateTime.' set date_time=%%j
set date_time=%date_time:~0,4%-%date_time:~4,2%-%date_time:~6,2% %date_time:~8,2%:%date_time:~10,2%:%date_time:~12,6%

REM Print the date and time. This will be the timestamp of the event.
echo Current time: %date_time%

REM Print the Windows time service status
w32tm /query /status /verbose

REM Print the time zone
w32tm /tz
