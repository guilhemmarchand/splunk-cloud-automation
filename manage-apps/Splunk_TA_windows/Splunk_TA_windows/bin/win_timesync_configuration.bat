@echo off
REM --------------------------------------------------------
REM Copyright (C) 2021 Splunk Inc. All Rights Reserved.
REM --------------------------------------------------------

setlocal EnableDelayedExpansion

REM Get the time service configuration and timezone.

REM Get the date & time
for /f "usebackq tokens=1,2 delims==" %%i in (`wmic os get LocalDateTime /value 2^>nul`) do if '.%%i.'=='.LocalDateTime.' set date_time=%%j
set date_time=%date_time:~0,4%-%date_time:~4,2%-%date_time:~6,2% %date_time:~8,2%:%date_time:~10,2%:%date_time:~12,6%

REM Print the date and time. This will be the timestamp of the event.
echo Current time: %date_time%

REM Print the Windows time service configuration
w32tm /query /configuration /verbose

REM Print the Windows time zone information
w32tm /tz
