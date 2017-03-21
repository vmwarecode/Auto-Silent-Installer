cd %~dp0
set sfld=%~dp0
set sdrv=%sfld:~0,2%
set cdrv=%CD:~0,2%
if not "%sdrv%"=="%cdrv%" (%sdrv%)
powershell -ExecutionPolicy ByPass -file %~n0.ps1 %*

REM pause
exit
