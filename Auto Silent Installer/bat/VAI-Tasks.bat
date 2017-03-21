cd %~dp0

powershell -ExecutionPolicy ByPass -file %~n0.ps1 %*

pause
REM exit
