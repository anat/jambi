@echo off
set NAME=jambi
mode con cols=80
mode con lines=25 
copy .\test\orig\*.exe .\test\ > nul
copy .\test\orig\*.scr .\test\ > nul

if exist %NAME%.ilk del %NAME%.ilk > nul
if exist %NAME%.pdb del %NAME%.pdb > nul
if exist %NAME%.obj del %NAME%.obj > nul
if exist %NAME%.exe del %NAME%.exe > nul

%MASM2%\masm32\bin\ml /Zi /c /coff /nologo %NAME%.asm
%MASM2%\masm32\bin\link /DEBUG /NOLOGO /SUBSYSTEM:CONSOLE %NAME%.obj

if exist %NAME%.obj del %NAME%.obj > nul

REM %NAME%.exe > out.txt
copy .\%NAME%.exe .\test\%NAME%.exe > nul
cd test
%NAME%.exe
REM del .\%NAME%.exe

echo %errorlevel%
REM pause
REM .\test\a.exe

pause