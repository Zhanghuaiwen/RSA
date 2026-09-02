@echo off
REM Build script for the CryptoCourse project.
REM It uses the g++ shipped with Dev-Cpp MinGW64 and links against the
REM official NTL 11.5.1 installed at D:\Dev-Cpp\MinGW64
REM   headers: D:\Dev-Cpp\MinGW64\include\NTL
REM   library: D:\Dev-Cpp\MinGW64\lib\libntl.a
REM Only -lntl is needed when linking; no self-made big integer module any more.
REM NOTE: keep this file free of non-ASCII text, because cmd parses a batch
REM       file with the GBK code page and multi-byte characters may break it.
REM NOTE: the script switches to the "src" folder next to itself, so it can be
REM       double-clicked from anywhere.
set GPP="D:\Dev-Cpp\MinGW64\bin\g++.exe"
cd /d "%~dp0src"
set SRC=utils.cpp rsa.cpp elgamal.cpp certificate.cpp pki.cpp entity.cpp securemail.cpp test.cpp main.cpp
%GPP% -O2 -std=c++11 -o CryptoCourse.exe %SRC% -lntl
if %errorlevel%==0 (echo BUILD OK) else (echo BUILD FAILED)
pause
