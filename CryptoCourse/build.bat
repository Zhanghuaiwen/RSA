@echo off
REM 使用 Dev-Cpp 自带 MinGW64 的 g++ 编译本课程设计（无需外部 NTL，已内置兼容的 NTL::ZZ 大整数库）
set GPP="D:\Dev-Cpp\MinGW64\bin\g++.exe"
set SRC=bigint.cpp utils.cpp rsa.cpp elgamal.cpp certificate.cpp pki.cpp entity.cpp securemail.cpp test.cpp main.cpp
%GPP% -O2 -std=c++11 -o CryptoCourse.exe %SRC%
if %errorlevel%==0 (echo BUILD OK) else (echo BUILD FAILED)
pause
