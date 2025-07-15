@echo off
echo Building Secure File Transfer Protocol...

REM Create clean build directory
echo Cleaning build directory...
if exist build rd /s /q build
mkdir build

REM Compile all Java files
echo Compiling Java files...
javac -d build src\common\*.java src\client\*.java src\server\*.java

if %ERRORLEVEL% equ 0 (
    echo Build successful! Files compiled to build directory.
    echo To run the server: java -cp build server.Server
    echo To run the client: java -cp build client.ClientUI
) else (
    echo Build failed. See error messages above.
    exit /b 1
)
