@echo off
REM ============================================
REM  Atexec.cpp 编译脚本 (TDM-GCC)
REM  支持多种编译模式
REM ============================================

setlocal enabledelayedexpansion

echo ============================================
echo   Atexec.cpp Compilation Script
echo   Using TDM-GCC (g++)
echo ============================================
echo.

REM 检查 g++ 是否可用
where g++ >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Error: g++ not found in PATH
    echo [!] Please install TDM-GCC first:
    echo [!] https://jmeubank.github.io/tdm-gcc/
    pause
    exit /b 1
)

REM 显示 g++ 版本
echo [*] Detected compiler:
g++ --version | findstr /C:"g++"
echo.

REM 选择编译模式
echo Select compilation mode:
echo [1] Standard Build (Default)
echo [2] Optimized Build (O2, smaller and faster)
echo [3] Minimal Size Build (Os, smallest)
echo [4] Debug Build (with debug symbols)
echo [5] Custom Build
echo.
set /p choice="Enter your choice (1-5, default=1): "

if "%choice%"=="" set choice=1

REM 基础编译参数
set LIBS=-lole32 -loleaut32 -luuid -ltaskschd -lmpr -lws2_32 -ladvapi32 -static-libgcc -static-libstdc++
set SOURCE=atexec.cpp
set OUTPUT=atexec.exe

REM 根据选择设置编译参数
if "%choice%"=="1" (
    echo [*] Building with: Standard mode
    set CXXFLAGS=-std=c++11 -municode
    set OUTPUT=atexec.exe
)

if "%choice%"=="2" (
    echo [*] Building with: Optimized mode (O2)
    set CXXFLAGS=-std=c++11 -municode -O2 -s -DNDEBUG
    set OUTPUT=atexec_optimized.exe
)

if "%choice%"=="3" (
    echo [*] Building with: Minimal size mode (Os)
    set CXXFLAGS=-std=c++11 -municode -Os -s -DNDEBUG -ffunction-sections -fdata-sections -Wl,--gc-sections
    set OUTPUT=atexec_mini.exe
)

if "%choice%"=="4" (
    echo [*] Building with: Debug mode
    set CXXFLAGS=-std=c++11 -municode -g -O0
    set OUTPUT=atexec_debug.exe
)

if "%choice%"=="5" (
    echo [*] Custom build mode
    echo [!] Note: Remember to include -municode for Unicode support
    set /p CXXFLAGS="Enter custom CXXFLAGS (e.g., -std=c++11 -municode -O3): "
    set /p OUTPUT="Enter output filename (e.g., atexec_custom.exe): "
)

echo.
echo [*] Compilation settings:
echo     Source: %SOURCE%
echo     Output: %OUTPUT%
echo     Flags:  %CXXFLAGS%
echo     Libs:   %LIBS%
echo.

REM 编译
echo [*] Compiling...
g++ %CXXFLAGS% %SOURCE% -o %OUTPUT% %LIBS%

REM 检查编译结果
if %errorlevel% equ 0 (
    echo.
    echo [+] Compilation successful!
    echo [+] Output: %OUTPUT%
    
    REM 显示文件信息
    if exist %OUTPUT% (
        echo.
        echo [*] File information:
        dir %OUTPUT% | findstr /C:"%OUTPUT%"
        
        REM 询问是否压缩
        echo.
        set /p compress="Do you want to compress with UPX? (y/n, default=n): "
        if /i "!compress!"=="y" (
            where upx >nul 2>&1
            if !errorlevel! equ 0 (
                echo [*] Compressing with UPX...
                upx --best %OUTPUT%
                if !errorlevel! equ 0 (
                    echo [+] Compression successful!
                    dir %OUTPUT% | findstr /C:"%OUTPUT%"
                ) else (
                    echo [-] Compression failed!
                )
            ) else (
                echo [!] UPX not found in PATH
                echo [!] Download from: https://upx.github.io/
            )
        )
        
        REM 询问是否测试
        echo.
        set /p test="Do you want to test the executable? (y/n, default=n): "
        if /i "!test!"=="y" (
            echo.
            echo [*] Running: %OUTPUT%
            %OUTPUT%
            echo.
        )
    )
) else (
    echo.
    echo [-] Compilation failed!
    echo [-] Please check the error messages above.
    pause
    exit /b 1
)

echo.
echo ============================================
echo   Build process completed!
echo ============================================
echo.
pause

