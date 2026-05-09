@echo off
setlocal
pushd "%~dp0"

echo [1/3] Locating Visual Studio build environment...
if defined VSINSTALLDIR (
    set "VS_VCVARS=%VSINSTALLDIR%VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
) else if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" (
    set "VS_VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
)

if not defined VS_VCVARS (
    echo ERROR: Could not find vcvars64.bat. Please run from a Visual Studio developer command prompt or set VSINSTALLDIR.
    popd
    exit /b 1
)

echo [2/3] Initializing build tools...
call "%VS_VCVARS%" >nul
if errorlevel 1 (
    echo ERROR: Failed to initialize Visual Studio build tools.
    popd
    exit /b 1
)

echo [3/3] Building UserChoiceLatestHash.exe...
cl /nologo /EHsc /W4 /TP /c main.cpp HashTables.cpp HashCodec.cpp RegistryContext.cpp Cli.cpp
if errorlevel 1 (
    echo ERROR: Compilation failed.
    popd
    exit /b 1
)
link /NOLOGO /OUT:UserChoiceLatestHash.exe main.obj HashTables.obj HashCodec.obj RegistryContext.obj Cli.obj advapi32.lib crypt32.lib
if errorlevel 1 (
    echo ERROR: Link failed.
    popd
    exit /b 1
)

echo [4/4] Packaging output to UserChoiceLatestHash.zip...
powershell -NoProfile -Command "Compress-Archive -Force -Path 'UserChoiceLatestHash.exe','README.md','LICENSE','*.h','*.cpp','*.inc' -DestinationPath 'UserChoiceLatestHash.zip'"
if errorlevel 1 (
    echo WARNING: Packaging failed, but build succeeded.
    popd
    exit /b 1
)

echo Build and packaging complete.
echo Output: %~dp0UserChoiceLatestHash.exe
echo Package: %~dp0UserChoiceLatestHash.zip
popd
exit /b 0
