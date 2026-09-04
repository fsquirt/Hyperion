@echo off
setlocal

:: 1. 使用 call 调用环境初始化脚本，环境变量会直接作用于当前窗口
call "D:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"

:: 2. 切换到当前批处理所在目录（防止路径漂移）
cd /d "%~dp0"

:: 3. 执行编译
msbuild VBSRemoteDetect.vcxproj /p:Configuration=Release /p:Platform=x64

endlocal
