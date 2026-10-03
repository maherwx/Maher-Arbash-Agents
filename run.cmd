@echo off
set SCOPE=%~1
set RULES=%~2
if "%SCOPE%"=="" set SCOPE=examples\scope.yaml
if "%RULES%"=="" set RULES=examples\rules.yaml
python -m pip install -e .
maher-bounty run --scope "%SCOPE%" --rules "%RULES%"
pause
