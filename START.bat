start cmd.exe /c gradlew.bat build ^&^& gradlew.bat :secure-silver-module:run

@echo =============================================
@echo   Wait for SSM to run and then press ENTER.
@echo =============================================

pause
CALL gradlew.bat :benchmark:run
pause
