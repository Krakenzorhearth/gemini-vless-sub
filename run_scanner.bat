@echo off
cd /d "%~dp0"

echo [%DATE% %TIME%] Запуск сканирования... >> scan_log.txt

:: Запуск сканера с абсолютным путем к Python
"C:\Users\Nitro\AppData\Local\Programs\Python\Python311\python.exe" main_2.py >> scan_log.txt 2>&1

:: Синхронизация и отправка только файлов подписок
git pull origin main >> scan_log.txt 2>&1
git add sub.txt sub_base64.txt >> scan_log.txt 2>&1
git diff-index --quiet HEAD || git commit -m "Auto-update Gemini working servers (Local Scan)" >> scan_log.txt 2>&1
git push origin main >> scan_log.txt 2>&1

echo [%DATE% %TIME%] Завершено. >> scan_log.txt