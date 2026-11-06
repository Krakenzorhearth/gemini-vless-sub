@echo off
cd /d "%~dp0"

:: Запускаем скрипт и перенаправляем весь вывод (ошибки и успехи) в файл log.txt в этой же папке
echo [%DATE% %TIME%] Запуск сканирования... >> scan_log.txt
python main_2.py >> scan_log.txt 2>&1

git stash >> scan_log.txt 2>&1
git pull origin main >> scan_log.txt 2>&1
git add sub.txt sub_base64.txt >> scan_log.txt 2>&1
git diff-index --quiet HEAD || git commit -m "Auto-update Gemini working servers (Local Scan)" >> scan_log.txt 2>&1
git push origin main >> scan_log.txt 2>&1

echo [%DATE% %TIME%] Завершено. >> scan_log.txt