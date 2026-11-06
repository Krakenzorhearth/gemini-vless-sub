@echo off
cd /d "%~dp0"

:: 1. Запуск сканера
python main_2.py

:: 2. Обновление локальной базы с GitHub
git pull --rebase origin main

:: 3. Добавление измененных файлов в Git
git add sub.txt sub_base64.txt

:: 4. Создание коммита (только если файлы изменились)
git diff-index --quiet HEAD || git commit -m "Auto-update Gemini working servers (Local Scan)"

:: 5. Отправка изменений на сервер
git push origin main
pause