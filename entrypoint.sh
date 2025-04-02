#!/bin/sh

# Проверяем, существует ли корневой сертификат, если нет - создаем
if [ ! -f "/app/ca.crt" ] || [ ! -f "/app/ca.key" ]; then
    echo "Генерируем корневой сертификат..."
    /app/gen_ca.sh
fi

# Проверяем, существует ли общий ключ для сертификатов хостов
if [ ! -f "/app/cert.key" ]; then
    echo "Генерируем общий ключ..."
    openssl genrsa -out /app/cert.key 2048
fi

# Запуск основного приложения
exec python /app/main.py
