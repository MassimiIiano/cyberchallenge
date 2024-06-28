#!/usr/bin/bash

DB_SECRET=$(hexdump -vn16 -e'4/4 "%08X" 1 "\n"' /dev/urandom);
TOKEN_KEY=$(hexdump -vn8 -e'4/4 "%08X" 1 "\n"' /dev/urandom);

if [[ ! -f ".env" ]]
then
    echo "DB_SECRET=${DB_SECRET}" >> .env
    echo "TOKEN_KEY=${TOKEN_KEY}" >> .env
fi

docker compose up --build --remove-orphans -d