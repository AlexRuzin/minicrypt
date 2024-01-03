#!/bin/bash

TESTCRYPT_PATH="../bin/testcrypt"
CRYPT_PATH="../bin/crypt"

echo "[+] Building app $TESTCRYPT_PATH and $CRYPT_PATH..."
sleep 1
cd src
make

sleep 1
if [ ! -f "$TESTCRYPT_PATH" ] && [ ! -f "$CRYPT_PATH" ]; then
    echo "[!] Binaries not found. Please run: cd ../src; make first"
    exit 1
fi

echo "[+] Running tests..."
cd ../test
./test.sh