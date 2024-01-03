#!/bin/bash

TESTCRYPT_PATH="../bin/testcrypt"
CRYPT_PATH="../bin/crypt"

generate_random_ascii_string() {
    local MAX_LENGTH=4096
    local LENGTH=$1

    if (( LENGTH > MAX_LENGTH )); then
        echo "Error: Requested length exceeds the maximum limit of $MAX_LENGTH characters."
        return 1
    fi

    local RANDOM_STRING=$(head /dev/urandom | tr -dc 'A-Za-z0-9' | head -c $LENGTH)

    echo "$RANDOM_STRING"
}

# Check that the binaries exist
if [ ! -f "$TESTCRYPT_PATH" ] && [ ! -f "$CRYPT_PATH" ]; then
    echo "[!] Binaries not found. Please run: cd ../src; make first"
    exit 1
fi

# Random key used
CRYPT_KEY_LEN=64
CRYPT_KEY=$(generate_random_ascii_string $CRYPT_KEY_LEN)

# Random buffer used to validate encryption
RANDOM_BUF_SIZE=2048
RANDOM_BUF=$(generate_random_ascii_string $RANDOM_BUF_SIZE)

# Run the testcrypt app
echo "[+] Running testcrypt..."
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:../lib
sleep 2
$TESTCRYPT_PATH
sleep 2

echo "[+] Using random key: "$CRYPT_KEY
CRYPT_KEY_PATH="../test_files/test.key"
echo "[+] Writing key to: "$CRYPT_KEY_PATH
echo "$CRYPT_KEY" > "$CRYPT_KEY_PATH"

CRYPT_OUT_FILE="../test_files/out.dat"
CRYPT_IN_FILE="../test_files/in.dat"
CRYPT_INPUT_BUFFER=$(generate_random_ascii_string $RANDOM_BUF_SIZE)
>$CRYPT_IN_FILE
echo "$CRYPT_INPUT_BUFFER" > "$CRYPT_IN_FILE"

echo "[+] Generated random buffer: $CRYPT_IN_FILE"
md5sum $CRYPT_IN_FILE

echo "[+] Testing crypt with key, input with file and output to file" 
>$CRYPT_OUT_FILE
echo "crypt -k $CRYPT_KEY -o $CRYPT_OUT_FILE $CRYPT_IN_FILE"
$CRYPT_PATH -k $CRYPT_KEY -o $CRYPT_OUT_FILE $CRYPT_IN_FILE
sleep 2

#cat $CRYPT_OUT_FILE
echo "[+] Inverting encryption, sending to stdout"
echo "crypt -k $CRYPT_KEY $CRYPT_OUT_FILE"
$CRYPT_PATH -k $CRYPT_KEY $CRYPT_OUT_FILE

echo "[+] Tests successful"