#!/bin/bash
set -e

# Определяем пути
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# Цвета
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Запускаем сборку
source "$SCRIPT_DIR/build.sh" "$@"

cd "$PROJECT_ROOT/build"

echo -e "\n${CYAN}=== [LAB 2] Setting up RSA Demo... ===${NC}"
INPUT_FILE="rsa_test.txt"
ENC_FILE="rsa_test.enc"

# Создаем файл побольше (чтобы было несколько блоков RSA)
# 1024 бита ключ = 128 байт. Блок данных ~117 байт.
# Напишем строку длиной около 300 байт.
echo "RSA is an asymmetric cryptographic algorithm. This implies that there are two separate keys: one public and one private. The public key is used for encryption and the private key is used for decryption. We are testing file processing with PKCS#1 padding which allows secure block encryption." > $INPUT_FILE

# Параметры
KEY_SIZE=1024
MODE="demo" # В коде main.cpp 'demo' делает Gen->Enc->Dec

echo "Configuration: KeySize=${KEY_SIZE} bits"

# 2. Запуск (Режим demo сам делает Enc и Dec)
echo -e "${CYAN}=== [LAB 2] Running RSA Demo (Gen -> Enc -> Dec)... ===${NC}"
./bin/lab2 $KEY_SIZE $INPUT_FILE $ENC_FILE $MODE

# 3. Проверка
DEC_FILE="${ENC_FILE}.dec" # main.cpp в режиме demo добавляет .dec

echo -e "${CYAN}=== [LAB 2] Verifying Integrity... ===${NC}"

if cmp -s "$INPUT_FILE" "$DEC_FILE"; then
    echo -e "${GREEN}[OK] Decrypted file matches original exactly!${NC}"
    echo "---------------------------------------------------"
    echo "Original size:  $(stat -c%s $INPUT_FILE) bytes"
    echo "Encrypted size: $(stat -c%s $ENC_FILE) bytes (Larger due to padding)"
    echo "---------------------------------------------------"
else
    echo -e "${RED}[ERROR] Files do not match!${NC}"
    exit 1
fi