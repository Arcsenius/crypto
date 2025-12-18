#!/bin/bash
set -e

# Определяем пути
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# Цвета (минимум, для читаемости логов)
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 1. Запускаем сборку (передаем аргументы, например --clean)
source "$SCRIPT_DIR/build.sh" "$@"

# Переходим в папку сборки
cd "$PROJECT_ROOT/build"

echo -e "\n${CYAN}=== [LAUNCH] Setting up environment... ===${NC}"
INPUT_FILE="secret_data.txt"
ENC_FILE="data.enc"
DEC_FILE="data.dec"

# Текст сообщения
echo "System check: strict execution mode. No animations allowed." > $INPUT_FILE

# Параметры (можно менять тут)
MODE="CBC"
ALGO="DES"
PADDING="PKCS7"
KEY="admin_key"

echo "Configuration: Algo=${ALGO}, Mode=${MODE}, Padding=${PADDING}"

# 2. Запуск Шифрования
echo -e "${CYAN}=== [LAUNCH] Encrypting... ===${NC}"
./bin/lab1 $MODE $ALGO $PADDING $KEY $INPUT_FILE $ENC_FILE enc

# 3. Запуск Дешифрования
echo -e "${CYAN}=== [LAUNCH] Decrypting... ===${NC}"
./bin/lab1 $MODE $ALGO $PADDING $KEY $ENC_FILE $DEC_FILE dec

# 4. Строгая проверка
echo -e "${CYAN}=== [LAUNCH] Verifying Integrity... ===${NC}"

if cmp -s "$INPUT_FILE" "$DEC_FILE"; then
    echo -e "${GREEN}[OK] Files match exactly.${NC}"

    # Выводим содержимое для контроля
    echo "---------------------------------------------------"
    echo "Input:  $(cat $INPUT_FILE)"
    echo "Output: $(cat $DEC_FILE)"
    echo "---------------------------------------------------"
else
    echo -e "${RED}[ERROR] Files do not match!${NC}"
    echo "Input size: $(stat -c%s $INPUT_FILE) bytes"
    echo "Dec size:   $(stat -c%s $DEC_FILE) bytes"
    exit 1
fi