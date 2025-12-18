#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# Цвета
CYAN='\033[0;36m'
GREEN='\033[0;32m'
NC='\033[0m'

# Сборка
source "$SCRIPT_DIR/build.sh" "$@"

cd "$PROJECT_ROOT/build"

echo -e "\n${CYAN}=== [LAB 6] FROG Cipher Demo ===${NC}"
INPUT="frog_in.txt"
ENC="frog.enc"
DEC="frog.dec"

echo "FROG is a polymorphic cipher with variable key size!" > $INPUT

# Params
KEY="frog_secret_key"
MODE="CBC"
PAD="PKCS7"

echo -e "Encrypting with FROG ($MODE)..."
./bin/lab6 $MODE $PAD $KEY $INPUT $ENC enc

echo -e "Decrypting..."
./bin/lab6 $MODE $PAD $KEY $ENC $DEC dec

if cmp -s "$INPUT" "$DEC"; then
    echo -e "${GREEN}[SUCCESS] Files match!${NC}"
    echo "Decrypted text: $(cat $DEC)"
else
    echo -e "\033[0;31m[FAIL] Mismatch!${NC}"
    exit 1
fi