#!/bin/bash
set -e

# Определяем пути
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# --- COLORS ---
GREEN='\033[0;32m'
BRIGHT_GREEN='\033[1;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

# Прячем курсор при прерывании Ctrl+C
trap "tput cnorm; exit" INT TERM

# --- 1. Функция анимации Матрицы ---
function matrix_rain() {
    echo -e "\033[2J\033[H" # Очистка экрана
    echo -e "${GREEN}"
    tput civis # Скрыть курсор

    local lines=$(tput lines)
    local cols=$(tput cols)

    # Массив капель
    declare -a drops
    for (( c=0; c<cols; c++ )); do drops[$c]=$((RANDOM % lines * -1)); done

    # Крутим 100 кадров
    for (( frame=0; frame<100; frame++ )); do
        for (( c=0; c<cols; c+=2 )); do
            local y=${drops[$c]}

            # Голова капли (яркая)
            if [[ $y -ge 0 && $y -lt $lines ]]; then
                tput cup $y $c
                echo -ne "${BRIGHT_GREEN}$(printf "\\x$(printf %x $((RANDOM%90+33)))")${GREEN}"
            fi

            # Хвост капли
            if [[ $((y-1)) -ge 0 && $((y-1)) -lt $lines ]]; then
                tput cup $((y-1)) $c
                echo -ne "${GREEN}$(printf "\\x$(printf %x $((RANDOM%90+33)))")"
            fi

            # Стираем хвост
            if [[ $((y-5)) -ge 0 && $((y-5)) -lt $lines ]]; then
                tput cup $((y-5)) $c
                echo -ne " "
            fi

            drops[$c]=$((y+1))

            # Респавн
            if [[ ${drops[$c]} -gt $((lines + 5)) ]]; then
                 if [[ $((RANDOM % 10)) -gt 8 ]]; then
                    drops[$c]=$((RANDOM % 10 * -1))
                 fi
            fi
        done
        # Небольшая задержка
        # sleep 0.01
    done

    tput cnorm
    echo -e "${NC}"
    echo -e "\033[2J\033[H"
}

# --- 2. Функция эффекта расшифровки ---
function decrypt_effect() {
    local text="$1"
    local len=${#text}
    local chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"

    tput civis
    echo -ne "${BRIGHT_GREEN}"

    # Центрируем текст (примерно)
    local row=10
    local col=10

    for (( i=0; i<=len; i++ )); do
        for (( k=0; k<2; k++ )); do
            tput cup $row $((col + i))
            echo -n "${chars:$((RANDOM%${#chars})):1}"

            # Мусор
            for (( j=i+1; j<len; j++ )); do
                 echo -n "${chars:$((RANDOM%${#chars})):1}"
            done

            tput cup $row $col
            echo -n "${text:0:i}"

            sleep 0.01
        done
    done

    tput cup $row $col
    echo -e "${text}${NC}"
    tput cnorm
    echo ""
    echo ""
}

# ==========================================
# ОСНОВНАЯ ЛОГИКА
# ==========================================

# 1. Запускаем сборку
source "$SCRIPT_DIR/build.sh" "$@"

# Переходим в папку сборки
cd "$PROJECT_ROOT/build"

echo -e "${CYAN}=== [LAB 1] Preparing Demo Data... ===${NC}"
INPUT_FILE="secret_data.txt"
ENC_FILE="data.enc"
DEC_FILE="data.dec"

# Сообщение
echo "The Matrix has you..." > $INPUT_FILE

# Параметры
MODE="CBC"
ALGO="DES"
PADDING="PKCS7"
KEY="neo_key"

echo -e "Config: ${BRIGHT_GREEN}$ALGO + $MODE + $PADDING${NC}"

# 2. Шифрование
echo -e "${CYAN}=== [LAB 1] Encrypting... ===${NC}"
./bin/lab1 $MODE $ALGO $PADDING $KEY $INPUT_FILE $ENC_FILE enc

# 3. Дешифрование
echo -e "${CYAN}=== [LAB 1] Decrypting... ===${NC}"
./bin/lab1 $MODE $ALGO $PADDING $KEY $ENC_FILE $DEC_FILE dec

# 4. Проверка и Анимация
if cmp -s "$INPUT_FILE" "$DEC_FILE"; then

    # === ЗАПУСК АНИМАЦИИ ===
    sleep 0.5
    matrix_rain
    decrypt_effect "SUCCESS: SYSTEM SECURITY VERIFIED."

    echo -e "${CYAN}Original:${NC} $(cat $INPUT_FILE)"
    echo -e "${CYAN}Result:  ${NC} $(cat $DEC_FILE)"
else
    echo -e "\033[0;31mFAILURE: Decryption mismatch!${NC}"
    exit 1
fi