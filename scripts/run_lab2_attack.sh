#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."
source "$SCRIPT_DIR/build.sh"

cd "$PROJECT_ROOT/build"

echo -e "\n\033[0;34m=== [LAB 2] Running Wiener Attack Test ===\033[0m"

# Для режима attack файлы не важны, передадим заглушки
./bin/lab2 1024 dummy.txt dummy.out attack