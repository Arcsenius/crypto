#!/bin/bash
set -e

# Определяем пути
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."
cd "$PROJECT_ROOT"

# Цвета
BLUE='\033[0;34m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${BLUE}=== [BUILD] Preparing Build Directory... ===${NC}"

# Если передан флаг --clean, удаляем build
if [[ "$1" == "--clean" ]]; then
    rm -rf build
    echo -e "${BLUE}=== [BUILD] Cleaned previous build ===${NC}"
fi

if [ ! -d "build" ]; then
    mkdir build
fi
cd build

echo -e "${BLUE}=== [BUILD] Configuring CMake (Release)... ===${NC}"
cmake -DCMAKE_BUILD_TYPE=Release .. > /dev/null

echo -e "${BLUE}=== [BUILD] Compiling... ===${NC}"
if cmake --build . -j$(nproc); then
    echo -e "${GREEN}=== [BUILD] Compilation Successful! ===${NC}"
else
    echo -e "\033[0;31m=== [BUILD] Compilation Failed! ===\033[0m"
    exit 1
fi