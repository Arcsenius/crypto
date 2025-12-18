#!/bin/bash
set -e

# Определяем пути
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
PROJECT_ROOT="$SCRIPT_DIR/.."

# 1. Запускаем сборку (передаем аргументы, например --clean)
source "$SCRIPT_DIR/build.sh" "$@"

# Возвращаемся в корень (build.sh переходит в build)
cd "$PROJECT_ROOT/build"

echo -e "\n${BLUE}=== [TESTS] Running Google Test Suite for Lab 1... ===${NC}"


if ./bin/crypto_tests; then
    echo -e "\n${GREEN}✔ ALL TESTS PASSED!${NC}"
else
    echo -e "\n\033[0;31m✘ SOME TESTS FAILED!${NC}"
    exit 1
fi