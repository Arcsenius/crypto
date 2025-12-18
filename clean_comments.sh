#!/bin/bash

# Скрипт для безопасной очистки комментариев в C++ проекте

set -e  # Выход при ошибке

PROJECT_DIR="${1:-.}"
BACKUP_DIR="${PROJECT_DIR}/backup_before_comment_removal"

echo "=== Очистка комментариев в C++ проекте ==="
echo "Проект: ${PROJECT_DIR}"
echo ""

# Проверяем Python
if ! command -v python3 &> /dev/null; then
    echo "Ошибка: python3 не найден!"
    exit 1
fi

# Проверяем скрипт
if [ ! -f "remove_comments.py" ]; then
    echo "Скрипт remove_comments.py не найден в текущей директории!"
    echo "Создайте его с помощью приведенного выше кода."
    exit 1
fi

# Предупреждение
echo "ВАЖНО: Этот скрипт удалит все комментарии из C++ файлов."
echo "Будут созданы backup копии файлов."
echo ""
read -p "Продолжить? (y/N): " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Отменено."
    exit 0
fi

# Запускаем Python скрипт
python3 remove_comments.py "$PROJECT_DIR"

echo ""
echo "=== Проверка кода ==="

# Проверяем, есть ли файлы для проверки
if command -v cppcheck &> /dev/null; then
    echo "Запуск cppcheck для проверки синтаксиса..."
    find "$PROJECT_DIR" -name "*.cpp" -o -name "*.hpp" -o -name "*.h" | head -5 | xargs -I {} cppcheck --quiet {} 2>&1 | head -20
fi

echo ""
echo "=== Рекомендации ==="
echo "1. Проверьте изменения в git: git diff"
echo "2. Соберите проект: cmake -B build && cmake --build build"
echo "3. Протестируйте основные функции"
echo "4. Если есть проблемы, восстановите файлы из папки ${BACKUP_DIR}"
echo ""
echo "Для отмены всех изменений выполните:"
echo "  git checkout .  # если используете git"
echo "Или восстановите из backup:"
echo "  cp ${BACKUP_DIR}/* ./ 2>/dev/null || true"