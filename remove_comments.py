#!/usr/bin/env python3
"""
Аккуратный удалитель комментариев для C++ проекта
Удаляет однострочные и многострочные комментарии, сохраняя строковые литералы
"""

import os
import re
import sys
from pathlib import Path

class CommentRemover:
    def __init__(self):
        # Регулярные выражения для поиска комментариев и строковых литералов
        self.string_pattern = re.compile(r'(".*?(?<!\\)"|\'.*?(?<!\\)\')')
        self.single_line_pattern = re.compile(r'//.*$')
        self.multi_line_pattern = re.compile(r'/\*.*?\*/', re.DOTALL)

    def remove_comments(self, content):
        """Удаляет комментарии, сохраняя строковые литералы"""
        lines = content.split('\n')
        result_lines = []
        in_multiline_comment = False
        multiline_buffer = []
        multiline_start = -1

        for i, line in enumerate(lines):
            if in_multiline_comment:
                # Ищем конец многострочного комментария
                end_index = line.find('*/')
                if end_index != -1:
                    # Конец комментария найден
                    in_multiline_comment = False
                    # Сохраняем часть строки после комментария
                    line = line[end_index + 2:]
                    multiline_buffer = []
                else:
                    # Продолжаем внутри комментария
                    multiline_buffer.append(line)
                    continue

            # Обрабатываем строку вне многострочного комментария
            processed_line = line

            # Защищаем строковые литералы
            string_matches = list(self.string_pattern.finditer(processed_line))
            protected_ranges = []

            for match in string_matches:
                protected_ranges.append((match.start(), match.end()))

            # Удаляем однострочные комментарии вне строковых литералов
            single_comment_pos = processed_line.find('//')
            if single_comment_pos != -1:
                # Проверяем, не находится ли комментарий внутри строкового литерала
                in_string = False
                for start, end in protected_ranges:
                    if start <= single_comment_pos < end:
                        in_string = True
                        break

                if not in_string:
                    processed_line = processed_line[:single_comment_pos]

            # Обрабатываем многострочные комментарии
            start_pos = 0
            while True:
                # Ищем начало многострочного комментария
                start_index = processed_line.find('/*', start_pos)
                if start_index == -1:
                    break

                # Проверяем, не находится ли начало комментария внутри строкового литерала
                in_string = False
                for start, end in protected_ranges:
                    if start <= start_index < end:
                        in_string = True
                        break

                if not in_string:
                    # Ищем конец комментария в той же строке
                    end_index = processed_line.find('*/', start_index)
                    if end_index != -1:
                        # Удаляем комментарий из строки
                        processed_line = processed_line[:start_index] + processed_line[end_index + 2:]
                        continue
                    else:
                        # Начинается многострочный комментарий
                        in_multiline_comment = True
                        multiline_buffer.append(processed_line[start_index:])
                        processed_line = processed_line[:start_index]
                        break
                else:
                    start_pos = start_index + 2

            # Добавляем обработанную строку, если она не пустая или содержит код
            stripped_line = processed_line.rstrip()
            if stripped_line or processed_line.startswith(' ') or processed_line.startswith('\t'):
                result_lines.append(stripped_line)

        return '\n'.join(result_lines)

    def process_file(self, filepath):
        """Обрабатывает один файл"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            cleaned_content = self.remove_comments(content)

            # Записываем обратно только если есть изменения
            if cleaned_content != content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(cleaned_content)
                return True
            return False
        except Exception as e:
            print(f"Ошибка при обработке {filepath}: {e}")
            return False

def find_cpp_files(root_dir):
    """Находит все C++ файлы в проекте"""
    extensions = {'.cpp', '.hpp', '.h', '.cc', '.cxx', '.hh', '.hxx'}
    files = []

    for root, dirs, filenames in os.walk(root_dir):
        # Пропускаем каталоги .git и build
        if '.git' in dirs:
            dirs.remove('.git')
        if 'build' in dirs:
            dirs.remove('build')
        if 'cmake-build' in dirs:
            dirs.remove('cmake-build')

        for filename in filenames:
            if Path(filename).suffix in extensions:
                files.append(os.path.join(root, filename))

    return files

def backup_file(filepath):
    """Создает backup файла"""
    backup_path = filepath + '.backup'
    try:
        import shutil
        shutil.copy2(filepath, backup_path)
        return True
    except Exception as e:
        print(f"Не удалось создать backup для {filepath}: {e}")
        return False

def main():
    if len(sys.argv) != 2:
        print("Использование: python remove_comments.py <путь_к_проекту>")
        print("Пример: python remove_comments.py ./my_project")
        sys.exit(1)

    project_path = sys.argv[1]

    if not os.path.exists(project_path):
        print(f"Путь {project_path} не существует!")
        sys.exit(1)

    print(f"Поиск C++ файлов в {project_path}...")
    files = find_cpp_files(project_path)

    if not files:
        print("C++ файлы не найдены!")
        sys.exit(0)

    print(f"Найдено {len(files)} файлов")

    # Создаем общий backup
    backup_dir = os.path.join(project_path, 'backup_before_comment_removal')
    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)
        print(f"Создана папка для backup: {backup_dir}")

    remover = CommentRemover()
    processed_count = 0

    for filepath in files:
        print(f"Обработка: {filepath}")

        # Создаем backup
        backup_success = backup_file(filepath)
        if not backup_success:
            print(f"  Предупреждение: не удалось создать backup для {filepath}")

        # Обрабатываем файл
        if remover.process_file(filepath):
            processed_count += 1
            print(f"  ✓ Комментарии удалены")
        else:
            print(f"  ⓘ Нет комментариев или ошибка")

    print(f"\nОбработка завершена!")
    print(f"Обработано файлов: {processed_count}/{len(files)}")
    print(f"Backup файлов сохранен в: {backup_dir}")

if __name__ == "__main__":
    main()