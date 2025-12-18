add_executable(lab1 main.cpp)

# Просто линкуем crypto_lib.
# Пути к хедерам и зависимость TBB подтянутся автоматически!
target_link_libraries(lab1 PRIVATE crypto_lib)