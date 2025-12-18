file(GLOB TEST_SOURCES "*.cpp")

add_executable(crypto_tests ${TEST_SOURCES})

target_link_libraries(crypto_tests PRIVATE
        crypto_lib
        GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(crypto_tests)