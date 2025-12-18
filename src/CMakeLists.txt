file(GLOB_RECURSE CRYPTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")

add_library(crypto_lib STATIC ${CRYPTO_SOURCES})

target_include_directories(crypto_lib PUBLIC
        "${CMAKE_SOURCE_DIR}/include"
)

target_link_libraries(crypto_lib PUBLIC TBB::tbb Boost::headers)

find_package(Threads REQUIRED)
target_link_libraries(crypto_lib PRIVATE Threads::Threads)