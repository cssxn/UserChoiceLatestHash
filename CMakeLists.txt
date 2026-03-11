cmake_minimum_required(VERSION 3.16)

project(UserChoiceLatestHash LANGUAGES CXX)

add_executable(UserChoiceLatestHash
    main.cpp
    HashTables.cpp
    HashCodec.cpp
    RegistryContext.cpp
    Cli.cpp
)

target_compile_features(UserChoiceLatestHash PRIVATE cxx_std_98)

target_compile_definitions(UserChoiceLatestHash PRIVATE UNICODE _UNICODE)

target_include_directories(UserChoiceLatestHash PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(UserChoiceLatestHash PRIVATE
    advapi32
    crypt32
)

if(MSVC)
    target_compile_options(UserChoiceLatestHash PRIVATE /W4 /EHsc)
else()
    target_compile_options(UserChoiceLatestHash PRIVATE -Wall -Wextra -pedantic)
endif()

