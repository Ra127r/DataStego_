cmake_minimum_required(VERSION 3.16)
project(DataStego VERSION 1.1.0 LANGUAGES CXX)

option(DATASTEGO_BUILD_TESTS "Build algorithm and integration tests" ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(datastego_core
    src/CryptoEngine.cpp
    src/ImageHandler.cpp
    src/StegoEngine.cpp
    src/ContainerFormat.cpp
    src/FileIO.cpp)
target_include_directories(datastego_core PUBLIC include)
if(WIN32)
    target_link_libraries(datastego_core PUBLIC advapi32)
endif()
if(MSVC)
    target_compile_options(datastego_core PRIVATE /W4 /utf-8)
else()
    target_compile_options(datastego_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    enable_language(RC)
    add_executable(datastego WIN32 src/main.cpp src/CLIController.cpp
        src/GUIController.cpp resources/datastego.rc)
    target_compile_definitions(datastego PRIVATE DATASTEGO_GUI UNICODE _UNICODE
        WINVER=0x0601 _WIN32_WINNT=0x0601)
    target_include_directories(datastego PRIVATE resources)
    target_link_libraries(datastego PRIVATE comctl32 comdlg32 gdi32 user32)
else()
    add_executable(datastego src/main.cpp src/CLIController.cpp)
endif()
target_link_libraries(datastego PRIVATE datastego_core)
if(WIN32)
    target_link_libraries(datastego PRIVATE shell32)
endif()
if(MINGW)
    target_link_options(datastego PRIVATE -static-libgcc -static-libstdc++)
endif()
if(MSVC)
    target_compile_options(datastego PRIVATE /utf-8)
else()
    target_compile_options(datastego PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(DATASTEGO_BUILD_TESTS)
    enable_testing()
    add_executable(datastego_tests tests/tests.cpp)
    target_link_libraries(datastego_tests PRIVATE datastego_core)
    if(MINGW)
        target_link_options(datastego_tests PRIVATE -static-libgcc -static-libstdc++)
    endif()
    add_test(NAME datastego_tests COMMAND datastego_tests)
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(Python3_Interpreter_FOUND)
        add_test(NAME datastego_integration
            COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py" "$<TARGET_FILE:datastego>")
        if(WIN32)
            add_test(NAME datastego_gui
                COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/gui_windows.py" "$<TARGET_FILE:datastego>")
        endif()
    endif()
endif()

install(TARGETS datastego RUNTIME DESTINATION bin)
