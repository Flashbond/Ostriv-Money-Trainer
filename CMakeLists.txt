cmake_minimum_required(VERSION 3.10)

project(OstrivTrainer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Derleyici optimizasyonları
if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -O3)
endif()

# Windows GUI uygulaması
add_executable(ostriv_trainer WIN32
    src/main.cpp
)