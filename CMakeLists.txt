cmake_minimum_required(VERSION 3.31)
project(manual_mapper LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(manual_mapper 
	src/main.cpp
	src/utils.cpp
)

