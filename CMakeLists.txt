cmake_minimum_required(VERSION 2.8)

include_directories(src)

add_library(evconnection src/libevconnection.c)
target_link_libraries(evconnection cares)

add_executable(sample ex/sample.c)
target_link_libraries(sample ev evconnection cares)

