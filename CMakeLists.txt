cmake_minimum_required(VERSION 3.13)

project(auth VERSION 0.1)

add_executable(auth main.c)

configure_file(authconf.h.in authconf.h)

target_link_libraries(auth -lcrypt)

