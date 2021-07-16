cmake_minimum_required(VERSION 3.10)

project(Finger VERSION 1.0 LANGUAGES C CXX)

add_executable(Finger source.cpp)

target_link_libraries(Finger netfilter_queue nfnetlink pthread)

