# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(twisted_elgamal)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")

find_package(OPENSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_twisted_elgamal test/test_twisted_elgamal.cpp)

target_link_libraries(test_twisted_elgamal ${OPENSSL_LIBRARIES})

add_executable(test_elgamal test/test_elgamal.cpp)

target_link_libraries(test_elgamal ${OPENSSL_LIBRARIES})

add_executable(test_new_feature test/test_new_feature.cpp)

target_link_libraries(test_new_feature ${OPENSSL_LIBRARIES})