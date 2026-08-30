cmake_minimum_required(VERSION 3.16)
project(lbed_bench LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_BUILD_TYPE Release)

find_package(OpenSSL REQUIRED)

# Set MCL_ROOT to the root of a locally built herumi/mcl checkout.
# Expected:
#   ${MCL_ROOT}/include/mcl/bls12_381.hpp
#   ${MCL_ROOT}/lib/libmcl.a  (or libmcl.so)
if(NOT DEFINED MCL_ROOT)
  message(FATAL_ERROR "Pass -DMCL_ROOT=/path/to/mcl")
endif()

find_path(MCL_INCLUDE_DIR mcl/bls12_381.hpp
  PATHS ${MCL_ROOT}/include
  NO_DEFAULT_PATH)

find_library(MCL_LIBRARY mcl
  PATHS ${MCL_ROOT}/lib
  NO_DEFAULT_PATH)

if(NOT MCL_INCLUDE_DIR OR NOT MCL_LIBRARY)
  message(FATAL_ERROR "Could not find mcl headers/library under MCL_ROOT=${MCL_ROOT}")
endif()

add_executable(lbed_bench lbed_benchmark.cpp)
target_include_directories(lbed_bench PRIVATE ${MCL_INCLUDE_DIR})
target_link_libraries(lbed_bench PRIVATE ${MCL_LIBRARY} OpenSSL::Crypto)

# Match mcl's standard BLS12-381 build configuration.
target_compile_definitions(lbed_bench PRIVATE MCL_FP_BIT=384 MCL_FR_BIT=256)
target_compile_options(lbed_bench PRIVATE -O3 -DNDEBUG)
