cmake_minimum_required (VERSION 3.16)
project (Cobble)
set (Cobble_VERSION_MAJOR 0)
set (Cobble_VERSION_MINOR 2)
set (CMAKE_EXPORT_COMPILE_COMMANDS ON)


find_package(Z3 REQUIRED CONFIG)
find_package(LLVM REQUIRED CONFIG)
find_package(Python 3.8 REQUIRED Development)

include_directories(${Python_INCLUDE_DIRS})

include_directories(${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})
llvm_map_components_to_libnames(llvm_libs support core irreader)

include_directories("${PROJECT_BINARY_DIR}")
include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("${PROJECT_SOURCE_DIR}/linux_headers")
include_directories(${PYTHON_INCLUDE_DIR})
set(LIB_SRC_DIR "${PROJECT_SOURCE_DIR}/src")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++1z")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")

file(GLOB LIB_SRC
  "${LIB_SRC_DIR}/*.cpp"
  "${LIB_SRC_DIR}/*.c"
  )

add_library(cobble STATIC ${LIB_SRC})
add_library(cobbleso SHARED ${LIB_SRC})

target_link_libraries(cobble z3)
target_link_libraries(cobble "-L/usr/lib -lz3")
target_link_libraries(cobble ${llvm_libs})
target_link_libraries(cobble ${Python_LIBRARIES})
target_link_libraries(cobble elf)

target_link_libraries(cobbleso z3)
target_link_libraries(cobbleso "-L/usr/lib -lz3")
target_link_libraries(cobbleso ${llvm_libs})
target_link_libraries(cobbleso ${Python_LIBRARIES})
target_link_libraries(cobbleso elf)


# set_property(SOURCE ${PROJECT_SOURCE_DIR}/mymod.i PROPERTY CPLUSPLUS ON)
# swig_add_module(mymod python ${PROJECT_SOURCE_DIR}/mymod.i ${LIB_SRC})
# swig_link_libraries(mymod ${PYTHON_LIBRARIES} doubleclick z3 elf)

file(GLOB EXEC_SRC
  "${PROJECT_SOURCE_DIR}/exec/*.cpp"
  )

foreach(src_file ${EXEC_SRC})
  get_filename_component(prog_name ${src_file} NAME_WE)
  add_executable(${prog_name} ${src_file})
  target_link_libraries(${prog_name} ${llvm_libs})
  target_link_libraries(${prog_name} z3)
  target_link_libraries(${prog_name} elf)
  target_link_libraries(${prog_name} cobble)
endforeach(src_file ${EXEC_SRC})
