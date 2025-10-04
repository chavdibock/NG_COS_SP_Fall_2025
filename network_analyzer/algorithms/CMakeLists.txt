cmake_minimum_required(VERSION 3.18)
project(example_mod LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(pybind11)  # or rely on your vcpkg/installed pybind11

pybind11_add_module(algos
	module.cpp
	implementation/OcSvm.cpp
	implementation/BaseAlgo.cpp
)  # module name must be "example"

# drop the built .pyd next to example.cpp
target_include_directories(algos PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/module.cpp" DIRECTORY)

set_target_properties(algos PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${SRC_DIR}"
  RUNTIME_OUTPUT_DIRECTORY "${SRC_DIR}"
  ARCHIVE_OUTPUT_DIRECTORY "${SRC_DIR}"
)
