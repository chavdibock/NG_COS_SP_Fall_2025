cmake_minimum_required(VERSION 3.18)
project(example_mod LANGUAGES CXX CUDA)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CUDAToolkit_ROOT "C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v12.8")
find_package(CUDAToolkit REQUIRED)
add_subdirectory(pybind11)  # or rely on your vcpkg/installed pybind11

pybind11_add_module(algos
	module.cpp
	implementation/BaseAlgo.cpp
	implementation/KNN.cpp
	implementation/gpu_knn_kernel.cu
)  # module name must be "example"

# drop the built .pyd next to example.cpp
target_include_directories(algos PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
	${CUDAToolkit_INCLUDE_DIRS}
)

get_filename_component(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/module.cpp" DIRECTORY)

set_target_properties(algos PROPERTIES
  LIBRARY_OUTPUT_DIRECTORY "${SRC_DIR}"
  RUNTIME_OUTPUT_DIRECTORY "${SRC_DIR}"
  ARCHIVE_OUTPUT_DIRECTORY "${SRC_DIR}"
  CUDA_SEPARABLE_COMPILATION ON
)
target_link_libraries(algos PRIVATE
    CUDA::cudart_static
)
set_source_files_properties(implementation/KNN.cpp PROPERTIES LANGUAGE CUDA)
