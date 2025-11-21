#include "headers/BaseAlgo.h"
#include <cuda_runtime.h>
#include <stdexcept>
#include <stdexcept>
#include <sstream>
#include <iostream>
namespace {
    inline void cuda_check(cudaError_t err, const char* msg) {
        if (err != cudaSuccess) {
            std::cerr << "CUDA ERROR at: " << msg << " -> "
                << cudaGetErrorString(err) << std::endl;
            throw std::runtime_error(std::string(msg) + ": " +
                cudaGetErrorString(err));
        }
    }
} // namespace

BaseAlgo::~BaseAlgo() {
    free_device_memory();
}

BaseAlgo::BaseAlgo(BaseAlgo&& other) noexcept {
    *this = std::move(other);
}

BaseAlgo& BaseAlgo::operator=(BaseAlgo&& other) noexcept {
    if (this != &other) {
        free_device_memory();

        featureKeys_ = std::move(other.featureKeys_);
        targetKey_ = std::move(other.targetKey_);
        n_features_ = other.n_features_;
        n_train_ = other.n_train_;
        d_x_train_ = other.d_x_train_;
        d_y_train_ = other.d_y_train_;

        other.d_x_train_ = nullptr;
        other.d_y_train_ = nullptr;
        other.n_features_ = 0;
        other.n_train_ = 0;
    }
    return *this;
}

void BaseAlgo::Train(const std::vector<float>& x_train,
    const std::vector<float>& y_train,
    int n_features) {

    int n_train = static_cast<int>(y_train.size());
    std::size_t expected_x = static_cast<std::size_t>(n_train) * n_features;
    std::size_t expected_y = static_cast<std::size_t>(n_train);

    if (x_train.size() != expected_x) {
        std::ostringstream oss;
        oss << "Train: x_train size mismatch. Got " << x_train.size()
            << ", expected " << expected_x
            << " (= n_train * n_features = "
            << n_train << " * " << n_features << ")";
        throw std::runtime_error(oss.str());
    }

    if (y_train.size() != expected_y) {
        std::ostringstream oss;
        oss << "Train: y_train size mismatch. Got " << y_train.size()
            << ", expected " << expected_y
            << " (= n_train)";
        throw std::runtime_error(oss.str());
    }
    allocate_and_copy_to_device(x_train, y_train, n_train, n_features);
}

void BaseAlgo::allocate_and_copy_to_device(
    const std::vector<float>& x_train,
    const std::vector<float>& y_train,
    int n_train,
    int n_features) {

    free_device_memory();

    n_train_ = n_train;
    n_features_ = n_features;

    std::cout << "ALLOCATE DEBUG\n";
    std::cout << "n_train=" << n_train << "\n";
    std::cout << "n_features=" << n_features << "\n";
    std::cout << "x_train.size=" << x_train.size() << "\n";
    std::cout << "y_train.size=" << y_train.size() << "\n";
    std::cout << "expected_x=" << (n_train * n_features) << "\n";
    std::cout << "expected_y=" << n_train << "\n";
    std::cout << std::flush;
    std::size_t x_bytes = static_cast<std::size_t>(n_train) * n_features * sizeof(float);
    std::size_t y_bytes = static_cast<std::size_t>(n_train) * sizeof(float);

    std::size_t expected_x = static_cast<std::size_t>(n_train) * n_features;
    std::size_t expected_y = static_cast<std::size_t>(n_train);
    
    if (x_train.size() != expected_x) {
        throw std::runtime_error("Train: x_train size mismatch");
    }
    if (y_train.size() != expected_y) {
        throw std::runtime_error("Train: y_train size mismatch");
    }

    std::cout << "About to cudaMalloc: x_bytes=" << x_bytes <<
        " y_bytes=" << y_bytes << std::endl;
    cuda_check(cudaMalloc(&d_x_train_, x_bytes), "cudaMalloc d_x_train_");
    cuda_check(cudaMalloc(&d_y_train_, y_bytes), "cudaMalloc d_y_train_");

    cuda_check(cudaMemcpy(d_x_train_, x_train.data(), x_bytes,
        cudaMemcpyHostToDevice),
        "cudaMemcpy x_train");
    cuda_check(cudaMemcpy(d_y_train_, y_train.data(), y_bytes,
        cudaMemcpyHostToDevice),
        "cudaMemcpy y_train");
}

void BaseAlgo::free_device_memory() {
    if (d_x_train_) cudaFree(d_x_train_);
    if (d_y_train_) cudaFree(d_y_train_);
    d_x_train_ = nullptr;
    d_y_train_ = nullptr;
    n_train_ = 0;
    n_features_ = 0;
}
