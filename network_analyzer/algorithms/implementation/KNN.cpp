#include "../headers/KNN.h"
#include "../headers/gpu_knn_kernel.h"
#include <iostream>
#include <cuda_runtime.h>
#include <stdexcept>

using namespace std;

namespace {
    inline void cuda_check(cudaError_t err, const char* msg) {
        if (err != cudaSuccess) {
            throw runtime_error(string(msg) + ": " + cudaGetErrorString(err));
        }
    }
}

KNN::KNN(int k) : k_(k) {
    if (k_ <= 0) {
        throw invalid_argument("k must be positive");
    }
}

void KNN::Train(const vector<float>& x_train, const vector<float>& y_train, int n_features) {
    
    BaseAlgo::Train(x_train, y_train, n_features);
}

vector<float> KNN::Predict(const vector<float>& x_test, int n_samples) const {
    if (n_features_ == 0 || n_train_ == 0) {
        throw runtime_error("Model not trained");
    }


    int input_features = static_cast<int>(x_test.size()) / n_samples;

    
    vector<float> x_test_transformed = TransformData(x_test, n_samples, input_features);

    
    int current_features = static_cast<int>(x_test_transformed.size()) / n_samples;

    if (current_features != n_features_) {
        throw runtime_error("KNN Predict: Transformed data dimension mismatch with Training data");
    }

    size_t x_bytes = static_cast<size_t>(n_samples) * n_features_ * sizeof(float);
    size_t y_bytes = static_cast<size_t>(n_samples) * sizeof(float);

    float* d_x_query = nullptr;
    float* d_y_pred = nullptr;

    cuda_check(cudaMalloc(&d_x_query, x_bytes), "cudaMalloc d_x_query");
    cuda_check(cudaMalloc(&d_y_pred, y_bytes), "cudaMalloc d_y_pred");

    cuda_check(cudaMemcpy(d_x_query, x_test_transformed.data(), x_bytes,
        cudaMemcpyHostToDevice), "cudaMemcpy x_test");

    knn_predict_gpu(d_x_train_, d_y_train_, n_train_,
        d_x_query, n_samples, n_features_,
        k_, d_y_pred);

    vector<float> y_pred(n_samples);
    cuda_check(cudaMemcpy(y_pred.data(), d_y_pred, y_bytes,
        cudaMemcpyDeviceToHost), "cudaMemcpy y_pred");

    cudaFree(d_x_query);
    cudaFree(d_y_pred);

    return y_pred;
}

void KNN::SanityCheck() {
    cout << "this is test print";
}