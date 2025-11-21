#include "headers/KNN.h"
#include "headers/gpu_knn_kernel.h"
#include <iostream>
#include <cuda_runtime.h>
#include <fstream>
#include <stdexcept>
using namespace std;
namespace {
    inline void cuda_check(cudaError_t err, const char* msg) {
        if (err != cudaSuccess) {
            throw runtime_error(string(msg) + ": " +
                cudaGetErrorString(err));
        }
    }
} // namespace

KNN::KNN(int k) : k_(k) {
    if (k_ <= 0) {
        throw invalid_argument("k must be positive");
    }
}

void KNN::Train(const vector<float>& x_train,
    const vector<float>& y_train,
    
    int n_features) {
    BaseAlgo::Train(x_train, y_train, n_features);
}

vector<float> KNN::Predict(const vector<float>& x_test,
    int n_samples) const {
    if (n_features_ == 0 || n_train_ == 0) {
        throw runtime_error("Model not trained");
    }

    size_t x_bytes = static_cast<size_t>(n_samples) * n_features_ * sizeof(float);
    size_t y_bytes = static_cast<size_t>(n_samples) * sizeof(float);

    float* d_x_query = nullptr;
    float* d_y_pred = nullptr;

    cuda_check(cudaMalloc(&d_x_query, x_bytes), "cudaMalloc d_x_query");
    cuda_check(cudaMalloc(&d_y_pred, y_bytes), "cudaMalloc d_y_pred");

    cuda_check(cudaMemcpy(d_x_query, x_test.data(), x_bytes,
        cudaMemcpyHostToDevice),
        "cudaMemcpy x_test");

    knn_predict_gpu(d_x_train_, d_y_train_, n_train_,
        d_x_query, n_samples, n_features_,
        k_, d_y_pred);

    vector<float> y_pred(n_samples);
    cuda_check(cudaMemcpy(y_pred.data(), d_y_pred, y_bytes,
        cudaMemcpyDeviceToHost),
        "cudaMemcpy y_pred");

    cudaFree(d_x_query);
    cudaFree(d_y_pred);

    return y_pred;
}

void KNN::SaveModel(const string& path) const {
    ofstream out(path, ios::binary);
    if (!out) {
        throw runtime_error("Cannot open file for writing: " + path);
    }

    out.write(reinterpret_cast<const char*>(&n_features_), sizeof(n_features_));
    out.write(reinterpret_cast<const char*>(&n_train_), sizeof(n_train_));
    out.write(reinterpret_cast<const char*>(&k_), sizeof(k_));
}

void KNN::LoadModelSettings(const string& path) {
    ifstream in(path, ios::binary);
    if (!in) {
        throw runtime_error("Cannot open file for reading: " + path);
    }
    in.read(reinterpret_cast<char*>(&n_features_), sizeof(n_features_));
    in.read(reinterpret_cast<char*>(&n_train_), sizeof(n_train_));
    in.read(reinterpret_cast<char*>(&k_), sizeof(k_));
    // Note: this only restores metadata, not the actual training data
}

void KNN::SanityCheck()
{
    cout << "this is test print";
}
