#include "../headers/OcSvm.h"
#include <cuda_runtime.h>
#include <iostream>
#include <vector>
#include <stdexcept>
#include "../headers/gpu_oc_svm_kernel.h"
using namespace std;
OcSvm::OcSvm(int kernel_type, float gamma, float nu, float coef0, int degree)
    : kernel_type_(kernel_type), gamma_(gamma), nu_(nu),
    coef0_(coef0), degree_(degree), rho_(0.0f), d_alpha_(nullptr) {
}

OcSvm::~OcSvm() {
    if (d_alpha_) cudaFree(d_alpha_);
}

void OcSvm::Train(const vector<float>& x_train, const vector<float>& y_train, int n_features) {
    // use bAseAlgo to coppy and 
    BaseAlgo::Train(x_train, y_train, n_features);

    cout << "Kernel Type: " << kernel_type_ << endl;

    float* d_kernel_matrix;
    size_t k_size = n_train_ * n_train_ * sizeof(float);
    if (cudaMalloc(&d_kernel_matrix, k_size) != cudaSuccess) {
        throw runtime_error("CUDA Malloc failed for Kernel Matrix");
    }

    if (d_alpha_) cudaFree(d_alpha_);
    cudaMalloc(&d_alpha_, n_train_ * sizeof(float));

    // compute kernel matrix
    compute_kernel_matrix_gpu(d_x_train_, n_train_, n_features_,
        kernel_type_, gamma_, coef0_, degree_,
        d_kernel_matrix);

    
    solve_qp(d_kernel_matrix, n_train_);

    // clear GPU memory after computation
    cudaFree(d_kernel_matrix);
}

void OcSvm::solve_qp(const float* d_kernel_matrix, int n_samples) {
    
    vector<float> h_alpha(n_samples, 1.0f / (nu_ * n_samples));
    cudaMemcpy(d_alpha_, h_alpha.data(), n_samples * sizeof(float), cudaMemcpyHostToDevice);

    rho_ = 0.5f;
    cout << "[OC-SVM] QP Solved (Simulated)." << endl;
}

vector<float> OcSvm::Predict(const vector<float>& x_test, int n_test_samples) const {
    if (!d_alpha_) throw runtime_error("Model not trained.");

   
    float* d_x_test;
    size_t test_bytes = n_test_samples * n_features_ * sizeof(float);
    if (cudaMalloc(&d_x_test, test_bytes) != cudaSuccess) {
        throw runtime_error("CUDA Malloc failed for Test Data");
    }
    cudaMemcpy(d_x_test, x_test.data(), test_bytes, cudaMemcpyHostToDevice);

   
    float* d_results;
    cudaMalloc(&d_results, n_test_samples * sizeof(float));

    
    compute_decision_function_gpu(d_x_train_, d_alpha_, d_x_test,
        n_train_, n_test_samples, n_features_,
        kernel_type_, gamma_, coef0_, degree_, rho_,
        d_results);

    
    vector<float> h_results(n_test_samples);
    cudaMemcpy(h_results.data(), d_results, n_test_samples * sizeof(float), cudaMemcpyDeviceToHost);


    cudaFree(d_x_test);
    cudaFree(d_results);

    for (int i = 0; i < n_test_samples; ++i) {
        h_results[i] = (h_results[i] >= 0.0f) ? 1.0f : -1.0f;
    }

    return h_results;
}

map<string, float> OcSvm::GetParams() const {

    // return the params of the Oc-SVM that is calculated
    return {
        {"kernel_type", (float)kernel_type_},
        {"gamma", gamma_},
        {"nu", nu_},
        {"coef0", coef0_},
        {"degree", (float)degree_},
        {"rho", rho_} 
    };
}

