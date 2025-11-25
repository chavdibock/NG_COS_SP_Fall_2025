#include "../headers/gpu_oc_svm_kernel.h"
#include <cuda_runtime.h>
#include <cmath>
#include <iostream>
using namespace std;

__device__ float compute_kernel_value(const float* ptr_a, const float* ptr_b, int n_features,
    int kernel_type, float gamma, float coef0, int degree) {
    float dot = 0.0f;
    float dist_sq = 0.0f;

    // Dt Product for Linear/Poly/Sigmoid and DistSq for RBF
    for (int k = 0; k < n_features; ++k) {
        float a = ptr_a[k];
        float b = ptr_b[k];

        if (kernel_type == RBF) {
            float diff = a - b;
            dist_sq += diff * diff;
        }
        else {
            dot += a * b;
        }
    }

    // Depending on the kernel calculate:
    switch (kernel_type) {
    case LINEAR:
        return dot;
    case RBF:
        return expf(-gamma * dist_sq);
    case POLY:
        return powf(gamma * dot + coef0, (float)degree);
    case SIGMOID:
        return tanhf(gamma * dot + coef0);
    default:
        return 0.0f;
    }
}

__global__ void kernel_matrix_kernel(const float* X, float* K_matrix, int n_samples, int n_features,
    int kernel_type, float gamma, float coef0, int degree) {
    int row = blockIdx.y * blockDim.y + threadIdx.y;
    int col = blockIdx.x * blockDim.x + threadIdx.x;

    if (row < n_samples && col < n_samples) {
        const float* vec_i = &X[row * n_features];
        const float* vec_j = &X[col * n_features];

        K_matrix[row * n_samples + col] = compute_kernel_value(vec_i, vec_j, n_features, kernel_type, gamma, coef0, degree);
    }
}

// Predict kernel based on the train Kernel

__global__ void predict_kernel(const float* train_X, const float* alpha, const float* test_X,
    int n_train, int n_test, int n_features,
    int kernel_type, float gamma, float coef0, int degree, float rho,
    float* results) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x; // Index of test sample

    if (idx < n_test) {
        float sum = 0.0f;
        const float* vec_test = &test_X[idx * n_features];

        for (int i = 0; i < n_train; ++i) {
            
            if (alpha[i] > 1e-7f) {
                const float* vec_train = &train_X[i * n_features];
                float k_val = compute_kernel_value(vec_train, vec_test, n_features, kernel_type, gamma, coef0, degree);
                sum += alpha[i] * k_val;
            }
        }
        results[idx] = sum - rho;
    }
}

//run to use the GPU

void compute_kernel_matrix_gpu(const float* d_x, int n_samples, int n_features,
    int kernel_type, float gamma, float coef0, int degree,
    float* d_kernel_matrix) {
    dim3 threads(16, 16);
    dim3 blocks((n_samples + 15) / 16, (n_samples + 15) / 16);

    kernel_matrix_kernel << <blocks, threads >> > (d_x, d_kernel_matrix, n_samples, n_features, kernel_type, gamma, coef0, degree);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) cerr << "CUDA Kernel Matrix Error: " << cudaGetErrorString(err) << endl;

    cudaDeviceSynchronize();
}

void compute_decision_function_gpu(const float* d_x_train, const float* d_alpha, const float* d_x_test,
    int n_train, int n_test, int n_features,
    int kernel_type, float gamma, float coef0, int degree, float rho,
    float* d_result) {
    int threads = 256;
    int blocks = (n_test + threads - 1) / threads;

    predict_kernel << <blocks, threads >> > (d_x_train, d_alpha, d_x_test, n_train, n_test, n_features,
        kernel_type, gamma, coef0, degree, rho, d_result);

    cudaError_t err = cudaGetLastError();
    if (err != cudaSuccess) cerr << "CUDA Predict Error: " << cudaGetErrorString(err) << endl;

    cudaDeviceSynchronize();
}