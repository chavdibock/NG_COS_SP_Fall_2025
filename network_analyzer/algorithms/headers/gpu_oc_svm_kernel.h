#pragma once

enum KernelType {
    LINEAR = 0,
    RBF = 1,
    POLY = 2,
    SIGMOID = 3
};

// Kernel Matrix (Gram Matrix) on the GPU
void compute_kernel_matrix_gpu(const float* d_x, int n_samples, int n_features,
    int kernel_type, float gamma, float coef0, int degree,
    float* d_kernel_matrix);

//  decision function for test data
void compute_decision_function_gpu(const float* d_x_train, const float* d_alpha, const float* d_x_test,
    int n_train, int n_test, int n_features,
    int kernel_type, float gamma, float coef0, int degree, float rho,
    float* d_result);