#include "headers/gpu_knn_kernel.h"
#include <cuda_runtime.h>
#include <float.h>

__global__
void knn_kernel(const float* __restrict__ x_train,
    const float* __restrict__ y_train,
    int n_train,
    const float* __restrict__ x_query,
    int n_query,
    int n_features,
    int k,
    float* __restrict__ y_pred) {
    int q_idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (q_idx >= n_query) return;

    const float* q = x_query + q_idx * n_features;

    float best_dist = FLT_MAX;
    float best_label = 0.0f;

    for (int i = 0; i < n_train; ++i) {
        const float* t = x_train + i * n_features;
        float dist = 0.0f;
        for (int f = 0; f < n_features; ++f) {
            float diff = q[f] - t[f];
            dist += diff * diff;
        }
        if (dist < best_dist) {
            best_dist = dist;
            best_label = y_train[i];
        }
    }

    y_pred[q_idx] = best_label;
}

void knn_predict_gpu(const float* d_x_train,
    const float* d_y_train,
    int n_train,
    const float* d_x_query,
    int n_query,
    int n_features,
    int k,
    float* d_y_pred) {
    (void)k; // currently unused (1-NN example)

    const int threads = 256;
    int blocks = (n_query + threads - 1) / threads;

    knn_kernel << <blocks, threads >> > (d_x_train, d_y_train, n_train,
        d_x_query, n_query, n_features,
        k, d_y_pred);
    cudaDeviceSynchronize();
}
