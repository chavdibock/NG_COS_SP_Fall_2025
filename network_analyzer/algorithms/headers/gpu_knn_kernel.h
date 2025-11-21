#pragma once

// Host wrapper for the CUDA kernel.  Implementation is in gpu_knn_kernel.cu
// X_train:  [n_train, n_features]
// y_train:  [n_train]
// X_query:  [n_query, n_features]
// y_pred:   [n_query]
void knn_predict_gpu(const float* d_x_train,
    const float* d_y_train,
    int n_train,
    const float* d_x_query,
    int n_query,
    int n_features,
    int k,
    float* d_y_pred);
