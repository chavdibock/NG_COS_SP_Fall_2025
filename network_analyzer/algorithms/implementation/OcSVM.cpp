#include "../headers/OcSvm.h"
#include <cuda_runtime.h>
#include <iostream>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <numeric>
#include <cmath>

#include "../headers/gpu_oc_svm_kernel.h"

using namespace std;

OcSvm::OcSvm(int kernel_type, float gamma, float nu, float coef0, int degree)
    : kernel_type_(kernel_type),
    gamma_(gamma),
    nu_(nu),
    coef0_(coef0),
    degree_(degree),
    rho_(0.0f),
    d_alpha_(nullptr) {
}

OcSvm::~OcSvm() {
    if (d_alpha_) cudaFree(d_alpha_);
}

void OcSvm::Train(const vector<float>& x_train, const vector<float>& y_train, int n_features) {
    
    BaseAlgo::Train(x_train, y_train, n_features);

    cout << "Kernel Type: " << kernel_type_ << endl;

    // Allocate kernel matrix on device
    float* d_kernel_matrix = nullptr;
    size_t k_size = static_cast<size_t>(n_train_) * static_cast<size_t>(n_train_) * sizeof(float);
    if (cudaMalloc(&d_kernel_matrix, k_size) != cudaSuccess) {
        throw runtime_error("CUDA Malloc failed for Kernel Matrix");
    }

    // Allocate alpha on device if needed
    if (d_alpha_) cudaFree(d_alpha_);
    if (cudaMalloc(&d_alpha_, n_train_ * sizeof(float)) != cudaSuccess) {
        cudaFree(d_kernel_matrix);
        throw runtime_error("CUDA Malloc failed for alpha");
    }

    
    compute_kernel_matrix_gpu(
        d_x_train_,
        n_train_,
        n_features_,
        kernel_type_,
        gamma_,
        coef0_,
        degree_,
        d_kernel_matrix
    );

    // Solve the SVM QP on CPU using this kernel matrix
    solve_qp(d_kernel_matrix, n_train_);

    // Free kernel matrix on device
    cudaFree(d_kernel_matrix);
}

void OcSvm::solve_qp(const float* d_kernel_matrix, int n_samples) {
    
    size_t k_size = static_cast<size_t>(n_samples) * static_cast<size_t>(n_samples);
    vector<float> K(k_size);
    cudaError_t err = cudaMemcpy(
        K.data(),
        d_kernel_matrix,
        k_size * sizeof(float),
        cudaMemcpyDeviceToHost
    );
    if (err != cudaSuccess) {
        throw runtime_error("CUDA memcpy failed when copying kernel matrix to host");
    }

   
    const float C = 1.0f / (nu_ * n_samples);

    
    vector<float> alpha(n_samples, 1.0f / static_cast<float>(n_samples));

    // gradient descent parameters
    const int max_iter = 500;         
    const float eta = 0.01f;          
    const float tol = 1e-4f;          

    vector<float> grad(n_samples);
    vector<float> alpha_old(n_samples);

    auto compute_grad = [&](const vector<float>& a, vector<float>& g) {
  
        for (int i = 0; i < n_samples; ++i) {
            float sum = 0.0f;
            const float* Ki = &K[static_cast<size_t>(i) * n_samples];
            for (int j = 0; j < n_samples; ++j) {
                sum += Ki[j] * a[j];
            }
            g[i] = sum;
        }
        };

    auto project_to_box_and_normalize = [&](vector<float>& a) {
        
        for (int i = 0; i < n_samples; ++i) {
            if (a[i] < 0.0f) a[i] = 0.0f;
            if (a[i] > C)    a[i] = C;
        }

        
        float sum_a = 0.0f;
        for (int i = 0; i < n_samples; ++i) {
            sum_a += a[i];
        }

        if (sum_a <= 0.0f) {
            
            float val = 1.0f / static_cast<float>(n_samples);
            for (int i = 0; i < n_samples; ++i) {
                a[i] = val;
            }
        }
        else {
            float inv_sum = 1.0f / sum_a;
            for (int i = 0; i < n_samples; ++i) {
                a[i] *= inv_sum;
            }
        }
        };

    for (int iter = 0; iter < max_iter; ++iter) {
        alpha_old = alpha;

        
        compute_grad(alpha, grad);

        
        for (int i = 0; i < n_samples; ++i) {
            alpha[i] = alpha[i] - eta * grad[i];


        }

        
        project_to_box_and_normalize(alpha);

        
        float diff_norm_sq = 0.0f;
        for (int i = 0; i < n_samples; ++i) {
            float d = alpha[i] - alpha_old[i];
            diff_norm_sq += d * d;
        }

        if (diff_norm_sq < tol * tol) {
           // cout << "[OC-SVM] QP converged at iteration " << iter << endl;
            break;
        }
    }

    
    err = cudaMemcpy(
        d_alpha_,
        alpha.data(),
        n_samples * sizeof(float),
        cudaMemcpyHostToDevice
    );
    if (err != cudaSuccess) {
        throw runtime_error("CUDA memcpy failed when copying alpha to device");
    }


    vector<float> f_raw(n_samples, 0.0f);

    
    for (int i = 0; i < n_samples; ++i) {
        float sum = 0.0f;
        for (int j = 0; j < n_samples; ++j) {
            float Kji = K[static_cast<size_t>(j) * n_samples + i];
            sum += alpha[j] * Kji;
        }
        f_raw[i] = sum;
    }

    
    const float eps = 1e-6f;
    vector<float> margin_vals;
    margin_vals.reserve(n_samples);

    for (int i = 0; i < n_samples; ++i) {
        if (alpha[i] > eps && alpha[i] < C - eps) {
            margin_vals.push_back(f_raw[i]);
        }
    }

    if (!margin_vals.empty()) {
        
        float sum = accumulate(margin_vals.begin(), margin_vals.end(), 0.0f);
        rho_ = sum / static_cast<float>(margin_vals.size());
    }
    else {
       
        float sum = accumulate(f_raw.begin(), f_raw.end(), 0.0f);
        rho_ = sum / static_cast<float>(n_samples);
    }

    cout << "[OC-SVM] QP Solved (Projected Gradient), rho = " << rho_ << endl;
}

vector<float> OcSvm::Predict(const vector<float>& x_test, int n_test_samples) const {
    if (!d_alpha_) throw runtime_error("Model not trained.");

    
    int input_features = static_cast<int>(x_test.size()) / n_test_samples;

   
    vector<float> x_test_transformed = TransformData(x_test, n_test_samples, input_features);

    
    if ((x_test_transformed.size() / n_test_samples) != n_features_) {
        throw runtime_error("OcSVM Predict: Transformed data dimension mismatch");
    }

    float* d_x_test = nullptr;
    size_t test_bytes = static_cast<size_t>(n_test_samples) * static_cast<size_t>(n_features_) * sizeof(float);
    if (cudaMalloc(&d_x_test, test_bytes) != cudaSuccess) {
        throw runtime_error("CUDA Malloc failed for Test Data");
    }
    cudaMemcpy(d_x_test, x_test_transformed.data(), test_bytes, cudaMemcpyHostToDevice);

    float* d_results = nullptr;
    if (cudaMalloc(&d_results, n_test_samples * sizeof(float)) != cudaSuccess) {
        cudaFree(d_x_test);
        throw runtime_error("CUDA Malloc failed for Results");
    }

    
    compute_decision_function_gpu(
        d_x_train_,
        d_alpha_,
        d_x_test,
        n_train_,
        n_test_samples,
        n_features_,
        kernel_type_,
        gamma_,
        coef0_,
        degree_,
        rho_,
        d_results
    );

    vector<float> h_results(n_test_samples);
    cudaMemcpy(h_results.data(), d_results, n_test_samples * sizeof(float), cudaMemcpyDeviceToHost);

    cudaFree(d_x_test);
    cudaFree(d_results);

   
    for (int i = 0; i < n_test_samples; ++i) {
        h_results[i] = (h_results[i] >= 0.0f) ? 0 : 1;
    }

    return h_results;
}

map<string, float> OcSvm::GetParams() const {
    return {
        {"kernel_type", static_cast<float>(kernel_type_)},
        {"gamma",       gamma_},
        {"nu",          nu_},
        {"coef0",       coef0_},
        {"degree",      static_cast<float>(degree_)},
        {"rho",         rho_}
    };
}