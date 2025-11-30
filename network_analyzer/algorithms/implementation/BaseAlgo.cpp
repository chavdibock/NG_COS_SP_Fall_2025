#include "../headers/BaseAlgo.h"
#include "../headers/preprocessing.h" 
#include <cuda_runtime.h>
#include <stdexcept>
#include <sstream>
#include <iostream>

using namespace std;

namespace {
    inline void cuda_check(cudaError_t err, const char* msg) {
        if (err != cudaSuccess) {
            cerr << "CUDA ERROR at: " << msg << " -> "
                << cudaGetErrorString(err) << endl;
            throw runtime_error(string(msg) + ": " +
                cudaGetErrorString(err));
        }
    }
}

BaseAlgo::~BaseAlgo() {
    free_device_memory();
}

BaseAlgo::BaseAlgo(BaseAlgo&& other) noexcept {
    *this = move(other);
}

BaseAlgo& BaseAlgo::operator=(BaseAlgo&& other) noexcept {
    if (this != &other) {
        free_device_memory();

        featureKeys_ = move(other.featureKeys_);
        targetKey_ = move(other.targetKey_);
        n_features_ = other.n_features_;
        n_train_ = other.n_train_;
        d_x_train_ = other.d_x_train_;
        d_y_train_ = other.d_y_train_;

        // Move preprocessing state
        use_scaling_ = other.use_scaling_;
        use_pca_ = other.use_pca_;
        n_pca_components_ = other.n_pca_components_;
        scaler_mean_ = move(other.scaler_mean_);
        scaler_std_ = move(other.scaler_std_);
        pca_eigenvectors_ = move(other.pca_eigenvectors_);
        pca_centering_mean_ = move(other.pca_centering_mean_);

        other.d_x_train_ = nullptr;
        other.d_y_train_ = nullptr;
        other.n_features_ = 0;
        other.n_train_ = 0;
    }
    return *this;
}

void BaseAlgo::SetPreprocessing(bool use_scaling, bool use_pca, int n_pca_components) {
    use_scaling_ = use_scaling;
    use_pca_ = use_pca;
    n_pca_components_ = n_pca_components;
}

void BaseAlgo::Train(const vector<float>& x_train,
    const vector<float>& y_train,
    int n_features) {

    int n_train = static_cast<int>(y_train.size());
    size_t expected_x = static_cast<size_t>(n_train) * n_features;

    if (x_train.size() != expected_x) {
        throw runtime_error("Train: x_train size mismatch");
    }

    // --- Preprocessing Logic ---
    vector<float> x_processed = x_train; // Working copy
    int current_n_features = n_features;

    
    if (use_scaling_) {
        cout << "[Preprocessing] Learning Scaling parameters..." << endl;
        compute_column_stats(x_processed, n_train, current_n_features, scaler_mean_, scaler_std_);
        apply_scaling(x_processed, n_train, current_n_features, scaler_mean_, scaler_std_);
    }


    if (use_pca_) {
        if (n_pca_components_ <= 0 || n_pca_components_ > current_n_features) {
            n_pca_components_ = current_n_features;
        }
        cout << "[Preprocessing] Learning PCA (Target dims: " << n_pca_components_ << ")..." << endl;

        if (!use_scaling_) {
            vector<float> dummy_std(current_n_features);
            compute_column_stats(x_processed, n_train, current_n_features, pca_centering_mean_, dummy_std);
            
            for (int i = 0; i < n_train; ++i) {
                for (int j = 0; j < current_n_features; ++j) {
                    x_processed[static_cast<size_t>(i) * current_n_features + j] -= pca_centering_mean_[j];
                }
            }
        }
        else {
           
            pca_centering_mean_.assign(current_n_features, 0.0f);
        }

        vector<float> cov_matrix;
        vector<float> eigenvalues;

        compute_covariance_matrix(x_processed, n_train, current_n_features, cov_matrix);
        jacobi_eigen_algorithm(cov_matrix, current_n_features, eigenvalues, pca_eigenvectors_);
        sort_eigen_pairs(eigenvalues, pca_eigenvectors_, current_n_features);

      
        vector<float> x_projected;
        project_pca(x_processed, n_train, current_n_features, pca_eigenvectors_, n_pca_components_, x_projected);

        x_processed = x_projected;
        current_n_features = n_pca_components_;
    }

    
    allocate_and_copy_to_device(x_processed, y_train, n_train, current_n_features);
}


vector<float> BaseAlgo::TransformData(const vector<float>& input, int n_samples, int n_in_features) const {

    
    vector<float> output = input;
    int current_dims = n_in_features;

    
    if (use_scaling_) {
        if (scaler_mean_.size() != current_dims) throw runtime_error("Transform: Feature dimension mismatch for Scaling");
        apply_scaling(output, n_samples, current_dims, scaler_mean_, scaler_std_);
    }

    
    if (use_pca_) {
       
        if (!use_scaling_) {
            if (pca_centering_mean_.size() != current_dims) throw runtime_error("Transform: Feature dimension mismatch for PCA Centering");
            for (int i = 0; i < n_samples; ++i) {
                for (int j = 0; j < current_dims; ++j) {
                    output[static_cast<size_t>(i) * current_dims + j] -= pca_centering_mean_[j];
                }
            }
        }

        vector<float> projected;
        project_pca(output, n_samples, current_dims, pca_eigenvectors_, n_pca_components_, projected);
        output = projected;
        
    }

    return output;
}

void BaseAlgo::allocate_and_copy_to_device(
    const vector<float>& x_train,
    const vector<float>& y_train,
    int n_train,
    int n_features) {

    free_device_memory();

    n_train_ = n_train;
    n_features_ = n_features;

    cout << "ALLOCATE DEBUG: n_train=" << n_train << ", n_features=" << n_features << endl;

    size_t x_bytes = static_cast<size_t>(n_train) * n_features * sizeof(float);
    size_t y_bytes = static_cast<size_t>(n_train) * sizeof(float);

    cuda_check(cudaMalloc(&d_x_train_, x_bytes), "cudaMalloc d_x_train_");
    cuda_check(cudaMalloc(&d_y_train_, y_bytes), "cudaMalloc d_y_train_");

    cuda_check(cudaMemcpy(d_x_train_, x_train.data(), x_bytes, cudaMemcpyHostToDevice), "cudaMemcpy x_train");
    cuda_check(cudaMemcpy(d_y_train_, y_train.data(), y_bytes, cudaMemcpyHostToDevice), "cudaMemcpy y_train");
}

void BaseAlgo::free_device_memory() {
    if (d_x_train_) cudaFree(d_x_train_);
    if (d_y_train_) cudaFree(d_y_train_);
    d_x_train_ = nullptr;
    d_y_train_ = nullptr;
    n_train_ = 0;
    n_features_ = 0;
}