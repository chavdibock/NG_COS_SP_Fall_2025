#include "../headers/preprocessing.h"
#include <cmath>
#include <stdexcept>
#include <algorithm>
#include <iostream>

using namespace std;

void compute_column_stats(const vector<float>& data, int n_samples, int n_features,
    vector<float>& means, vector<float>& stds) {
    means.assign(n_features, 0.0f);
    stds.assign(n_features, 0.0f);

    
    for (int i = 0; i < n_samples; ++i) {
        for (int j = 0; j < n_features; ++j) {
            means[j] += data[static_cast<size_t>(i) * n_features + j];
        }
    }

  
    for (int j = 0; j < n_features; ++j) {
        means[j] /= static_cast<float>(n_samples);
    }

    //  Squared Differences
    for (int i = 0; i < n_samples; ++i) {
        for (int j = 0; j < n_features; ++j) {
            float val = data[static_cast<size_t>(i) * n_features + j];
            float diff = val - means[j];
            stds[j] += diff * diff;
        }
    }

    
    for (int j = 0; j < n_features; ++j) {
        stds[j] = std::sqrt(stds[j] / static_cast<float>(n_samples));
        
        if (stds[j] < 1e-9f) stds[j] = 1.0f;
    }
}

void apply_scaling(vector<float>& data, int n_samples, int n_features,
    const vector<float>& means, const vector<float>& stds) {
    for (int i = 0; i < n_samples; ++i) {
        for (int j = 0; j < n_features; ++j) {
            size_t idx = static_cast<size_t>(i) * n_features + j;
            data[idx] = (data[idx] - means[j]) / stds[j];
        }
    }
}

void compute_covariance_matrix(const vector<float>& data, int n_samples, int n_features,
    vector<float>& covariance_matrix) {
    covariance_matrix.assign(static_cast<size_t>(n_features) * n_features, 0.0f);

    vector<float> col_means(n_features, 0.0f);
    for (int i = 0; i < n_samples; ++i) {
        for (int j = 0; j < n_features; ++j) {
            col_means[j] += data[static_cast<size_t>(i) * n_features + j];
        }
    }
    for (int j = 0; j < n_features; ++j) col_means[j] /= n_samples;

    for (int i = 0; i < n_features; ++i) {
        for (int j = i; j < n_features; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < n_samples; ++k) {
                float val_i = data[static_cast<size_t>(k) * n_features + i] - col_means[i];
                float val_j = data[static_cast<size_t>(k) * n_features + j] - col_means[j];
                sum += val_i * val_j;
            }
            float cov = sum / (n_samples - 1);
            covariance_matrix[static_cast<size_t>(i) * n_features + j] = cov;
            covariance_matrix[static_cast<size_t>(j) * n_features + i] = cov; 
        }
    }
}

void jacobi_eigen_algorithm(const vector<float>& covariance, int n,
    vector<float>& eigenvalues, vector<float>& eigenvectors) {
 
    vector<float> A = covariance;

    
    eigenvectors.assign(static_cast<size_t>(n) * n, 0.0f);
    for (int i = 0; i < n; ++i) eigenvectors[static_cast<size_t>(i) * n + i] = 1.0f;

    
    eigenvalues.resize(n);
    for (int i = 0; i < n; ++i) eigenvalues[i] = A[static_cast<size_t>(i) * n + i];

    int max_iter = 100;
    float tol = 1e-9f;

    for (int iter = 0; iter < max_iter; ++iter) {
        
        float max_val = 0.0f;
        int p = -1, q = -1;
        for (int i = 0; i < n; ++i) {
            for (int j = i + 1; j < n; ++j) {
                if (std::abs(A[static_cast<size_t>(i) * n + j]) > max_val) {
                    max_val = std::abs(A[static_cast<size_t>(i) * n + j]);
                    p = i;
                    q = j;
                }
            }
        }

        if (max_val < tol) break; 
        float app = A[static_cast<size_t>(p) * n + p];
        float aqq = A[static_cast<size_t>(q) * n + q];
        float apq = A[static_cast<size_t>(p) * n + q];

        float theta = 0.5f * (aqq - app) / apq;
        float t = (theta > 0) ? 1.0f / (theta + std::sqrt(theta * theta + 1.0f))
            : 1.0f / (theta - std::sqrt(theta * theta + 1.0f));
        float c = 1.0f / std::sqrt(1.0f + t * t);
        float s = t * c;

        A[static_cast<size_t>(p) * n + p] = c * c * app - 2.0f * s * c * apq + s * s * aqq;
        
        A[static_cast<size_t>(q) * n + q] = s * s * app + 2.0f * s * c * apq + c * c * aqq;
        
        A[static_cast<size_t>(p) * n + q] = 0.0f;
        A[static_cast<size_t>(q) * n + p] = 0.0f;

        for (int i = 0; i < n; ++i) {
            if (i != p && i != q) {
                float aip = A[static_cast<size_t>(i) * n + p];
                float aiq = A[static_cast<size_t>(i) * n + q];
                A[static_cast<size_t>(i) * n + p] = c * aip - s * aiq;
                A[static_cast<size_t>(p) * n + i] = A[static_cast<size_t>(i) * n + p];
                A[static_cast<size_t>(i) * n + q] = s * aip + c * aiq;
                A[static_cast<size_t>(q) * n + i] = A[static_cast<size_t>(i) * n + q];
            }
        }

        // Update Eigenvectors
        for (int i = 0; i < n; ++i) {
            float vip = eigenvectors[static_cast<size_t>(i) * n + p];
            float viq = eigenvectors[static_cast<size_t>(i) * n + q];
            eigenvectors[static_cast<size_t>(i) * n + p] = c * vip - s * viq;
            eigenvectors[static_cast<size_t>(i) * n + q] = s * vip + c * viq;
        }

        for (int i = 0; i < n; ++i) eigenvalues[i] = A[static_cast<size_t>(i) * n + i];
    }
}

void sort_eigen_pairs(vector<float>& eigenvalues, vector<float>& eigenvectors, int n) {
    for (int i = 0; i < n - 1; ++i) {
        for (int j = 0; j < n - i - 1; ++j) {
            if (eigenvalues[j] < eigenvalues[j + 1]) {
                swap(eigenvalues[j], eigenvalues[j + 1]);

                for (int k = 0; k < n; ++k) {
                    swap(eigenvectors[static_cast<size_t>(k) * n + j],
                        eigenvectors[static_cast<size_t>(k) * n + j + 1]);
                }
            }
        }
    }
}

void project_pca(const vector<float>& input, int n_samples, int n_features,
    const vector<float>& eigenvectors, int k, vector<float>& output) {
    
    output.resize(static_cast<size_t>(n_samples) * k);

    
    for (int i = 0; i < n_samples; ++i) {
        for (int j = 0; j < k; ++j) {
            float sum = 0.0f;
            for (int l = 0; l < n_features; ++l) {
                float x_val = input[static_cast<size_t>(i) * n_features + l];
                float v_val = eigenvectors[static_cast<size_t>(l) * n_features + j]; 
                sum += x_val * v_val;
            }
            output[static_cast<size_t>(i) * k + j] = sum;
        }
    }
}

vector<float> pca_scaling(
    const vector<float>& input,
    int n_samples,
    int n_features,
    bool use_scaling,
    bool use_pca,
    int n_pca_components)
{
    vector<float> data = input; 
    int current_n_features = n_features;

    
    if (use_scaling) {
        vector<float> means, stds;
        compute_column_stats(data, n_samples, current_n_features, means, stds);
        apply_scaling(data, n_samples, current_n_features, means, stds);
    }

    
    if (use_pca) {
        if (n_pca_components <= 0 || n_pca_components > current_n_features) {
            n_pca_components = current_n_features;
        }

        
        if (!use_scaling) {
            vector<float> means(current_n_features), unused_stds(current_n_features);
            compute_column_stats(data, n_samples, current_n_features, means, unused_stds);

            // centering
            for (int i = 0; i < n_samples; ++i) {
                for (int j = 0; j < current_n_features; ++j) {
                    data[static_cast<size_t>(i) * current_n_features + j] -= means[j];
                }
            }
        }

        vector<float> cov_matrix;
        vector<float> eigenvalues;
        vector<float> eigenvectors;

        compute_covariance_matrix(data, n_samples, current_n_features, cov_matrix);
        jacobi_eigen_algorithm(cov_matrix, current_n_features, eigenvalues, eigenvectors);
        sort_eigen_pairs(eigenvalues, eigenvectors, current_n_features);

        vector<float> projected_data;
        project_pca(data, n_samples, current_n_features, eigenvectors, n_pca_components, projected_data);

        data = projected_data;
    }

    return data;
}