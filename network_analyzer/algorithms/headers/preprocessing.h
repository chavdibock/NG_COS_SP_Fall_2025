#pragma once
#include <vector>

using namespace std;

void compute_column_stats(const vector<float>& data, int n_samples, int n_features,
    vector<float>& means, vector<float>& stds);

void apply_scaling(vector<float>& data, int n_samples, int n_features,
    const vector<float>& means, const vector<float>& stds);

void compute_covariance_matrix(const vector<float>& data, int n_samples, int n_features,
    vector<float>& covariance_matrix);

void jacobi_eigen_algorithm(const vector<float>& covariance, int n,
    vector<float>& eigenvalues, vector<float>& eigenvectors);

void sort_eigen_pairs(vector<float>& eigenvalues, vector<float>& eigenvectors, int n);

void project_pca(const vector<float>& input, int n_samples, int n_features,
    const vector<float>& eigenvectors, int k, vector<float>& output);

vector<float> pca_scaling(
    const vector<float>& input,
    int n_samples,
    int n_features,
    bool use_scaling,
    bool use_pca,
    int n_pca_components);