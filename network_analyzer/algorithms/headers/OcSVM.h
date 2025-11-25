#pragma once
#include "BaseAlgo.h"
#include "gpu_oc_svm_kernel.h"
#include <vector>
#include <string>
#include <map> // Added for dictionary return
using namespace std;

class OcSvm : public BaseAlgo {
private:
    // params
    int kernel_type_;
    float gamma_;
    float nu_;
    float coef0_;
    int degree_;

  
    float rho_; 
    float* d_alpha_{ nullptr }; 

public:
    // Constructor with defaults
    OcSvm(int kernel_type = RBF, float gamma = 0.1f, float nu = 0.1f, float coef0 = 0.0f, int degree = 3);
    ~OcSvm() override;

    // train:  computes Kernel Matrix
    void Train(const vector<float>& x_train,
        const vector<float>& y_train,
        int n_features) override;

    // Predict: Returns 1.0 for Normal, -1.0 for Anomaly
    vector<float> Predict(const vector<float>& x_test, int n_samples) const override;

    // return parameters as a dictionary
    map<string, float> GetParams() const;

private:
    
    void solve_qp(const float* d_kernel_matrix, int n_samples);
};