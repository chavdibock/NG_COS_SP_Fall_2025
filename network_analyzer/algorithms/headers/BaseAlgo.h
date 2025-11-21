#pragma once

#include <string>
#include <vector>

class BaseAlgo {
protected:
    // column names (optional, but matches your diagram idea)
    std::vector<std::string> featureKeys_;
    std::string              targetKey_;

    int   n_features_{ 0 };
    int   n_train_{ 0 };

    // training data on the GPU: row-major [n_train, n_features]
    float* d_x_train_{ nullptr };
    float* d_y_train_{ nullptr };

public:
    BaseAlgo() = default;
    virtual ~BaseAlgo();

    // non-copyable (GPU pointers)
    BaseAlgo(const BaseAlgo&) = delete;
    BaseAlgo& operator=(const BaseAlgo&) = delete;

    BaseAlgo(BaseAlgo&& other) noexcept;
    BaseAlgo& operator=(BaseAlgo&& other) noexcept;

    // Common interface
    virtual void Train(const std::vector<float>& x_train,
        const std::vector<float>& y_train,
        int n_features);

    virtual std::vector<float> Predict(const std::vector<float>& x_test,
        int n_samples) const = 0;

    virtual void SaveModel(const std::string& path) const = 0;
    virtual void LoadModelSettings(const std::string& path) = 0;

protected:
    // helper for derived classes
    void allocate_and_copy_to_device(const std::vector<float>& x_train,
        const std::vector<float>& y_train,
        int n_train,
        int n_features);

    void free_device_memory();
};
