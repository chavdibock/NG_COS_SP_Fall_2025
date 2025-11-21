#pragma once

#include "BaseAlgo.h"

class KNN : public BaseAlgo {
public:
    explicit KNN(int k);

    // override training (but still call BaseAlgo::Train to do copies)
    void Train(const std::vector<float>& x_train,
        const std::vector<float>& y_train,
        int n_features) override;

    std::vector<float> Predict(const std::vector<float>& x_test,
        int n_samples) const override;

    void SaveModel(const std::string& path) const override;
    void LoadModelSettings(const std::string& path) override;
    void SanityCheck();
private:
    int k_{ 1 };
};
