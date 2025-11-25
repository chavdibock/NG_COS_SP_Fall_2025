#pragma once
#include <vector>
#include "BaseAlgo.h"
using namespace std;

class KNN : public BaseAlgo {
public:
    explicit KNN(int k);

    // override training 
    void Train(const vector<float>& x_train,
        const vector<float>& y_train,
        int n_features) override;

    vector<float> Predict(const vector<float>& x_test,
        int n_samples) const override;

    void SanityCheck();
private:
    int k_{ 1 };
};
