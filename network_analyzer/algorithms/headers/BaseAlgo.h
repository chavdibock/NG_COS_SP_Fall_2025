#pragma once

#include <string>
#include <vector>
using namespace std;
class BaseAlgo {
protected:
	vector<string> featureKeys_;
	string targetKey_;

	int   n_features_{ 0 };
	int   n_train_{ 0 };

	
	float* d_x_train_{ nullptr };
	float* d_y_train_{ nullptr };

public:
	BaseAlgo() = default;
	virtual ~BaseAlgo();


	BaseAlgo(const BaseAlgo&) = delete;
	BaseAlgo& operator=(const BaseAlgo&) = delete;

	BaseAlgo(BaseAlgo&& other) noexcept;
	BaseAlgo& operator=(BaseAlgo&& other) noexcept;


	virtual void Train(const vector<float>& x_train,
		const vector<float>& y_train,
		int n_features);

	virtual vector<float> Predict(const vector<float>& x_test,
		int n_samples) const = 0;

protected:

	void allocate_and_copy_to_device(const vector<float>& x_train,
		const vector<float>& y_train,
		int n_train,
		int n_features);

	void free_device_memory();
};
