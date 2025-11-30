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

	// --- Preprocessing State ---
	bool use_scaling_{ false };
	bool use_pca_{ false };
	int  n_pca_components_{ 0 };

	// Learned params
	vector<float> scaler_mean_;
	vector<float> scaler_std_;
	vector<float> pca_eigenvectors_; // Full matrix, sorted
	// PCA technically also needs a mean for centering, but we can reuse scaler_mean_ if scaling is off
	// However, to be robust, we store a separate centering mean for PCA if scaling wasn't used.
	vector<float> pca_centering_mean_;

public:
	BaseAlgo() = default;
	virtual ~BaseAlgo();

	BaseAlgo(const BaseAlgo&) = delete;
	BaseAlgo& operator=(const BaseAlgo&) = delete;

	BaseAlgo(BaseAlgo&& other) noexcept;
	BaseAlgo& operator=(BaseAlgo&& other) noexcept;

	// Configuration method
	void SetPreprocessing(bool use_scaling, bool use_pca, int n_pca_components = 0);

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

	// Helper to transform data based on learned state
	// Returns the transformed data vector and updates n_features_out
	vector<float> TransformData(const vector<float>& input, int n_samples, int n_in_features) const;
};