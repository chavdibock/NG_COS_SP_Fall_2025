#pragma once

using namespace std;

// ROC-AUC
double roc_auc_pairwise_gpu(const float* h_pos, int n_pos,
    const float* h_neg, int n_neg);

// Recall on GPU 
double recall_at_threshold_gpu(const float* h_score, const int* h_true,
    int n, float threshold);
