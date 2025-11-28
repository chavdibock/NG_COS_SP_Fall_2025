#pragma once

#include <vector>

using namespace std;

// ROC-AUC 
double roc_auc(const vector<float>& y_score, const vector<int>& y_true);

// Recall
double recall_at_threshold(const vector<float>& y_score,
    const vector<int>& y_true,
    float threshold);
