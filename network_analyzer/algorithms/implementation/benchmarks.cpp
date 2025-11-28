#include "../headers/benchmarks.h"
#include "../headers/benchmarks_gpu.h"

#include <stdexcept>

using namespace std;

double roc_auc(const vector<float>& y_score, const vector<int>& y_true) {
    const int n = static_cast<int>(y_score.size());
    if (static_cast<int>(y_true.size()) != n) {
        throw runtime_error("roc_auc: y_score and y_true must have the same length.");
    }

    vector<float> pos_scores;
    vector<float> neg_scores;
    pos_scores.reserve(n);
    neg_scores.reserve(n);

    for (int i = 0; i < n; ++i) {
        const int label = y_true[i];
        if (label == 1) {
            pos_scores.push_back(y_score[i]);
        }
        else if (label == 0) {
            neg_scores.push_back(y_score[i]);
        }
        
    }

    if (pos_scores.empty() || neg_scores.empty()) {
        
        return 0.0;
    }

    return roc_auc_pairwise_gpu(
        pos_scores.data(),
        static_cast<int>(pos_scores.size()),
        neg_scores.data(),
        static_cast<int>(neg_scores.size())
    );
}

double recall_at_threshold(const vector<float>& y_score,
    const vector<int>& y_true,
    float threshold) {
    const int n = static_cast<int>(y_score.size());
    if (static_cast<int>(y_true.size()) != n) {
        throw runtime_error("recall_at_threshold: y_score and y_true must have the same length.");
    }

    if (n == 0) {
        return 0.0;
    }

    return recall_at_threshold_gpu(
        y_score.data(),
        y_true.data(),
        n,
        threshold
    );
}
