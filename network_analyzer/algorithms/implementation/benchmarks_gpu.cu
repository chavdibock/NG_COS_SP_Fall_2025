#include "../headers/benchmarks_gpu.h"

#include <cuda_runtime.h>
#include <stdexcept>
#include <string>
#include <climits>

using namespace std;

 void check_cuda(cudaError_t err, const char* msg) {
    if (err != cudaSuccess) {
        throw runtime_error(string(msg) + ": " + cudaGetErrorString(err));
    }
}

__global__ void pairwise_auc_kernel(const float* pos, int n_pos,
    const float* neg, int n_neg,
    unsigned long long* greater,
    unsigned long long* equal) {
    unsigned long long idx =
        blockIdx.x * (unsigned long long)blockDim.x + threadIdx.x;
    unsigned long long total =
        (unsigned long long)n_pos * (unsigned long long)n_neg;
    if (idx >= total) return;

    int i = static_cast<int>(idx / n_neg);
    int j = static_cast<int>(idx % n_neg);

    float ps = pos[i];
    float ns = neg[j];

    if (ps > ns) {
        atomicAdd(greater, 1ULL);
    }
    else if (ps == ns) {
        atomicAdd(equal, 1ULL);
    }
}


__global__ void recall_kernel(const float* scores, const int* y_true,
    int n, float threshold,
    unsigned int* tp, unsigned int* fn) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= n) return;

    int label = y_true[idx];
    if (label != 1) return;

    float s = scores[idx];
    bool pred_pos = (s >= threshold);

    if (pred_pos) {
        atomicAdd(tp, 1u);
    }
    else {
        atomicAdd(fn, 1u);
    }
}


double roc_auc_pairwise_gpu(const float* h_pos, int n_pos,
    const float* h_neg, int n_neg) {
    if (n_pos <= 0 || n_neg <= 0) {
        return 0.0;
    }

    float* d_pos = nullptr;
    float* d_neg = nullptr;
    unsigned long long* d_greater = nullptr;
    unsigned long long* d_equal = nullptr;

    unsigned long long h_greater = 0;
    unsigned long long h_equal = 0;

    size_t size_pos = static_cast<size_t>(n_pos) * sizeof(float);
    size_t size_neg = static_cast<size_t>(n_neg) * sizeof(float);

    check_cuda(cudaMalloc(&d_pos, size_pos), "cudaMalloc d_pos failed");
    check_cuda(cudaMalloc(&d_neg, size_neg), "cudaMalloc d_neg failed");
    check_cuda(cudaMalloc(&d_greater, sizeof(unsigned long long)),
        "cudaMalloc d_greater failed");
    check_cuda(cudaMalloc(&d_equal, sizeof(unsigned long long)),
        "cudaMalloc d_equal failed");

    check_cuda(cudaMemcpy(d_pos, h_pos, size_pos, cudaMemcpyHostToDevice),
        "cudaMemcpy pos H2D failed");
    check_cuda(cudaMemcpy(d_neg, h_neg, size_neg, cudaMemcpyHostToDevice),
        "cudaMemcpy neg H2D failed");

    check_cuda(cudaMemset(d_greater, 0, sizeof(unsigned long long)),
        "cudaMemset greater failed");
    check_cuda(cudaMemset(d_equal, 0, sizeof(unsigned long long)),
        "cudaMemset equal failed");

    unsigned long long total =
        (unsigned long long)n_pos * (unsigned long long)n_neg;
    const int threads = 256;
    int blocks = static_cast<int>((total + threads - 1ULL) / threads);

    pairwise_auc_kernel << <blocks, threads >> > (
        d_pos, n_pos, d_neg, n_neg, d_greater, d_equal);
    check_cuda(cudaGetLastError(), "pairwise_auc_kernel launch failed");
    check_cuda(cudaDeviceSynchronize(), "pairwise_auc_kernel sync failed");

    check_cuda(cudaMemcpy(&h_greater, d_greater, sizeof(unsigned long long),
        cudaMemcpyDeviceToHost),
        "cudaMemcpy greater D2H failed");
    check_cuda(cudaMemcpy(&h_equal, d_equal, sizeof(unsigned long long),
        cudaMemcpyDeviceToHost),
        "cudaMemcpy equal D2H failed");

    cudaFree(d_pos);
    cudaFree(d_neg);
    cudaFree(d_greater);
    cudaFree(d_equal);

    double denom = static_cast<double>(n_pos) * static_cast<double>(n_neg);
    if (denom == 0.0) {
        return 0.0;
    }

    double auc = (static_cast<double>(h_greater) +
        0.5 * static_cast<double>(h_equal)) /
        denom;
    return auc;
}

double recall_at_threshold_gpu(const float* h_score, const int* h_true,
    int n, float threshold) {
    if (n <= 0) {
        return 0.0;
    }

    float* d_score = nullptr;
    int* d_true = nullptr;
    unsigned int* d_tp = nullptr;
    unsigned int* d_fn = nullptr;

    unsigned int h_tp = 0;
    unsigned int h_fn = 0;

    size_t size_score = static_cast<size_t>(n) * sizeof(float);
    size_t size_true = static_cast<size_t>(n) * sizeof(int);

    check_cuda(cudaMalloc(&d_score, size_score), "cudaMalloc d_score failed");
    check_cuda(cudaMalloc(&d_true, size_true), "cudaMalloc d_true failed");
    check_cuda(cudaMalloc(&d_tp, sizeof(unsigned int)), "cudaMalloc d_tp failed");
    check_cuda(cudaMalloc(&d_fn, sizeof(unsigned int)), "cudaMalloc d_fn failed");

    check_cuda(cudaMemcpy(d_score, h_score, size_score, cudaMemcpyHostToDevice),
        "cudaMemcpy score H2D failed");
    check_cuda(cudaMemcpy(d_true, h_true, size_true, cudaMemcpyHostToDevice),
        "cudaMemcpy true H2D failed");

    check_cuda(cudaMemset(d_tp, 0, sizeof(unsigned int)), "cudaMemset tp failed");
    check_cuda(cudaMemset(d_fn, 0, sizeof(unsigned int)), "cudaMemset fn failed");

    const int threads = 256;
    const int blocks = (n + threads - 1) / threads;

    recall_kernel << <blocks, threads >> > (
        d_score, d_true, n, threshold, d_tp, d_fn);
    check_cuda(cudaGetLastError(), "recall_kernel launch failed");
    check_cuda(cudaDeviceSynchronize(), "recall_kernel sync failed");

    check_cuda(cudaMemcpy(&h_tp, d_tp, sizeof(unsigned int),
        cudaMemcpyDeviceToHost),
        "cudaMemcpy tp D2H failed");
    check_cuda(cudaMemcpy(&h_fn, d_fn, sizeof(unsigned int),
        cudaMemcpyDeviceToHost),
        "cudaMemcpy fn D2H failed");

    cudaFree(d_score);
    cudaFree(d_true);
    cudaFree(d_tp);
    cudaFree(d_fn);

    unsigned int denom_u = h_tp + h_fn;
    if (denom_u == 0u) {
        // No positives => recall undefined. Return 0.
        return 0.0;
    }

    double recall = static_cast<double>(h_tp) / static_cast<double>(denom_u);
    return recall;
}
