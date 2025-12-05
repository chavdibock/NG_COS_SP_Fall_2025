import numpy as np
from algorithms import algos # this is the pybind11 module we built

# ---------- 1. Create a tiny toy dataset ----------

# 4 training points in 2D
# Class 0: near (0,0)
# Class 1: near (1,1)
print("Creating test Array")
x_train = np.array([
    [0.0, 0.0],
    [0.1, 0.1],
    [0.0, 0.1],
    [0.2, 0.1],
    [0.1, 0.3],
    [0.3, 0.0],
    [0.95, 0.98],
    [0.78, 0.8],
    [0.7, 0.8],
    [0.8, 0.7],
    [0.9, 1.0],
    [1.0, 0.9],
], dtype=np.float32)


print("Creating Lables")
y_array = [
    0.0,
    0.0,
    0.0,
    0.0,
    0.0,
    0.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0,
    1.0
]
y_train = np.array(y_array, dtype=np.float32)

n_train    = x_train.shape[0]
n_features = x_train.shape[1]

# Flatten to 1D (row-major) for the C++ side: [x00, x01, x10, x11, ...]
x_train_flat = x_train.ravel()

# ---------- 2. Create some test points ----------

x_test = np.array([
    [0.05, 0.05],  # should be close to class 0
    [0.95, 0.95],  # should be close to class 1
    [0.2, 0.0],    # closer to class 0
    [0.8, 0.9],    # closer to class 1
], dtype=np.float32)

n_test = x_test.shape[0]
x_test_flat = x_test.ravel()

# ---------- 3. Use the GPU KNN model ----------
print("Before KNN creation")
k = 3
knn = algos.KNN(k)
print("After KNN creation")

knn.sanity_check()

print("Before KNN train")
print("x_train_flat size:", len(x_train_flat))
print("y_train size:", len(y_train))
print("n_features:", n_features)
print("Expected x_train size:", len(y_train) * n_features)
# Train: copies data to GPU
knn.train(x_train_flat.tolist(),  # or just x_train_flat
          y_train.tolist(),
          n_features)
print("After KNN train")
print("Before KNN predict")
# Predict
y_pred = knn.predict(x_test_flat.tolist(), n_test)
print("After KNN predict")
print("x_test:")
print(x_test)
print("predicted labels:", y_pred)
