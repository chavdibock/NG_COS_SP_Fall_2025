import numpy as np
from algorithms import algos

# 1. Train ONLY on Class 0 (The "Normal" data)
X_train_normal = np.array([
    [0.0, 0.0], [0.1, 0.1], [0.0, 0.1],
    [0.2, 0.1], [0.1, 0.3], [0.3, 0.0]
], dtype=np.float32)

# We don't need Y for OC-SVM, pass dummy
dummy_y = np.zeros(len(X_train_normal), dtype=np.float32)

print("Training OC-SVM on 'Normal' (Class 0) data only...")
# fix kernel argument if needed (e.g. "rbf", "linear", etc.)
model = algos.OcSvm(gamma=10.0, nu=0.1, kernel=algos.KernelType.RBF)
model.train(X_train_normal.ravel().tolist(), dummy_y.tolist(), 2)

# 2. Test on mixture
# - First two are Class 0 (Normal / Inliers)
# - Last two are Class 1 (Anomaly / Outliers)
x_test = np.array([
    [0.05, 0.05],  # Normal
    [0.10, 0.05],  # Normal
    [0.49, 0.48],
    [0.55, 0.40],
    [0.95, 0.95],  # Anomaly
    [0.80, 0.90],  # Anomaly
], dtype=np.float32)
 
y_test = np.array([0, 0, 0,1,1, 1], dtype=np.int32)  # 0 = normal, 1 = anomaly

print("Predicting...")
preds = model.predict(x_test.ravel().tolist(), 6)  # raw OC-SVM scores
preds = np.array(preds, dtype=np.float32)

print("####")
print(model.get_params())
print("####")
print("Raw Scores (Positive=Normal, Negative=Anomaly):")
print(preds)

# ------- METRICS -------

# Option 1: Treat "normal" as the positive class
#   - labels: 1 = normal, 0 = anomaly
labels_normal_pos = (y_test == 0).astype(np.int32).tolist()
scores_for_normal = preds.tolist()  # higher score = more normal

auc_normal = algos.roc_auc(scores_for_normal, labels_normal_pos)
rec_normal = algos.recall(scores_for_normal, labels_normal_pos, 0.0)  # threshold at 0 (decision boundary)

print("\n[Normal = positive class]")
print("AUC:", auc_normal)
print("REC:", rec_normal)

# Option 2 (often used in anomaly detection): Treat "anomaly" as positive
#   - labels: 1 = anomaly, 0 = normal
#   - since OC-SVM returns positive for normal and negative for anomaly,
#     we flip the sign so that "higher score = more anomalous".
labels_anom_pos = (y_test == 1).astype(np.int32).tolist()
scores_for_anom = (-preds).tolist()  # now higher => more anomalous

auc_anom = algos.roc_auc(scores_for_anom, labels_anom_pos)
rec_anom = algos.recall(scores_for_anom, labels_anom_pos, 0.0)

print("\n[Anomaly = positive class]")
print("AUC:", auc_anom)
print("REC:", rec_anom)
