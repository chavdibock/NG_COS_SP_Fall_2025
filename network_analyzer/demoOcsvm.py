import numpy as np
from algorithms import algos  # Assumes your compiled module is named 'algos'

def main():
    print("=== GPU ML Library: Manual Preprocessing Workflow ===\n")

    # ---------------------------------------------------------
    # 1. Prepare Data (Features on different scales)
    # ---------------------------------------------------------
    # Feature 0: Small scale [0.0 - 0.3]
    # Feature 1: Large scale [1000 - 1050]
    # Without scaling, Feature 1 would dominate the distance metric.
    
    # Training Data (Normal behavior)
    X_train_raw = np.array([
        [0.1, 1000.0], 
        [0.2, 1020.0], 
        [0.15, 1010.0], 
        [0.1, 1005.0], 
        [0.25, 1040.0], 
        [0.3, 1050.0]
    ], dtype=np.float32)

    # Test Data (Mixture of Normal and Anomaly)
    # Point 1: [0.15, 1025.0] -> Normal
    # Point 2: [0.99, 1025.0] -> Anomaly (Outlier in Feature 0)
    X_test_raw = np.array([
        [0.15, 1025.0], 
        [0.99, 1025.0]
    ], dtype=np.float32)
    
    # Labels for ROC-AUC (1=Normal, 0=Anomaly for this specific metric function logic)
    # Or 0=Normal, 1=Anomaly. Let's assume standard ROC: 1=Positive/Anomaly. 
    # But OcSvm usually outputs: 1 (Inlier), -1 (Outlier).
    y_test_labels = [1, 0] 

    n_features = 2
    n_train_samples = X_train_raw.shape[0]
    n_test_samples = X_test_raw.shape[0]

    # ---------------------------------------------------------
    # 2. Manual Preprocessing via pca_scaling
    # ---------------------------------------------------------
    print("--- Preprocessing Data ---")

    # Apply Scaling + PCA (reducing to 2 components, effectively just rotation/scaling here)
    # Note: pca_scaling returns a flat list
    X_train_processed_flat = algos.pca_scaling(
        x=X_train_raw.ravel().tolist(),
        n_samples=n_train_samples,
        n_features=n_features,
        use_scaling=True,
        use_pca=True,
        n_pca_components=2
    )

    # Apply Scaling to Test Data
    # NOTE: Since the API doesn't support applying 'saved' scaler stats, 
    # this scales the test data based on its OWN stats. 
    # (In a production pipeline, you would want to apply train-stats to test-data, 
    # but with this specific API exposure, we transform them independently).
    X_test_processed_flat = algos.pca_scaling(
        x=X_test_raw.ravel().tolist(),
        n_samples=n_test_samples,
        n_features=n_features,
        use_scaling=True,
        use_pca=True,
        n_pca_components=2
    )

    # Debug print to see the effect
    print(f"Raw Train[0]: {X_train_raw[0]}")
    print(f"Proc Train[0]: {X_train_processed_flat[0:2]}")
    print("(Data is now centered and scaled)\n")

    # ---------------------------------------------------------
    # 3. Train OC-SVM
    # ---------------------------------------------------------
    print("--- Training OC-SVM ---")
    
    # Initialize Model
    model = algos.OcSvm(kernel=algos.KernelType.RBF, gamma=0.1, nu=0.1)

    # Pass the PROCESSED data to train
    dummy_y = [0.0] * n_train_samples
    model.train(X_train_processed_flat, dummy_y, n_features)
    
    params = model.get_params()
    print(f"Model trained. Rho: {params['rho']}\n")

    # ---------------------------------------------------------
    # 4. Predict
    # ---------------------------------------------------------
    print("--- Predicting ---")
    
    # Pass the PROCESSED test data to predict
    # The model expects data in the same feature space (scaled) as training
    preds = model.predict(X_test_processed_flat, n_test_samples)

    print("Predictions (1.0 = Normal, -1.0 = Anomaly):")
    for i, p in enumerate(preds):
        type_str = "Normal" if i == 0 else "Anomaly"
        print(f"Sample {i} ({type_str}): Score {p}")

    # ---------------------------------------------------------
    # 5. Benchmarks
    # ---------------------------------------------------------
    # We need to convert OcSvm predictions (1/-1) to scores or binary labels for AUC
    # Usually AUC expects probability or raw score, but here we have binary outputs.
    # Let's just map -1 (Anomaly) to 1 and 1 (Normal) to 0 for standard Anomaly Detection AUC.
    
    # Example conversion for the benchmark function:
    # If benchmark expects: 1=Target(Anomaly), 0=Background
    y_true_bench = [0, 1] 
    y_scores_bench = [-p for p in preds] # Flip sign so Anomaly (-1) becomes high score

    try:
        auc = algos.roc_auc(y_scores_bench, y_true_bench)
        print(f"\nROC-AUC Score: {auc}")
    except Exception as e:
        print(f"\nBenchmark error (needs more samples usually): {e}")

if __name__ == "__main__":
    main()