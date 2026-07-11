import os

# Suppress TensorFlow startup noise so Java can cleanly parse stdout
os.environ["Tf_CPP_MIN_LOG_LEVEL"]="3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import sys
import numpy as np
import json
import joblib
import tensorflow as tf

tf.get_logger().setLevel("ERROR")



#Paths
BASE_DIR    = r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\AI_IDS_Autoencoder"
MODEL_PATH  = os.path.join(BASE_DIR, "autoencoder_model.h5")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")
THRESH_PATH = os.path.join(BASE_DIR, "threshold.json")

# =============================================================================
# USAGE:
#   python detect_anomaly.py f0 f1 f2 ... f45
#   (46 space-separated feature values, already engineered but NOT normalised)
#
# OUTPUT (one line to stdout, parsed by Java):
#   normal|0.001234
#   anomaly|0.023456
# =============================================================================

def main():

    # -------------------------------------------------------------------------
    # 1. Parse command-line arguments
    # Java calls: Runtime.exec("python detect_anomaly.py 0.0 1.0 0.5 ...")
    # sys.argv[0] = script name, sys.argv[1:] = the 46 feature values
    # -------------------------------------------------------------------------

    if len(sys.argv) !=47: # 1 script name + 46 features
        print(f"ERROR|expected 46 features, got {len(sys.argv) - 1}", flush=True)
        sys.exit(1)

    try:
        features=np.array([float(x) for x in sys.argv[1:]], dtype=np.float64)
    except ValueError as e:
        print(f"ERROR|could not parse features: {e}", flush=True)
        sys.exit(1)

        # -------------------------------------------------------------------------
        # 2. Load model, scaler, threshold
        # These were saved by train_autoencoder.py
        # -------------------------------------------------------------------------
    autoencoder = tf.keras.models.load_model(MODEL_PATH,compile=False)
    scaler = joblib.load(SCALER_PATH)

    with open(THRESH_PATH, "r") as f:
        threshold = json.load(f)["threshold"]

    # -------------------------------------------------------------------------
    # 3. Normalise using the TRAINING scaler
    # features.reshape(1, -1) converts [f0, f1, ..., f45] → [[f0, f1, ..., f45]]
    # because scaler.transform() expects a 2D array (rows × features)
    # -------------------------------------------------------------------------

    features_2d = features.reshape(1,-1) #shape: (1, 46)
    scaled = scaler.transform(features_2d)
    scaled=np.clip(scaled,0.0,1.0)

    # -------------------------------------------------------------------------
    # 4. Reconstruct and compute error
    # -------------------------------------------------------------------------

    reconstructed = autoencoder.predict(scaled, verbose=0)
    error= float(np.mean(np.power(scaled-reconstructed,2)))

    # -------------------------------------------------------------------------
    # 5. Compare to threshold and print result
    # Format: "verdict|error" on one line
    # Java splits on "|" to get verdict and error separately
    # flush=True ensures Java's BufferedReader receives it immediately
    # -------------------------------------------------------------------------
    verdict = "anomaly" if error > threshold else "normal"
    print(f"{verdict}|{error:.6f}", flush=True)

if __name__ == "__main__":
    main()








