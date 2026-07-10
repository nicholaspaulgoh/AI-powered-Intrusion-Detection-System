import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
from tensorflow import keras
import joblib
import os
import json
import random
import tensorflow as tf

np.random.seed(42)
tf.random.set_seed(42)
random.seed(42)

TRAIN_PATH = r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\data\KDDTrain+.txt"
OUTPUT_DIR =r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\AI_IDS_Autoencoder"
MODEL_PATH =os.path.join(OUTPUT_DIR, "autoencoder_model.h5")
SCALER_PATH=os.path.join(OUTPUT_DIR, "scaler.pkl")
THRESH_PATH=os.path.join(OUTPUT_DIR, "threshold.json")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# =============================================================================
# STEP 1 — CATEGORICAL ENCODING MAPS
# must exactly match your Java Preprocessor.java maps.
# =============================================================================

PROTOCOL_MAP={ "tcp" :0.0, "udp" :1.0, "icmp" :2.0 }
SERVICE_MAP = {
    "http": 0.0, "ftp": 1.0, "smtp": 2.0, "ssh": 3.0, "domain_u": 4.0,
    "ftp_data": 5.0, "other": 6.0, "private": 7.0, "http_443": 8.0,
    "telnet": 9.0, "finger": 10.0, "pop_3": 11.0, "pop_2": 12.0,
    "imap4": 13.0, "auth": 14.0, "uucp": 15.0, "kshell": 16.0,
    "klogin": 17.0, "shell": 18.0, "login": 19.0, "exec": 20.0,
    "remote_job": 21.0, "rje": 22.0, "netbios_ssn": 23.0,
    "netbios_dgm": 24.0, "netbios_ns": 25.0, "domain": 26.0,
    "dns": 27.0, "ntp_u": 28.0, "tftp_u": 29.0, "echo": 30.0,
    "discard": 31.0, "daytime": 32.0, "time": 33.0, "systat": 34.0,
    "netstat": 35.0, "whois": 36.0, "gopher": 37.0, "printer": 38.0,
    "nntp": 39.0, "nnsp": 40.0, "bgp": 41.0, "ldap": 42.0,
    "iso_tsap": 43.0, "csnet_ns": 44.0, "sql_net": 45.0,
    "sunrpc": 46.0, "vmnet": 47.0, "uucp_path": 48.0,
    "courier": 49.0, "efs": 50.0, "hostnames": 51.0, "name": 52.0,
    "link": 53.0, "ctf": 54.0, "supdup": 55.0, "mtp": 56.0,
    "irc": 57.0, "x11": 58.0, "z39_50": 59.0, "eco_i": 60.0,
    "ecr_i": 61.0, "urh_i": 62.0, "urp_i": 63.0, "red_i": 64.0,
    "tim_i": 65.0, "pm_dump": 66.0, "harvest": 67.0,
    "http_2784": 68.0, "http_8001": 69.0, "aol": 70.0,
}

FLAG_MAP={
    "SF": 0.0, "S0": 1.0, "REJ": 2.0, "RSTO": 3.0, "RSTR": 4.0,
    "SH": 5.0, "S1": 6.0, "S2": 7.0, "S3": 8.0, "OTH": 9.0, "RSTOS0": 10.0
}

ATTACK_MAP={"normal":"normal"}
for a in ["neptune","smurf","pod","teardrop","land","back","apache2","udpstorm","processtable","mailbomb"]:
    ATTACK_MAP[a]="DoS"

for a in ["ipsweep","portsweep","nmap","satan","mscan","saint"]:
    ATTACK_MAP[a] ="Probe"

for a in ["guess_passwd","ftp_write","imap","phf","multihop","warezmaster","warezclient","spy","xlock","xsnoop","snmpgetattack","named","sendmail","httptunnel","worm","snmpguess"]:
    ATTACK_MAP[a] ="R2L"

for a in ["buffer_overflow","rootkit","loadmodule","perl", "xterm","ps","sqlattack"]:
    ATTACK_MAP[a] ="U2R"

# =============================================================================
# STEP 2 — LOAD AND PARSE THE RAW CSV
# NSL-KDD has no header row. 43 columns: 41 features + label + difficulty.
# We name them ourselves.
# =============================================================================
print("[1] Loading KDDTrain+.txt ...")

#41 features + 1 label + 1 difficulty
col_names = [
    "duration","protocol_type","service","flag",
    "src_bytes","dst_bytes","land","wrong_fragment",
    "urgent","hot","num_failed_logins","logged_in",
    "num_compromised","root_shell","su_attempted",
    "num_root","num_file_creations","num_shells",
    "num_access_files","num_outbound_cmds","is_hot_login",
    "is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate",
    "same_srv_rate","diff_srv_rate","srv_diff_host_rate",
    "dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
    "dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate",
    "label","difficulty"   # columns 41 and 42
]

df =pd.read_csv(TRAIN_PATH, header=None, names=col_names)
print(f"Loaded: {len(df)} rows and  {len(df.columns)} columns") # or df.shape[0] for rows and df.shape[1] for col

# =============================================================================
# STEP 3 — ENCODE CATEGORICAL COLUMNS
# protocol_type, service, flag are strings — convert to numbers
# exactly as Java does.
# =============================================================================
print("[2] Encoding categorical features ...")

#Change value to string then "trim()" it then map it. If NaN then replace with -1.0
df["protocol_type"] = df["protocol_type"].str.strip().map(PROTOCOL_MAP).fillna(-1.0)
df["service"] = df["service"].str.strip().str.lower().map(SERVICE_MAP).fillna(6.0)
df["flag"] = df["flag"].str.strip().map(FLAG_MAP).fillna(-1.0)

# =============================================================================
# STEP 4 — MAP ATTACK LABELS TO CATEGORIES
# =============================================================================

df["category"] = df["label"].str.strip().str.lower().map(ATTACK_MAP).fillna("unknown")
print(f" Category distribution:\n{df["category"].value_counts()}")
#value_counts sort largest -> smallest automatically

# =============================================================================
# STEP 5 — EXTRACT THE 41 RAW FEATURES AS A NUMPY ARRAY
# df.iloc[:, 0:41] means: all rows, columns 0 to 40 (inclusive)
# .values converts DataFrame → numpy array (like a 2D double[][] in Java)
# =============================================================================
print("[3] Extracting raw feature matrix ...")
feature_cols= col_names[:41]
X_raw =df[feature_cols].values.astype(np.float64)
print(f"    Feature matrix shape: {X_raw.shape}")  # (125973, 41)

# =============================================================================
# STEP 6 — ENGINEER THE SAME 5 FEATURES AS JAVA
# Must match engineerFeatures() in Preprocessor.java exactly.
# numpy operations work on entire columns at once (no loops needed).
# =============================================================================
print("[4] Engineering 5 new features ...")

# Feature 41: byte_ratio = src_bytes / (dst_bytes + 1)
byte_ratio = X_raw[:,4] / (X_raw[:,5] +1.0)

# Feature 42: failed_no_login = num_failed_logins * (1 - logged_in)
failed_no_login = X_raw[:,10] * (1.0 - X_raw[:,11])

# Feature 43: privilege_score = root_shell + su_attempted + num_shells
privilege_score = X_raw[:,13] + X_raw[:,14] + X_raw[:,17]

# Feature 44: file_access_score = num_access_files + num_file_creations
file_access_score = X_raw[:,18] + X_raw[:,16]

# Feature 45: scan_error_rate = serror_rate + srv_serror_rate + rerror_rate + dst_host_diff_srv_rate
scan_error_rate = X_raw[:, 24] + X_raw[:, 25] + X_raw[:, 26] + X_raw[:, 34]

# np.column_stack joins multiple arrays as new columns
# X_raw has shape (125973, 41); after stack → (125973, 46)

X_engineered =np.column_stack([
    X_raw,
    byte_ratio,
    failed_no_login,
    privilege_score,
    file_access_score,
    scan_error_rate
]
)

print(f"    Expanded feature matrix shape: {X_engineered.shape}")  # (125973, 46)

# =============================================================================
# STEP 7 — NORMALISE WITH MinMaxScaler
# This is equivalent to computeMaxMin() + normalize() in Java.
# The scaler LEARNS the min/max from training data (.fit)
# then APPLIES it (.transform). We save the scaler so test data
# can be scaled with the same min/max values.
# =============================================================================
print("[5] Normalising features ...")

scaler = MinMaxScaler()
X_scaled= scaler.fit_transform(X_engineered) ##fit_transform() is fit() + transform()
print(f"    Value range after scaling: [{X_scaled.min():.3f}, {X_scaled.max():.3f}]")

# =============================================================================
# STEP 8 — FILTER TO NORMAL TRAFFIC ONLY
# The autoencoder only trains on normal traffic.
# df["category"] == "normal" creates a boolean mask (True/False per row)
# X_scaled[mask] selects only the rows where mask is True
# =============================================================================
print("[6] Filtering to normal traffic only ...")

normal_mask = df["category"].values =="normal"
X_normal= X_scaled[normal_mask]
print(f"    Normal samples: {X_normal.shape[0]} / {X_scaled.shape[0]}")

# =============================================================================
# STEP 9 — BUILD THE AUTOENCODER
# Input:   46 features
# Encoder: 46 → 32 → 16 → 8   (compressing)
# Decoder: 8  → 16 → 32 → 46  (reconstructing)
#
# 'relu' activation: max(0, x) — standard hidden layer activation
# 'sigmoid' output:  squashes output to [0,1] — matches normalised input range
# =============================================================================
print("[7] Building autoencoder architecture ...")

INPUT_DIM=46

# keras.Input defines the shape of one input sample (46 numbers)
inputs =keras.Input(shape=(INPUT_DIM,))

# --- Encoder ---
encoded = keras.layers.Dense(32, activation="relu")(inputs)
encoded=keras.layers.Dense(16,activation="relu")(encoded)
encoded=keras.layers.Dense(8,activation="relu")(encoded)

# --- Decoder ---
decoded=keras.layers.Dense(16, activation="relu")(encoded)
decoded =keras.layers.Dense(32,activation="relu")(decoded)
decoded=keras.layers.Dense(INPUT_DIM, activation="sigmoid")(decoded)

# Build model: input → compressed → reconstructed output
autoencoder= keras.Model(inputs=inputs, outputs=decoded)

# 'adam' = adaptive learning rate optimiser (standard choice)
# 'mse'  = Mean Squared Error — measures how different input and output are
autoencoder.compile(optimizer="adam", loss="mse")
autoencoder.summary()

#== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
# STEP 10 — TRAIN
# X_normal is BOTH input and target (autoencoder learns to copy itself)
# epochs=50: passes through all normal training data 50 times
# batch_size=256: updates weights after every 256 samples
# validation_split=0.1: holds out 10% of normal data to monitor overfitting
# =============================================================================
print("\n[8] Training autoencoder on normal traffic only ...")

history=autoencoder.fit(
    X_normal, X_normal,
    epochs=150,
    batch_size=256,
    validation_split=0.1,
    shuffle=True,
    verbose=1
)

# =============================================================================
# STEP 11 — COMPUTE RECONSTRUCTION ERROR THRESHOLD
# Run all normal training samples through the trained autoencoder.
# The reconstruction error for each sample = mean((original - reconstructed)^2)
# Threshold = 95th percentile of those errors.
# → 95% of normal traffic falls below threshold (acceptable false alarm rate)
# → Attacks with higher errors get flagged as anomalies
# =============================================================================
print("\n[9] Computing reconstruction error threshold ...")

X_normal_reconstructed = autoencoder.predict(X_normal,verbose=0)

# np.mean(..., axis=1) computes MSE per row (per sample), not overall
reconstruction_errors = np.mean(np.power(X_normal - X_normal_reconstructed,2),axis=1)

threshold = float(np.percentile(reconstruction_errors,95))
print(f"    Reconstruction error stats on normal traffic:")
print(f"    Min:    {reconstruction_errors.min():.6f}")
print(f"    Mean:   {reconstruction_errors.mean():.6f}")
print(f"    95th %: {threshold:.6f}  ← this is your threshold")
print(f"    Max:    {reconstruction_errors.max():.6f}")

# =============================================================================
# STEP 12 — EVALUATE ON ALL CATEGORIES
# Run the full scaled dataset through and see average error per category.
# This tells you how well the autoencoder separates normal from attacks.
# =============================================================================
print("\n[10] Evaluating reconstruction error per attack category ...")

all_reconstructed = autoencoder.predict(X_scaled,verbose=0)
all_errors =np.mean(np.power(X_scaled-all_reconstructed,2),axis=1)

categories=df["category"].values
for cat in ["normal", "DoS", "Probe" , "R2L","U2R"]:
    mask = categories ==cat

    if mask.sum() == 0:
        continue

    cat_errors = all_errors[mask]

    above_threshold = (cat_errors > threshold).sum() #how many were detected successfully
    pct= above_threshold/ len(cat_errors) *100.0

    print(f"    {cat:<8}  avg_error={cat_errors.mean():.6f}  "
          f"flagged_as_anomaly={above_threshold}/{len(cat_errors)} ({pct:.1f}%)")

#== == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == == =
# STEP 13 — SAVE EVERYTHING
# model   → .h5 file  (the trained neural network weights)
# scaler  → .pkl file (the min/max values for normalisation)
# threshold → .json   (the 95th percentile cutoff value)
# =============================================================================
print("\n[11] Saving model, scaler, and threshold ...")

autoencoder.save(MODEL_PATH)

joblib.dump(scaler, SCALER_PATH)

with open(THRESH_PATH, "w") as f:
    json.dump({"threshold":threshold},f)

print(f"    Model saved to:     {MODEL_PATH}")
print(f"    Scaler saved to:    {SCALER_PATH}")
print(f"    Threshold saved to: {THRESH_PATH}")
print("\n===== Autoencoder Training Complete =====")