import numpy as np
import pandas as pd
from tensorflow import keras
import joblib
import json


TEST_PATH=r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\data\KDDTest+.txt"
MODEL_PATH=r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\AI_IDS_Autoencoder\autoencoder_model.h5"
SCALER_PATH=r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\AI_IDS_Autoencoder\scaler.pkl"
THRESH_PATH=r"C:\Users\SAUS\Documents\AI-powered-Intrusion-Detection-System\AI_IDS_Autoencoder\threshold.json"

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


print("[1] Loading saved model, scaler, and threshold ...")

scaler= joblib.load(SCALER_PATH)
with open(THRESH_PATH,"r") as f:
    threshold = json.load(f)["threshold"]

print(f"    Threshold: {threshold:.6f}")

autoencoder= keras.models.load_model(MODEL_PATH,compile=False)

print("\n[2] Loading KDDTest+.txt ...")
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

df =pd.read_csv(TEST_PATH, header=None, names=col_names)
print(f"Loaded {len(df)} rows")

print("[3] Encoding categorical features ...")

df["protocol_type"] = df["protocol_type"].str.strip().map(PROTOCOL_MAP).fillna(-1.0)
df["service"] = df["service"].str.strip().str.lower().map(SERVICE_MAP).fillna(6.0)
df["flag"] = df["flag"].str.strip().map(FLAG_MAP).fillna(-1.0)

df["category"] = df["label"].str.strip().map(ATTACK_MAP).fillna("unknown")

print(f"Category Distribution:\n {df["category"].value_counts()}")

feature_cols = col_names[:41]
X_raw= df[feature_cols].values.astype(np.float64)


print("\n[4] Engineering features ...")
byte_ratio = X_raw[:,4] / (X_raw[:,5] +1.0)

failed_no_login = X_raw[:,10] * (1.0 - X_raw[:,11])

privilege_score = X_raw[:,13] + X_raw[:,14] + X_raw[:,17]

file_access_score = X_raw[:,18] + X_raw[:,16]

scan_error_rate = X_raw[:, 24] + X_raw[:, 25] + X_raw[:, 26] + X_raw[:, 34]

X_engineered = np.column_stack([
    X_raw,
    byte_ratio,
    failed_no_login,
    privilege_score,
    file_access_score,
    scan_error_rate
])
print(f"Feature matrix shape: {X_engineered.shape}")

print("[5] Normalising using training scaler ...")
X_scaled= scaler.transform(X_engineered)

# Some test features may be outside training range → clip to [0, 1]
X_scaled=np.clip(X_scaled,0.0,1.0)

print(f"    Value range after scaling: [{X_scaled.min():.3f}, {X_scaled.max():.3f}]")

print("\n[6] Computing reconstruction errors ...")

X_reconstructed= autoencoder.predict(X_scaled, verbose=0)
errors= np.mean(np.power(X_scaled-X_reconstructed,2),axis=1)

print("Overall Error Stats: ")
print(f"Min: {np.min(errors):.6f}")
print(f"Mean: {np.mean(errors):.6f}")
print(f"Max: {np.max(errors):.6f}")

print("\n[7] Per-category anomaly detection on KDDTest+ ...")

print("=" * 70)
print(f"  Threshold: {threshold:.6f}")
print("=" * 70)
print(f"  {'Category':<10} {'Avg Error':>12} {'Detected':>10} {'Total':>8} {'Rate':>8}")
print("-" * 70)

categories= df["category"].values
category_order= ["normal","DoS","Probe","R2L","U2R"]

total_detected = 0
total_samples  = 0

for cat in category_order:
    mask = categories == cat

    if mask.sum() ==0:
        continue

    cat_errors=(errors[mask])

    #Calculate Avg_error per cat
    avg_error = np.mean(cat_errors)

    #how many samples in this category were reconstructed badly enough that their error exceeded the threshold.
    detected= (cat_errors>threshold).sum()

    #total number of instances per category
    total= len(cat_errors)

    #Rate per category
    rate= detected/total *100

    if cat != "normal":
        total_detected += detected
        total_samples += total

    print(f"  {cat:<10} {avg_error:>12.6f} {detected:>10} {total:>8} {rate:>7.2f}%")

print("-" * 70)

# Overall attack detection (excluding normal false alarms)
if total_samples > 0:
    print(f"\n  Overall attack detection rate: {total_detected}/{total_samples} "
          f"({total_detected/total_samples*100:.2f}%)")



print("\n" + "=" * 70)
print("  Autoencoder Evaluation Complete")
print("=" * 70)
