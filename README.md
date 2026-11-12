# AI-Powered Intrusion Detection System (IDS)

A hybrid network intrusion detection system built as a final-year capstone project (QACT2244, Bachelor of Information Technology, UCSI College). It combines a supervised **Random Forest** classifier (Java, Weka) with an **autoencoder** anomaly detector (Python, TensorFlow/Keras) and runs on **live packet capture** with a real-time web dashboard.

## What it does

- Classifies network connections into five categories: **normal, DoS, Probe, R2L, U2R**, using the NSL-KDD benchmark.
- Improves detection of the rare R2L and U2R categories with **SMOTE** oversampling, **cost-sensitive classification** and **five engineered features** (41 to 46 features).
- Flags traffic that deviates from normal behavior with an **autoencoder** trained only on normal traffic.
- Captures live packets with **Pcap4J**, rebuilds connections, and streams results to a **Flask** dashboard using Server-Sent Events.

## Results on KDDTest+

| Stage | Overall | R2L | U2R |
|---|---|---|---|
| Baseline Random Forest | 75.07% | 3.60% | 5.97% |
| SMOTE + cost-sensitive + feature engineering (final) | 86.61% | 63.70% | 71.64% |

Final per-category detection rates: normal 92.49%, DoS 86.38%, Probe 91.45%, R2L 63.70%, U2R 71.64%. The gain in attack detection costs about 4.84 percentage points of normal-traffic accuracy.

How to read these numbers:

- Cross-validation on the training set gives about 99.9% accuracy, while the baseline scores 75.07% on KDDTest+. KDDTest+ contains attack subtypes that are absent from the training set, so cross-validation measures recognition of known subtypes and KDDTest+ measures generalization. The difference between them is not an "overfitting gap".
- SMOTE and cost-matrix settings were selected using KDDTest+ results (there was no separate validation set), so the test figures are likely optimistic.
- Each configuration was run once with fixed seeds. KDDTest+ contains only 67 U2R records, so one record is about 1.5 percentage points.
- A two-stage design (binary, then multiclass) was also tested and did not outperform the single-stage classifier.

## Architecture

```
Live traffic -> Pcap4J capture + connection tracking (5-tuple)
             -> feature extraction (46 features)
             -> Random Forest (Weka, cost-sensitive)   \
             -> Autoencoder (Flask /detect endpoint)    -> correlation filter -> Flask dashboard (SSE)
```

- Connections are classified when a TCP connection closes (SF / RSTO / REJ) or after 10 seconds of inactivity.
- The autoencoder service returns a normal/anomaly verdict and the reconstruction error. The threshold is stored in `threshold.json`. The test-set threshold is 0.004868 (95th percentile of normal training errors) and the live threshold is 0.013.

## Repository contents

- `AI IDS/` - the Java (Maven) project. Source files are in `src/`:
  - `Main.java` - main application that coordinates training and evaluation
  - `DataLoader.java`, `Preprocessor.java` - loading NSL-KDD, encoding, feature engineering and normalization
  - `ClassifierEngine.java` - Random Forest, SMOTE and cost-sensitive classification
  - `AnomalyDetector.java` - client for the Python autoencoder service
  - `NetworkCapture.java`, `ConnectionTracker.java`, `LiveDetection.java`, `TrafficInput.java` - live packet capture and connection tracking
  - `DatasetExplorer.java`, `DetectionEngine.java`, `combinedExamples.java`, `dataReader.java` - supporting and exploratory code
- `AI_IDS_Autoencoder/` - the Python autoencoder service:
  - `train_autoencoder.py` - trains the autoencoder on normal traffic
  - `evaluate_autoencoder.py` - evaluates it on KDDTest+
  - `detect_anomaly.py` - anomaly detection helper
  - `flask_server.py` - Flask REST API (`/detect`) and the dashboard
  - `templates/` - dashboard pages
  - `autoencoder_model.h5`, `scaler.pkl`, `threshold.json` - the saved autoencoder, scaler and threshold
- `models/` - saved Weka models: `random_forest.model` (final model), `binary_rf.model` (Stage 1 of the two-stage experiment) and `multiclass_csc_rf.model` (five-class cost-sensitive classifier)
- `data/` - NSL-KDD files (`KDDTrain+.txt`, `KDDTest+.txt`) and the field-name list
- `graphs/` - figures from the project
- `FYP Report-*.docx`, `TESTING DATA.docx` - the final-year report and testing notes
- `*.txt` result files - Weka outputs for J48, Naive Bayes and Random Forest

## Requirements

- Java 17 (JDK) and IntelliJ IDEA (or any IDE that can open a Maven project)
- Weka 3.8.7 with the SMOTE package
- Python 3.13 with TensorFlow/Keras, Flask, NumPy, Pandas and scikit-learn
- Pcap4J, plus a packet-capture driver (Npcap on Windows, libpcap on Linux and macOS)

## How to run

1. Clone the repository:

   ```
   git clone https://github.com/nicholaspaulgoh/AI-powered-Intrusion-Detection-System.git
   cd AI-powered-Intrusion-Detection-System
   ```

2. Start the autoencoder service:

   ```
   cd AI_IDS_Autoencoder
   python -m venv .venv
   .venv\Scripts\activate
   pip install tensorflow flask numpy pandas scikit-learn
   python flask_server.py
   ```

   The service listens on `http://localhost:5000`.

3. Open the `AI IDS` folder in IntelliJ IDEA as a Maven project and let it import the dependencies listed in `pom.xml`.

4. Run `Main` to load NSL-KDD, train and evaluate the classifier.

5. Run `LiveDetection` for live capture (this needs packet-capture permissions). Results appear on the dashboard served by Flask.

## Known limitations

- **Packet vs. connection mismatch:** NSL-KDD features describe whole connections, while live capture sees packets. Window statistics are estimated, and duration is measured from the first captured packet.
- **Application-layer features unavailable:** 15 of the 41 original features need payload-level information (failed logins, root shells and similar). They are set to zero in live capture, and TLS encryption would hide them anyway. The engineered `failed_no_login` and `privilege_score` features depend on these inputs.
- **Old benchmark:** NSL-KDD derives from 1999 traffic and may not represent modern networks.
- **Unevaluated components:** the combined classifier and autoencoder decision, the live autoencoder threshold and the post-classification correlation filter have not been evaluated on labeled data. No live detection rates are claimed.

## Future work

- Flow-based feature extraction with NetFlow/IPFIX.
- Retraining and testing on a contemporary dataset such as CICIDS2017.
- Rolling-window destination-host statistics (NSL-KDD features 31 to 40).
- Authorized TLS inspection where legally appropriate.
- Evaluating Isolation Forest and One-Class SVM as alternative anomaly detectors.

## Data

The NSL-KDD files in `data/` are copies of the public benchmark, included for convenience. The original source is the Canadian Institute for Cybersecurity, University of New Brunswick. If you use the data, please cite:

M. Tavallaee, E. Bagheri, W. Lu, and A. A. Ghorbani, "A detailed analysis of the KDD CUP 99 data set," in *Proc. IEEE Symp. Comput. Intell. Secur. Defense Appl.*, 2009, pp. 1-6.

## Use of generative AI

Claude (Anthropic) was used as a tutor and learning aid during this project, and to write the git commit messages.

## License

The source code is released under the MIT License (see `LICENSE`). The license does not cover the NSL-KDD data files, which belong to their original authors, or the report documents.

## Citation

A manuscript based on this work is in preparation. A full citation will be added here after publication.

## Author

Nicholas Paul Goh Chang Yew - nicholaspaulgoh@gmail.com
