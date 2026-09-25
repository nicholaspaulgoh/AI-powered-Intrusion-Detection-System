

# AI-Powered Intrusion Detection System (IDS)

Final-year capstone project (QACT2244) — a Java/Weka-based Intrusion Detection System combining supervised classification, deep-learning anomaly detection, and real-time live traffic analysis.

**Student:** Nicholas Paul Goh Chang Yew | **Institution:** UCSI College, Bachelor of Information Technology 
**Project duration:** 8 May – 31 July 2026

---

## Overview

This system detects and classifies network intrusions using a hybrid approach:

- **Supervised classification** via Random Forest, trained on the NSL-KDD dataset, to categorize traffic into Normal, DoS, Probe, R2L, and U2R classes.
- **Unsupervised anomaly detection** via a Python autoencoder, used to flag traffic that doesn't fit learned normal patterns.
- **Live packet capture** via pcap4j, enabling real-time classification of actual network traffic rather than only static datasets.

The project started from near-zero Java experience and was built up into a full end-to-end system with a working live-capture pipeline, a REST API, and a real-time dashboard.

---

## Architecture

```
                     ┌─────────────────────┐
   Live Traffic ───► │  pcap4j Capture     │
                     │  (ConnectionTracker)│
                     └──────────┬──────────┘
                                │ 5-tuple state machine
                                │ classify at TCP close (SF/RSTO/REJ)
                                │ or 10s idle timeout
                                ▼
                     ┌─────────────────────┐
                     │  Feature Extraction │
                     │  41 → 46 features   │
                     └──────────┬──────────┘
                                │
                 ┌──────────────┴───────────────┐
                 ▼                              ▼
     ┌───────────────────────┐      ┌─────────────────────────┐
     │ Random Forest (Weka)  │      │ Autoencoder (Python/    │
     │ + Cost-Sensitive      │      │ TensorFlow/Keras)       │
     │ Classification        │      │ via Flask REST API      │
     └───────────┬───────────┘      └────────────┬────────────┘
                 │                               │
                 └───────────────┬───────────────┘
                                 ▼
                     ┌─────────────────────┐
                     │ Post-classification │
                     │ correlation filters │
                     └──────────┬──────────┘
                                ▼
                     ┌─────────────────────┐
                     │ Flask SSE Dashboard │
                     └─────────────────────┘
```

---

## Key Results (KDDTest+)

| Metric | Result |
|---|---|
| Overall accuracy | **86.61%** |
| R2L detection | 63.70% (17.7× improvement over baseline) |
| U2R detection | 71.64% (12× improvement over baseline) |
| Probe detection | 91.45% |

**Model selection:** Random Forest was chosen over J48 and Naive Bayes based on superior per-class F1 scores on rare attack categories (U2R: 0.690 vs J48's 0.525; R2L: 0.978 vs J48's 0.937) and the lowest overfitting gap (0.09%) between cross-validation and test accuracy.

A two-stage binary Cost-Sensitive-Classifier + Random Forest (CSC-RF) architecture was also experimented with and is documented in the thesis as a negative result.

---

## Feature Engineering

Five engineered features were added on top of the standard 41 NSL-KDD features (41 → 46 total):

- `byte_ratio`
- `failed_no_login`
- `privilege_score`
- `file_access_score`
- `scan_error_rate`

## Class Imbalance Handling

- **SMOTE** was applied before cost-sensitive classification (via `oversampleMinorityClasses()` in `Main.java`, applied to `balancedInstances`).
  - Best configuration: R2L = 900% oversampling, k=12 neighbors; U2R = 1800% oversampling, k=9 neighbors.
- **Cost-sensitive classification** weights (post feature engineering): R2L = 30, U2R = 40.

## Anomaly Detection

- Python autoencoder: 150 epochs, seed=42, bottleneck layer size 8, reconstruction error threshold = 0.010.
- `AnomalyDetector.java` communicates with the autoencoder via Java 17's built-in `HttpClient`, POSTing to a local Flask server at `localhost:5000/detect`.

## Live Capture Pipeline

- Built with **pcap4j**, using a `ConnectionTracker` keyed on a canonical 5-tuple.
- Connections are only classified at TCP close (`SF`/`RSTO`/`REJ` flags) via a `shouldClassify()` guard, or after a 10-second idle timeout.
- IGMP (protocol 2) and multicast traffic (224.x.x.x) are filtered out before classification.
- `serror_rate` is forced to 0.0 when the final flag is `SF`.
- `serverIp` is used consistently across all sliding-window feature lookups (this fixed an earlier direction-mismatch bug).

### Known limitation: live detection vs. dataset assumptions

Because NSL-KDD's statistical features were derived from full connection records rather than live packet streams, the live pipeline has documented limitations:
- A packet-level vs. connection-level mismatch (statistical features are computed progressively from packets rather than from a complete connection).
- Connection duration is measured from the first packet observed, not the true full connection duration.
- As a consequence, some normal traffic can be misclassified as Probe.
- This is framed in the thesis as a known challenge in the intrusion-detection field; NetFlow/IPFIX-based feature extraction is noted as the production-grade solution.

### Known limitation: TLS encryption

NSL-KDD features 10–21 (`num_failed_logins`, `logged_in`, `root_shell`, `su_attempted`, `num_shells`, etc.) rely on application-layer payload inspection. This was feasible on the unencrypted 1998 traffic NSL-KDD was built from, but is not accessible on modern TLS-encrypted traffic without acting as a TLS-terminating proxy — a limitation discussed in the thesis as evidence of domain understanding rather than an oversight.

---

## Tech Stack

---------------------------------------------------------------------------
|       Component      |                     Technology                    |
|----------------------|---------------------------------------------------|
| Core classifier      | Java 17, Weka 3.8.7                               |
| Anomaly detector     | Python 3.13, TensorFlow/Keras                     |
| API / dashboard      | Flask (REST + Server-Sent Events)                 |
| Live packet capture  | pcap4j                                            |
| Dataset              | NSL-KDD (`KDDTrain+.txt`, `KDDTest+.txt`)         |
| IDE                  | IntelliJ IDEA Community Edition                   |
| Development hardware | AMD Ryzen 5 7520U, 8 logical processors, Windows  |
----------------------------------------------------------------------------
---

## Getting Started

### Prerequisites
- Java 17 (JDK)
- Weka 3.8.7 (library, bundled or on classpath)
- Python 3.13 with TensorFlow/Keras and Flask installed
- NSL-KDD dataset files (`KDDTrain+.txt`, `KDDTest+.txt`) — not redistributed here; download separately

### Setup

```bash
# Clone the repository
git clone <your-repo-url>
cd AI-powered-Intrusion-Detection-System

# Python side: set up the anomaly detection service
pip install -r requirements.txt   # tensorflow, flask, etc.
python autoencoder_server.py      # starts Flask API on localhost:5000

# Java side: build and run the main classifier / live capture
# (adjust for your build tool — Maven/Gradle/plain javac)
```

### Running against the test set

```bash
java -cp <classpath> Main --test KDDTest+.txt
```

### Running live capture

Requires appropriate packet capture permissions (e.g. Npcap on Windows, or root/CAP_NET_RAW on Linux).

```bash
java -cp <classpath> Main --live
```

> Note: replace the placeholder commands above with your actual entry points/build commands once finalized — adjust to match your Maven/Gradle setup or manual classpath.

---

## Project Structure (adjust to match your actual layout)

```
AI-powered-Intrusion-Detection-System/
├── src/
│   ├── Main.java
│   ├── ConnectionTracker.java
│   ├── AnomalyDetector.java
│   └── ...
├── python/
│   ├── autoencoder_server.py
│   └── train_autoencoder.py
├── data/
│   ├── KDDTrain+.txt
│   └── KDDTest+.txt
├── docs/
│   ├── thesis_report.pdf
│   └── presentation_slides.pptx
└── README.md
```

---

## Documentation

- Full thesis report (APA 7th edition)
- Main presentation deck (51 slides) plus 7 experiment-results slides and 10 live-capture demo slides
- Project proposal with literature review

---

## Future Work

- Implement destination-host window statistics (NSL-KDD features 31–40) via a 100-connection rolling window per destination IP in `ConnectionTracker`.
- Migrate live feature extraction to NetFlow/IPFIX to resolve the packet-level vs. connection-level mismatch.
- Explore TLS-proxy-based inspection for payload-dependent features in encrypted traffic.

---

## Acknowledgements

Developed as a final-year capstone project (QACT2244) at UCSI College.
