# DNShield - RNN-Based DNS Firewall

DNShield is an advanced network security solution leveraging a Recurrent Neural Network (RNN) to analyze DNS queries in real time, accurately classifying each as either benign or malicious. This powerful firewall protects networks from threats such as phishing, spam, and malware by intercepting and blocking suspicious DNS queries instantly.

## Features
- **Real-Time DNS Analysis**: Instantly evaluates DNS queries to detect and block malicious requests.
- **RNN-Based Detection**: Utilizes Bidirectional LSTM networks to capture temporal patterns in DNS traffic.
- **Robust Data Handling**: Built upon the comprehensive BCCC-CIC-Bell-DNS-2024 dataset, providing accurate and wide-ranging threat detection.
- **High Scalability**: Efficiently manages high DNS query volumes without compromising speed or performance.
- **User-Friendly Interface**: Includes a real-time monitoring dashboard to visualize and log DNS queries.

## Project Architecture

DNShield employs a sophisticated architecture:
- **Input Layer**: Processes sequences of 5 consecutive DNS queries.
- **Bidirectional LSTM Layers**: Capture complex temporal relationships in DNS traffic.
- **Dropout Layers**: Prevent overfitting by regularizing training.
- **Dense Layers**: Generate final predictions with high accuracy.

## Dataset

DNShield utilizes the **BCCC-CIC-Bell-DNS-2024** dataset containing:
- Over 1 million DNS records categorized into benign, phishing, spam, and malware.
- 121 detailed columns capturing extensive metadata and flow characteristics.

## Model Performance

- **Overall Accuracy**: Approximately 88% validation accuracy.
- **Precision & Recall**: High effectiveness in distinguishing benign and malicious queries.
- **ROC-AUC**: Achieves strong discriminative power, with scores ranging from 0.90 to 0.99 across classes.

## Installation & Usage

Clone the repository:
```bash
git clone https://github.com/gauravmehraa/dnshield.git
cd dnshield
```

Install dependencies:
```bash
pip install -r requirements.txt
```
Run the firewall application:
```bash
python firewall.py
```

## Libraries & Technologies
- **Data Handling**: Pandas, NumPy
- **Model Building**: TensorFlow (Keras API)
- **Real-Time Traffic Analysis**: Scapy
- **Visualization**: Matplotlib
- **Interface**: Tkinter

## Future Improvements
- Integration with WHOIS and IP reputation databases
- Incremental learning for adaptive threat detection
- Support for encrypted DNS traffic (DoH, DoT)
- Implementation of anomaly detection for novel threats
