# DDoS Detection System using Django & Machine Learning

## Overview
This is a full-stack **DDoS detection system** built using **Django** (backend) and **pgAdmin4** (database). The system leverages **ensemble machine learning** to detect malicious network flows and prevent distributed denial-of-service (DDoS) attacks in real-time.

## Features
- **Machine Learning-Based Detection**: Uses **Gaussian Naïve Bayes, Random Forest, and a Neural Network** to classify network flows.
- **Django Framework**: Robust backend for data processing and API handling.
- **pgAdmin4 Database**: Stores network flow logs and attack patterns.
- **Real-Time Monitoring**: Detects and flags unusual traffic patterns.
- **Admin Dashboard**: View attack trends, logs, and system performance.
- **Ensemble Learning Approach**: Increases accuracy and minimizes false positives.
- **Secure Communication**: Implements **CORS and 2FA with bcrypt**.

## Architecture
1. **Data Ingestion**: Captures network traffic from logs or real-time packets.
2. **Feature Extraction**: Prepares data for ML classification.
3. **Ensemble ML Models**: Predicts DDoS attacks using multiple algorithms.
4. **Alert System**: Notifies admins of detected threats.
5. **Dashboard**: Displays logs and attack statistics.

## Installation
### Prerequisites
- Python 3.8+
- Django 5.1.1
- PostgreSQL with pgAdmin4
- Scikit-learn, Pandas, NumPy

Run 
**pip install -r --no-cache-dir requirements.txt**
Or
- use the .venv file in the repo

### Steps
```bash
# Clone the repository
git clone git@github.com:stee1011/ddos-detection-system.git
cd ddos-detection-system

# Set up a virtual environment
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run Django migrations
python manage.py migrate

# Start the server
python manage.py runserver
```

## Model Training & Evaluation
1. **Prepare Dataset**: Preprocess network traffic logs.
2. **Train ML Models**:
   ```python
   from models import train_models
   train_models()
   ```
3. **Evaluate Performance**:
   ```python
   from models import evaluate
   evaluate()
   ```

## Dashboard Preview
Access the dashboard at:
```
http://127.0.0.1:8000/admin
```

## Security Features
- **2FA Authentication with bcrypt**
- **ModSecurity WAF Integration**
- **DDoS Intrusion Detection System (IDS) using ensemble learning**
- **CORS & Secure API Endpoints**

## Contributing
1. Fork the repository
2. Create a new branch (`feature-xyz`)
3. Commit your changes (`git commit -m "Add feature xyz"`)
4. Push and open a PR

## License
This project is **open-source** and available under the **MIT License**.

## Contact
**Developer:** stee1011  
 Email: stevenjoro101@gmail.com  
 GitHub: [stee1011](https://github.com/stee1011)
 ![img](base (3).jpg)

