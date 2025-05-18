# Security Anomaly Detection System

This project implements a real-time security anomaly detection system using Apache Beam and Gemini AI to identify and classify potential security threats.

## Components

1. **Data Generation (data_generation.py)**: 
   - Simulates user activity data with different access levels
   - Publishes data to a PubSub topic

2. **Anomaly Detection Pipeline (detect_and_explain_anomaly.py)**:
   - Consumes user activity data from PubSub
   - Detects anomalies using machine learning
   - Classifies potential security threats using Gemini AI
   - Publishes alerts to another PubSub topic

3. **Security Dashboard (security_dashboard.py)**:
   - Real-time monitoring of security alerts 
   - Interactive UI for security administrators
   - Provides workflows for investigating and addressing alerts
   - Analytics and insights on security incidents

## Setup

### Prerequisites
- Google Cloud Platform account
- Python 3.8+
- Apache Beam
- Streamlit

### Environment Variables
Create a `.env` file with the following variables:
```
GOOGLE_CLOUD_PROJECT=<your-gcp-project>
GOOGLE_CLOUD_LOCATION=<your-preferred-region>
GCS_ROOT=gs://<your-bucket>
PUBSUB_TOPIC=projects/<project-id>/topics/<topic-name>
PUBSUB_SUBSCRIPTION=projects/<project-id>/subscriptions/<subscription-name>
PUBSUB_TOPIC_ALERT=projects/<project-id>/topics/<alert-topic-name>
PUBSUB_SUBSCRIPTION_ALERT=projects/<project-id>/subscriptions/<alert-subscription-name>
```

### Installation
```bash
# Install dependencies
pip install -r requirements.txt
```

## Running the Application

### 1. Start the Data Generation Pipeline
```bash
python data_generation.py
```

### 2. Start the Anomaly Detection Pipeline
```bash
python detect_and_explain_anomaly.py
```

### 3. Launch the Security Dashboard
```bash
streamlit run security_dashboard.py
```

Access the dashboard at http://localhost:8501

## Features

- **Real-time Anomaly Detection**: Identifies unusual patterns in user activity data
- **AI-Powered Threat Classification**: Categorizes anomalies into specific security threats
- **Interactive Dashboard**: User-friendly interface for security monitoring
- **Workflow Management**: Tools for investigating and addressing security incidents
- **Analytics**: Visual insights into security alert patterns and trends 