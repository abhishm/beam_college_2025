import json
import os
import random
import time
from faker import Faker
from google.cloud import pubsub_v1
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Faker for generating usernames
fake = Faker()

# Configure PubSub client
project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
topic_id = os.environ["PUBSUB_TOPIC_ALERT"].split('/')[-1]
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(project_id, topic_id)

# Sample attack classifications
ATTACK_CLASSIFICATIONS = {
    "Privilege Escalation": """
Privilege Escalation

The user has performed actions that exceed their normal permission level. This indicates a possible compromise of credentials or exploitation of a system vulnerability to gain higher access rights.
    """,
    
    "Data Exfiltration": """
Data Exfiltration

The user has downloaded an unusually high volume of data, suggesting a possible attempt to extract sensitive information from the system. This behavior is atypical compared to the user's normal baseline.
    """,
    
    "Ransomware Attack": """
Ransomware Attack

The user's activity shows an abnormally high number of encryption operations, which is consistent with ransomware behavior that encrypts files to hold them hostage. Immediate investigation is recommended.
    """,
    
    "Unauthorized Access": """
Unauthorized Access

The user account has shown activity when it should have none. This indicates that the account may have been compromised and is being used by an unauthorized party.
    """
}

# Generate sample alerts with various attack types
def generate_sample_alert():
    """Generate a single sample security alert"""
    access_types = ["no_access", "reader", "editor"]
    access_type = random.choice(access_types)
    
    # Generate user activity data based on access type
    if access_type == "no_access":
        # Anomaly: Should have no activity
        data = {
            "user_name": fake.user_name(),
            "access_type": access_type,
            "num_read": random.randint(1, 10),
            "num_edits": random.randint(1, 5),
            "num_downloads": random.randint(0, 3),
            "num_encryption": random.randint(0, 2)
        }
        attack_type = "Unauthorized Access"
    
    elif access_type == "reader":
        # Possible anomalies: edits, high downloads, or encryption
        anomaly_type = random.choice(["edits", "downloads", "encryption"])
        
        if anomaly_type == "edits":
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(80, 150),
                "num_edits": random.randint(10, 50),  # Readers shouldn't edit
                "num_downloads": random.randint(5, 15),
                "num_encryption": 0
            }
            attack_type = "Privilege Escalation"
            
        elif anomaly_type == "downloads":
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(80, 350),
                "num_edits": 0,
                "num_downloads": random.randint(50, 150),  # Very high downloads
                "num_encryption": 0
            }
            attack_type = "Data Exfiltration"
            
        else:  # encryption
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(80, 150),
                "num_edits": 0,
                "num_downloads": random.randint(5, 15),
                "num_encryption": random.randint(5, 30)  # Readers shouldn't encrypt
            }
            attack_type = "Ransomware Attack"
    
    else:  # editor
        # Possible anomalies: high reads, low edits, high downloads, high encryption
        anomaly_type = random.choice(["reads", "low_edits", "downloads", "encryption"])
        
        if anomaly_type == "reads":
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(150, 300),  # Unusually high reads
                "num_edits": random.randint(10, 50),   # Lower than normal edits
                "num_downloads": random.randint(3, 8),
                "num_encryption": random.randint(5, 15)
            }
            attack_type = "Unauthorized Access"
            
        elif anomaly_type == "low_edits":
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(5, 20),
                "num_edits": random.randint(0, 5),     # Very low edits (unusual)
                "num_downloads": random.randint(3, 8),
                "num_encryption": random.randint(5, 15)
            }
            attack_type = "Unauthorized Access"
            
        elif anomaly_type == "downloads":
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(5, 30),
                "num_edits": random.randint(150, 300),
                "num_downloads": random.randint(30, 100),  # Very high downloads
                "num_encryption": random.randint(5, 15)
            }
            attack_type = "Data Exfiltration"
            
        else:  # encryption
            data = {
                "user_name": fake.user_name(),
                "access_type": access_type,
                "num_read": random.randint(5, 30),
                "num_edits": random.randint(150, 300),
                "num_downloads": random.randint(3, 8),
                "num_encryption": random.randint(50, 150)  # Very high encryption
            }
            attack_type = "Ransomware Attack"
    
    # Create complete alert
    alert = {
        "data": data,
        "attack": ATTACK_CLASSIFICATIONS[attack_type]
    }
    
    return alert

def publish_alert(alert):
    """Publish an alert to PubSub"""
    data = json.dumps(alert).encode("utf-8")
    future = publisher.publish(topic_path, data)
    message_id = future.result()
    print(f"Published message ID: {message_id}")
    print(f"Alert: {alert['data']['user_name']} - {alert['attack'].split('\n')[1].strip()}")
    print("-" * 50)

def generate_and_publish_alerts(num_alerts=10, delay=2):
    """Generate and publish multiple sample alerts"""
    print(f"Publishing {num_alerts} sample alerts to {topic_path}")
    print("-" * 50)
    
    for i in range(num_alerts):
        alert = generate_sample_alert()
        publish_alert(alert)
        time.sleep(delay)  # Wait between publishing alerts
    
    print(f"Finished publishing {num_alerts} alerts")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate and publish sample security alerts for testing")
    parser.add_argument("--num", type=int, default=10, help="Number of alerts to generate")
    parser.add_argument("--delay", type=float, default=2, help="Delay between alerts in seconds")
    
    args = parser.parse_args()
    
    generate_and_publish_alerts(args.num, args.delay) 