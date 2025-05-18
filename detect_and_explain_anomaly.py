import json
import os

import apache_beam as beam
from apache_beam.ml.anomaly.detectors.pyod_adapter import PyODFactory
from apache_beam.ml.anomaly.transforms import AnomalyDetection
from apache_beam.ml.inference.base import ModelHandler
from apache_beam.options.pipeline_options import PipelineOptions
from dotenv import load_dotenv
from google import genai


load_dotenv()

# Create detector for PyOd model pickled file
model_save_path = os.environ["GCS_ROOT"] + '/anomaly/iforest.pkl'

features = ('num_read', 'num_edits', 'num_downloads', 'num_encryption', 
           'access_type_editor', 'access_type_no_access', 'access_type_reader')
detector = PyODFactory.create_detector(model_save_path, features=features)

system_prompt = """
You are an AI Security Analyst. Your primary function is to analyze logs of user activity that have already been flagged as anomalous and categorize them into specific cybersecurity threat types. You must use the provided context about normal behavior to make your determination.

**Your Task:**

Given a JSON object representing a single anomalous activity record, you must classify this activity into ONE of the following four categories:

1.  Privilege Escalation  
2.  Data Exfiltration  
3.  Ransomware Attack  
4.  Unauthorized Access

**Input Data Structure:**

You will receive a JSON object with the following fields:

```json  
{  
    "access_type": "anomaly_no_access" | "anomaly_reader" | "anomaly_editor", // Indicates the original role whose behavior is now anomalous  
    "num_read": int,       // Number of read operations  
    "num_edits": int,      // Number of edit operations  
    "num_downloads": int,  // Number of download operations  
    "num_encryption": int  // Number of encryption operations  
}
```

**Context on Normal (Non-Anomalous) Behavior Patterns:**

Understanding normal behavior is key to identifying the nature of an anomaly. Here's a summary:

* **Normal no_access Profile:**  
  * num_read: 0  
  * num_edits: 0  
  * num_downloads: 0  
  * num_encryption: 0  
  * *Any activity is anomalous.*  
* **Normal reader Profile:**  
  * num_read: Typically around 100 (e.g., from a distribution like N(100, 50)).  
  * num_edits: 0 (Readers do not edit).  
  * num_downloads: Typically around 10 (e.g., from N(10, 5)).  
  * num_encryption: 0 (Readers do not encrypt).  
  * *Anomalies might include any edits, any encryption, or vastly different read/download volumes.*  
* **Normal editor Profile:**  
  * num_read: Typically low, around 10 (e.g., from N(10, 10)).  
  * num_edits: Typically high, around 200 (e.g., from N(200, 100)).  
  * num_downloads: Typically low, around 5 (e.g., from N(5, 2)).  
  * num_encryption: Typically low, around 10 (e.g., from N(10, 10)).  
  * *Anomalies might include unusually high reads, very low edits, very high downloads, or very high encryption relative to their normal baseline.*

**Anomaly Categories & Key Indicators:**

Carefully consider the anomalous data in light of the normal patterns and the access_type prefix (e.g., anomaly_reader was originally a reader).

1. **Privilege Escalation:**  
   * **Definition:** An account performing actions typically reserved for a higher access level or explicitly forbidden for its designated role.  
   * **Key Indicators:**  
     * An anomaly_no_access record showing *any* num_read > 0 or num_edits > 0.  
     * An anomaly_reader record showing num_edits > 0 or num_encryption > 0 (since normal readers cannot perform these actions).  
     * The focus is on *gaining new capabilities* not just volume changes of existing ones.  
2. **Data Exfiltration:**  
   * **Definition:** The unauthorized copying, transfer, or retrieval of large volumes of data from the system.  
   * **Key Indicators:**  
     * An anomaly_reader or anomaly_editor record showing a num_downloads count that is drastically and significantly higher than its normal baseline (e.g., anomaly_reader with num_downloads of 50+ when normal is ~10; anomaly_editor with num_downloads of 30+ when normal is ~5).  
     * May be accompanied by an unusually high num_read count, but the primary indicator is the excessive num_downloads.  
3. **Ransomware Attack:**  
   * **Definition:** Malicious activity involving the unauthorized encryption of data, rendering it inaccessible.  
   * **Key Indicators:**  
     * An anomaly_reader record showing *any* num_encryption > 0 (since normal readers do not encrypt).  
     * An anomaly_editor record showing a num_encryption count that is drastically and significantly higher than its normal baseline (e.g., num_encryption of 50+ when normal is ~10).  
     * May be accompanied by unusual num_edits if files are modified/encrypted in place.  
4. **Unauthorized Access:**  
   * **Definition:** Access to systems, applications, or data without proper authorization, or use of an authorized account in an unauthorized manner that doesn't clearly fit the other categories. This can be an initial breach or misuse of credentials.  
   * **Key Indicators:**  
     * This is the most direct category if an anomaly_no_access record shows *any activity at all*, as it signifies the account was used when it shouldn't have been.  
     * An anomaly_reader or anomaly_editor performing actions that are unusual for their role but don't strongly align with the specific high-impact patterns of Privilege Escalation, Data Exfiltration, or Ransomware. For example:  
       * An anomaly_editor with unusually high num_read (e.g., 100+) and/or unusually low num_edits (e.g., < 50), but without extreme num_downloads or num_encryption spikes. This might indicate an attacker using an editor account for reconnaissance rather than typical editing tasks.  
     * Use this as a category when the activity is clearly suspicious and outside normal bounds for the given role, but doesn't meet the more specific criteria of the other three categories.

Output Format:

Respond with the name of the category and then the possible explanation for the input to belong to that category. If an input belong to multiple categories, then describle all the them one by one.
"""


def convert_data_to_key_value(data):
    """
    Convert the data to a key-value pair.
    
    Args:
        data: Dictionary containing user data
        
    Returns:
        Tuple of (user_name, data)
    """
    data = data.copy()
    user_name = data["user_name"]
    data["access_type_no_access"] = False
    data["access_type_reader"] = False
    data["access_type_editor"] = False
    if data["access_type"] == "no_access":
        data["access_type_no_access"] = True
    elif data["access_type"] == "reader":
        data["access_type_reader"] = True
    elif data["access_type"] == "editor":
        data["access_type_editor"] = True
    del data["user_name"]
    del data["access_type"]
    return (user_name, data)


def fix_access_type(alert_data):
    """
    Fix access type in alert data.
    
    Args:
        alert_data: Tuple of (user_name, data)
        
    Returns:
        Dictionary with fixed access type
    """
    new_alert_data = {}
    for k, v in alert_data[1].items():
        if not k.startswith("access_type_"):
            new_alert_data[k] = v
            continue
        if not v:
            continue
        new_alert_data["access_type"] = k.split("access_type_")[1]
    new_alert_data["user_name"] = alert_data[0]
    return new_alert_data


def find_attack_associated_with_anomaly(client, alert_data):
    """
    Use Gemini to classify the type of attack associated with the anomaly.
    
    Args:
        client: Gemini client
        alert_data: Alert data dictionary
        
    Returns:
        String containing attack classification
    """
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=f'''
        # Data

        {alert_data}
        ''',
         config=genai.types.GenerateContentConfig(
                    system_instruction=system_prompt
                ),
    )
    return response.text


class GeminiModelHandler(ModelHandler):
    """Model handler for Gemini inference."""

    def __init__(self):
        self.gcp_project = os.environ["GOOGLE_CLOUD_PROJECT"]
        self.gcp_location = os.environ["GOOGLE_CLOUD_LOCATION"]
    
    def load_model(self):
        """Load Gemini client."""
        client = genai.Client(vertexai=True, project=self.gcp_project, location=self.gcp_location)
        return client

    def run_inference(self, batch, client, inference_args=None):
        """Run inference on a batch of examples.
        
        Args:
            batch: Batch of examples
            client: Gemini client
            inference_args: Additional arguments for inference
            
        Yields:
            Dictionary with original data and attack classification
        """
        for b in batch:
            yield {"data": b, "attack": find_attack_associated_with_anomaly(client, b)}


# Define pipeline locations
TEMP_LOCATION = os.environ["GCS_ROOT"] + '/anomaly/tmp'
STAGING_LOCATION = os.environ["GCS_ROOT"] + '/anomaly/staging'

# Configure pipeline options
options = PipelineOptions([
    "--runner=DataflowRunner",
    "--temp_location=" + TEMP_LOCATION,
    "--staging_location=" + STAGING_LOCATION,
    "--project=" + os.environ["GOOGLE_CLOUD_PROJECT"],
    "--region=" + os.environ["GOOGLE_CLOUD_LOCATION"],
    "--job_name=" + "anomaly-detection-and-classification-3",
    "--setup_file=./setup.py"
])

# Create and run the pipeline
with beam.Pipeline(options=options) as p:
    _ = (p
         | "ReadUserActivity" >> beam.io.gcp.pubsub.ReadFromPubSub(subscription=os.environ["PUBSUB_SUBSCRIPTION"])
         | "ParseJson" >> beam.Map(lambda x: json.loads(x.decode("utf-8")))
         | "ConvertToKeyValue" >> beam.Map(convert_data_to_key_value)
         | "ConvertToRow" >> beam.Map(lambda x: (x[0], beam.Row(**x[1])))
         | "DetectAnomalies" >> AnomalyDetection(detector=detector)
         | "FilterAnomalies" >> beam.Filter(lambda x: x[1].predictions[0].label)  # Filter only anomalies
         | "ExtractFeatures" >> beam.Map(lambda x: (x[0], x[1].example.as_dict()))
         | "FixAccessType" >> beam.Map(lambda x: fix_access_type(x))
         | "ClassifyAttack" >> beam.ml.inference.RunInference(model_handler=GeminiModelHandler())
         | "EncodeJson" >> beam.Map(lambda x: json.dumps(x).encode("utf-8"))
         | "PublishAlerts" >> beam.io.gcp.pubsub.WriteToPubSub(topic=os.environ["PUBSUB_TOPIC_ALERT"])
    )