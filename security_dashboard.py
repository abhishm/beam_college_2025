import streamlit as st
import json
import os
import time
import threading
from datetime import datetime
from google.cloud import pubsub_v1
from dotenv import load_dotenv
import pandas as pd
import random

# Load environment variables
load_dotenv()

# Configure page
st.set_page_config(
    page_title="Security Alert Dashboard",
    page_icon="🔒",
    layout="wide",
)

# Initialize session state for alerts if it doesn't exist
if 'alerts' not in st.session_state:
    st.session_state.alerts = []

if 'alert_status' not in st.session_state:
    st.session_state.alert_status = {}  # Dictionary to track status of each alert

# Function to get attack title from full attack text
def get_attack_title(attack_text):
    if not attack_text or not isinstance(attack_text, str):
        return "Unknown Attack"
    
    lines = attack_text.strip().split('\n')
    if not lines:
        return "Unknown Attack"

    first_meaningful_line = ""
    for line in lines:
        if line.strip():
            first_meaningful_line = line.strip()
            break
    
    if not first_meaningful_line:
        return "Unknown Attack"

    # Check for "Attack Type: explanation" or "**Attack Type**: explanation"
    if ":" in first_meaningful_line:
        title = first_meaningful_line.split(":", 1)[0].strip().replace("*", "")
        return title if title else "Unknown Attack"
    
    # Check for "**Attack Type**" as the entire line
    if first_meaningful_line.startswith("**") and first_meaningful_line.endswith("**"):
        return first_meaningful_line.strip("* ")

    # Assume the first meaningful line is the title if it's short (e.g., "Privilege Escalation")
    # This is a heuristic and might need adjustment based on actual Gemini output diversity
    if len(first_meaningful_line.split()) <= 3: 
        return first_meaningful_line
        
    return "Unknown Attack" # Fallback

# Templates for detailed sample attack explanations
DETAILED_SAMPLE_ATTACK_EXPLANATIONS = {
    "Privilege Escalation": """**Privilege Escalation**

Explanation: User '{user_name}' (original role: '{access_type}') exhibited activity suggesting an attempt to escalate privileges. {reason} This is a deviation from their standard permissions. Normal '{access_type}' accounts should not perform these actions.""",
    "Data Exfiltration": """**Data Exfiltration**

Explanation: Suspicious activity from user '{user_name}' (role: '{access_type}') indicates potential data exfiltration. The observed number of downloads ({num_downloads}) is significantly elevated for this role. Normal '{access_type}' accounts typically download far less data.""",
    "Ransomware Attack": """**Ransomware Attack**

Explanation: User '{user_name}' (role: '{access_type}') shows {num_encryption} encryption operations. This is highly anomalous and a strong indicator of a potential ransomware attack, as unauthorized encryption is a hallmark of such threats. '{access_type}' accounts are not expected to perform bulk encryptions.""",
    "Unauthorized Access": """**Unauthorized Access**

Explanation: Account '{user_name}' (expected role: '{access_type}') was used in a manner inconsistent with its designated purpose. {reason} This activity is flagged as potential unauthorized access or misuse of credentials."""
}

def format_sample_attack_explanation(attack_type, user_data):
    explanation_template = DETAILED_SAMPLE_ATTACK_EXPLANATIONS.get(attack_type, "**{attack_type}**\n\nNo detailed explanation template available for this sample attack type.")
    
    ud = {
        'user_name': user_data.get('user_name', 'N/A'),
        'access_type': user_data.get('access_type', 'N/A'),
        'num_read': user_data.get('num_read', 0),
        'num_edits': user_data.get('num_edits', 0),
        'num_downloads': user_data.get('num_downloads', 0),
        'num_encryption': user_data.get('num_encryption', 0)
    }

    reason = "The observed activity pattern is unusual for the given role." 

    if attack_type == "Privilege Escalation":
        if ud['access_type'] == 'reader':
            if ud['num_edits'] > 0 and ud['num_encryption'] > 0:
                reason = f"They performed {ud['num_edits']} edits and {ud['num_encryption']} encryptions, operations forbidden for 'reader' accounts."
            elif ud['num_edits'] > 0:
                reason = f"They performed {ud['num_edits']} edit operations, which is not a permitted action for 'reader' accounts."
            elif ud['num_encryption'] > 0:
                reason = f"They performed {ud['num_encryption']} encryption operations, which is not permitted for 'reader' accounts."
            else: 
                reason = f"Their actions (e.g. {ud['num_edits']} edits, {ud['num_encryption']} encryptions) suggest privilege seeking."
        elif ud['access_type'] == 'no_access':
             reason = f"Any activity ({ud['num_read']} reads, {ud['num_edits']} edits) from a 'no_access' account implies gained access, a form of privilege escalation."

    elif attack_type == "Data Exfiltration":
        if ud['access_type'] == 'reader' and ud['num_downloads'] > 5: 
            reason = f"The download count of {ud['num_downloads']} is notably high for a 'reader' (typical < 5), suggesting data theft."
        elif ud['access_type'] == 'editor' and ud['num_downloads'] > 10: 
            reason = f"The download count of {ud['num_downloads']} is unusually high for an 'editor' (typical < 10), indicating potential exfiltration."
        else:
            reason = f"Observed {ud['num_downloads']} downloads, which is anomalous for a '{ud['access_type']}' user, suggesting potential data theft."


    elif attack_type == "Ransomware Attack":
        if ud['num_encryption'] > 0: 
            reason = f"The {ud['num_encryption']} encryption events are highly suspicious. For '{ud['access_type']}' accounts, this level of encryption activity is a strong ransomware indicator."

    elif attack_type == "Unauthorized Access":
        if ud['access_type'] == 'no_access':
            reason = f"The account performed {ud['num_read']} reads and {ud['num_edits']} edits, whereas 'no_access' accounts should exhibit no activity."
        elif ud['access_type'] == 'editor' and ud['num_read'] > 20: 
            reason = f"The number of read operations ({ud['num_read']}) is uncharacteristically high for an 'editor', suggesting reconnaissance or misuse."
        elif ud['access_type'] == 'reader' and ud['num_read'] > 30 and ud['num_edits'] == 0 and ud['num_encryption'] == 0 and ud['num_downloads'] < 10:
            reason = f"The number of read operations ({ud['num_read']}) is unusually high for a 'reader', suggesting potential probing or misuse."

    return explanation_template.format(
        attack_type=attack_type, 
        user_name=ud['user_name'],
        access_type=ud['access_type'],
        num_read=ud['num_read'],
        num_edits=ud['num_edits'],
        num_downloads=ud['num_downloads'],
        num_encryption=ud['num_encryption'],
        reason=reason
    ).strip()

# Function to process received PubSub messages
def process_message(message):
    try:
        data = json.loads(message.data.decode('utf-8'))
        
        # Add timestamp and ID
        alert_id = f"alert-{int(time.time() * 1000)}"
        data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data['id'] = alert_id
        
        # Add to session state
        st.session_state.alerts.insert(0, data)  # Add new alerts to the beginning
        st.session_state.alert_status[alert_id] = "New"
        
        # Acknowledge the message
        message.ack()
    except Exception as e:
        st.error(f"Error processing message: {str(e)}")
        message.nack()

# Background thread to pull messages from PubSub
def pull_messages():
    try:
        # Ensure PUBSUB_SUBSCRIPTION_ALERT is the full path
        subscription_path_env = os.environ.get("PUBSUB_SUBSCRIPTION_ALERT")
        if not subscription_path_env:
            st.error("PUBSUB_SUBSCRIPTION_ALERT environment variable not set.")
            return
        
        if not subscription_path_env.startswith("projects/"):
             st.error(f"PUBSUB_SUBSCRIPTION_ALERT must be the full subscription path (e.g., projects/project-id/subscriptions/sub-id). Current value: {subscription_path_env}")
             return

        subscriber = pubsub_v1.SubscriberClient()
        
        streaming_pull_future = subscriber.subscribe(
            subscription_path_env, 
            callback=process_message
        )
        
        # Keep the thread running
        try:
            streaming_pull_future.result() # Block indefinitely
        except Exception as e: # Catch errors from the subscriber thread
            streaming_pull_future.cancel()
            # Check if it's a Cancelled error, which might be expected on shutdown
            if "Cancelled" not in str(e) and "EOF" not in str(e): # EOF can happen on clean shutdown too
                 st.error(f"Subscriber error: {str(e)}")
    except Exception as e:
        st.error(f"Error setting up PubSub subscription: {str(e)}")

# Start background thread for PubSub subscription
if 'pubsub_thread' not in st.session_state:
    try:
        st.session_state.pubsub_thread = threading.Thread(target=pull_messages, daemon=True)
        st.session_state.pubsub_thread.start()
    except Exception as e:
        st.error(f"Error starting PubSub thread: {str(e)}")

# Add sample data option for testing
if st.sidebar.button("Load Sample Data"):
    # Generate a sample alert for testing
    sample_attacks = [
        "Privilege Escalation",
        "Data Exfiltration",
        "Ransomware Attack",
        "Unauthorized Access"
    ]
    
    for i in range(5):
        attack_type_for_sample = sample_attacks[i % len(sample_attacks)]
        current_sample_access_type = ["reader", "editor", "no_access", "reader", "editor"][i % 5] # Define access_type for current sample

        # Make num_read, etc. slightly more varied and larger for more interesting samples
        num_read_sample = random.randint(5, 50) + (i * 20)
        num_edits_sample = random.randint(0,10) + (i*2) if attack_type_for_sample == "Privilege Escalation" or current_sample_access_type == 'editor' else 0 # Use defined access_type
        num_downloads_sample = random.randint(10,30) + (i*10) if attack_type_for_sample == "Data Exfiltration" else random.randint(0,5)
        num_encryption_sample = random.randint(5,20) + (i*5) if attack_type_for_sample == "Ransomware Attack" else random.randint(0,2)


        sample_alert_data = {
            "user_name": f"sample_user_{i+1}",
            "access_type": current_sample_access_type, # Use defined access_type here as well
            "num_read": num_read_sample,
            "num_edits": num_edits_sample,
            "num_downloads": num_downloads_sample,
            "num_encryption": num_encryption_sample
        }
        
        # Adjust metrics to better fit the chosen attack type for the sample
        if attack_type_for_sample == "Privilege Escalation":
            if sample_alert_data["access_type"] == "reader":
                sample_alert_data["num_edits"] = max(sample_alert_data["num_edits"], random.randint(5, 20)) # Ensure some edits
            elif sample_alert_data["access_type"] == "no_access":
                 sample_alert_data["num_read"] = max(sample_alert_data["num_read"], random.randint(1,10))


        elif attack_type_for_sample == "Data Exfiltration":
            sample_alert_data["num_downloads"] = max(sample_alert_data["num_downloads"], random.randint(50, 150)) # Ensure high downloads

        elif attack_type_for_sample == "Ransomware Attack":
            sample_alert_data["num_encryption"] = max(sample_alert_data["num_encryption"], random.randint(20, 70)) # Ensure high encryption
            if sample_alert_data["access_type"] == "reader": # Readers normally don't encrypt
                sample_alert_data["num_encryption"] = max(sample_alert_data["num_encryption"], random.randint(5,30))


        elif attack_type_for_sample == "Unauthorized Access":
            if sample_alert_data["access_type"] == "no_access":
                sample_alert_data["num_read"] = max(sample_alert_data["num_read"], random.randint(10,30))
            elif sample_alert_data["access_type"] == "editor": # High reads for editor
                 sample_alert_data["num_read"] = max(sample_alert_data["num_read"], random.randint(100,200))


        attack_justification = format_sample_attack_explanation(attack_type_for_sample, sample_alert_data)

        sample_alert = {
            "data": sample_alert_data,
            "attack": attack_justification,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "id": f"sample-{i}-{int(time.time())}"
        }
        st.session_state.alerts.insert(0, sample_alert)
        st.session_state.alert_status[sample_alert["id"]] = "New"
    
    st.sidebar.success("Added 5 sample alerts with detailed justifications!")

# App header
st.title("🔒 Security Alert Dashboard")
st.markdown("Real-time monitoring and response for security alerts")

# Create tabs for different views
tab1, tab2, tab3 = st.tabs(["Active Alerts", "Resolved Alerts", "Analytics"])

# Function to mark an alert as addressed
def mark_as_addressed(alert_id):
    st.session_state.alert_status[alert_id] = "Addressed"
    st.rerun()

# Function to mark an alert as false positive
def mark_as_false_positive(alert_id):
    st.session_state.alert_status[alert_id] = "False Positive"
    st.rerun()

# Function to escalate an alert
def escalate_alert(alert_id):
    st.session_state.alert_status[alert_id] = "Escalated"
    st.rerun()

# Active Alerts Tab
with tab1:
    st.header("Active Alerts")
    
    # Filter options
    col1, col2, col3 = st.columns(3)
    with col1:
        filter_user = st.text_input("Filter by username")
    with col2:
        attack_types = ["All", "Privilege Escalation", "Data Exfiltration", "Ransomware Attack", "Unauthorized Access"]
        filter_attack = st.selectbox("Filter by attack type", attack_types)
    with col3:
        filter_status = st.selectbox("Filter by status", ["All", "New", "Investigating", "Escalated"])
    
    # Get active alerts (not addressed or false positive)
    active_alerts = [
        alert for alert in st.session_state.alerts 
        if st.session_state.alert_status.get(alert.get('id')) not in ["Addressed", "False Positive"]
    ]
    
    # Apply filters
    if filter_user:
        active_alerts = [alert for alert in active_alerts if filter_user.lower() in alert.get('data', {}).get('user_name', '').lower()]
    
    if filter_attack != "All":
        active_alerts = [
            alert for alert in active_alerts 
            if filter_attack.lower() in get_attack_title(alert.get('attack', '')).lower()
        ]
    
    if filter_status != "All":
        active_alerts = [alert for alert in active_alerts if st.session_state.alert_status.get(alert.get('id')) == filter_status]
    
    # Show alerts
    if not active_alerts:
        st.info("No active alerts found.")
    
    for idx, alert in enumerate(active_alerts):
        user_data = alert.get('data', {})
        attack_info = alert.get('attack', 'Unknown attack')
        attack_title = get_attack_title(attack_info)
        
        # Create a card for each alert
        with st.expander(f"⚠️ {user_data.get('user_name', 'Unknown User')} - {attack_title}", expanded=idx==0):
            cols = st.columns([3, 1])
            
            with cols[0]:
                st.markdown(f"**User:** {user_data.get('user_name', 'Unknown')}")
                st.markdown(f"**Access Type:** {user_data.get('access_type', 'Unknown')}")
                st.markdown(f"**Time Detected:** {alert.get('timestamp', 'Unknown')}")
                st.markdown(f"**Status:** {st.session_state.alert_status.get(alert.get('id'), 'New')}")
                
                # Activity metrics
                metrics_cols = st.columns(4)
                with metrics_cols[0]:
                    st.metric("Reads", user_data.get('num_read', 0))
                with metrics_cols[1]:
                    st.metric("Edits", user_data.get('num_edits', 0))
                with metrics_cols[2]:
                    st.metric("Downloads", user_data.get('num_downloads', 0))
                with metrics_cols[3]:
                    st.metric("Encryptions", user_data.get('num_encryption', 0))
                
                st.markdown("### Attack Classification")
                st.markdown(attack_info)
            
            with cols[1]:
                st.markdown("### Actions")
                
                status = st.session_state.alert_status.get(alert.get('id'), "New")
                
                if status == "New":
                    if st.button("Start Investigation", key=f"inv_{alert.get('id')}"):
                        st.session_state.alert_status[alert.get('id')] = "Investigating"
                        st.rerun()
                
                if status == "Investigating":
                    st.button("Mark as Addressed", key=f"address_{alert.get('id')}", 
                             on_click=mark_as_addressed, args=(alert.get('id'),))
                    
                    st.button("Mark as False Positive", key=f"false_{alert.get('id')}", 
                             on_click=mark_as_false_positive, args=(alert.get('id'),))
                    
                    st.button("Escalate", key=f"escalate_{alert.get('id')}", 
                             on_click=escalate_alert, args=(alert.get('id'),))
                
                if status == "Escalated":
                    st.button("Mark as Addressed", key=f"address_{alert.get('id')}", 
                             on_click=mark_as_addressed, args=(alert.get('id'),))

# Resolved Alerts Tab
with tab2:
    st.header("Resolved Alerts")
    
    # Get resolved alerts
    resolved_alerts = [
        alert for alert in st.session_state.alerts 
        if st.session_state.alert_status.get(alert.get('id')) in ["Addressed", "False Positive"]
    ]
    
    if not resolved_alerts:
        st.info("No resolved alerts found.")
    else:
        # Create a dataframe for easy viewing
        resolved_data = []
        for alert in resolved_alerts:
            user_data = alert.get('data', {})
            attack_info = alert.get('attack', 'Unknown')
            attack_title = get_attack_title(attack_info)
                
            resolved_data.append({
                "Timestamp": alert.get('timestamp', 'Unknown'),
                "User": user_data.get('user_name', 'Unknown'),
                "Access Type": user_data.get('access_type', 'Unknown'),
                "Attack Type": attack_title,
                "Resolution": st.session_state.alert_status.get(alert.get('id'), 'Unknown'),
            })
        
        resolved_df = pd.DataFrame(resolved_data)
        st.dataframe(resolved_df, use_container_width=True)

# Analytics Tab
with tab3:
    st.header("Security Analytics")
    
    if not st.session_state.alerts:
        st.info("No data available for analytics.")
    else:
        # Create some simple analytics
        all_alerts = st.session_state.alerts
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Count by attack type
            attack_counts = {}
            for alert in all_alerts:
                attack_title = get_attack_title(alert.get('attack', 'Unknown'))
                attack_counts[attack_title] = attack_counts.get(attack_title, 0) + 1
            
            attack_df = pd.DataFrame({
                'Attack Type': attack_counts.keys(),
                'Count': attack_counts.values()
            })
            
            st.subheader("Alerts by Attack Type")
            st.bar_chart(attack_df.set_index('Attack Type'))
        
        with col2:
            # Count by resolution status
            status_counts = {}
            for alert_id, status in st.session_state.alert_status.items():
                status_counts[status] = status_counts.get(status, 0) + 1
            
            status_df = pd.DataFrame({
                'Status': status_counts.keys(),
                'Count': status_counts.values()
            })
            
            st.subheader("Alerts by Status")
            st.bar_chart(status_df.set_index('Status'))
        
        # Access type distribution
        access_counts = {}
        for alert in all_alerts:
            access_type = alert.get('data', {}).get('access_type', 'Unknown')
            access_counts[access_type] = access_counts.get(access_type, 0) + 1
        
        access_df = pd.DataFrame({
            'Access Type': access_counts.keys(),
            'Count': access_counts.values()
        })
        
        st.subheader("Alerts by Access Type")
        st.bar_chart(access_df.set_index('Access Type'))
        
        # User activity over time
        if len(all_alerts) > 1:
            st.subheader("Alert Activity Timeline")
            timeline_data = []
            
            for alert in all_alerts:
                if 'timestamp' in alert:
                    try:
                        timestamp = datetime.strptime(alert['timestamp'], "%Y-%m-%d %H:%M:%S")
                        timeline_data.append({
                            'timestamp': timestamp,
                            'count': 1
                        })
                    except:
                        pass
            
            if timeline_data:
                timeline_df = pd.DataFrame(timeline_data)
                timeline_df = timeline_df.set_index('timestamp')
                timeline_df = timeline_df.resample('1H').sum().fillna(0)
                st.line_chart(timeline_df)

# Footer
st.markdown("---")
st.markdown("*This dashboard monitors real-time security alerts from Apache Beam anomaly detection pipeline.*")
st.sidebar.markdown("### Testing")
st.sidebar.markdown("Use the button above to load sample data or run the `generate_test_alerts.py` script to publish real alerts to PubSub.") 