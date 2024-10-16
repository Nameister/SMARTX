import os
import numpy as np
import datetime
from flask import Flask, request, jsonify
from neo4j import GraphDatabase
import joblib

app = Flask(__name__)

# Set environment variable to disable oneDNN optimizations if needed
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'

# Global variables for model and vectorizer
model = None
vectorizer = None
driver = None

# Paths to resources
VECTORIZER_PATH = r'C:\Users\User\OneDrive\Desktop\XSS_Detection_Model1\tfidf_vectorizer_with_custom_features.pkl'
MODEL_PATH = r'C:\Users\User\OneDrive\Desktop\XSS_Detection_Model1\mlpc_xss_model_with_custom_features.pkl'
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "12345678"

# Load resources at the start
def load_resources():
    global model, vectorizer, driver
    try:
        vectorizer = joblib.load(VECTORIZER_PATH)
        model = joblib.load(MODEL_PATH)
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        print("All resources loaded successfully.")
    except Exception as e:
        app.logger.error(f"Failed to load resources: {str(e)}")
        raise RuntimeError(f"Failed to load resources: {str(e)}")

# Calculate custom features
def calculate_features(urls):
    url_length = np.array([len(url) for url in urls])
    special_char_count = np.array([sum(1 for char in url if char in ['<', '>', '"', '&']) for url in urls])
    keyword_presence = np.array([1 if any(kw in url.lower() for kw in ['script', 'alert', 'img', 'onerror']) else 0 for url in urls])
    return url_length, special_char_count, keyword_presence

# Process batch of URLs
def process_batch(urls):
    X_tfidf = vectorizer.transform(urls).toarray()
    url_length, special_char_count, keyword_presence = calculate_features(urls)
    X_features = np.hstack([X_tfidf, url_length.reshape(-1, 1), special_char_count.reshape(-1, 1), keyword_presence.reshape(-1, 1)])
    return X_features

# Define the route for detecting XSS
@app.route('/detect', methods=['POST'])
def detect():
    if not model or not vectorizer or not driver:
        return jsonify({"error": "System not ready, resources are not loaded"}), 500

    try:
        data = request.get_json(force=True)
        if 'inputString' not in data or 'clientID' not in data or 'hostIP' not in data:
            return jsonify({"error": "Missing required fields"}), 400
        urls = [data['inputString']]
        X_tfidf = vectorizer.transform(urls).toarray()
        print(f"X_tfidf shape: {X_tfidf.shape}")  # Debug print
        url_length, special_char_count, keyword_presence = calculate_features(urls)
        print(f"Feature Shapes: url_length={url_length.shape}, special_char_count={special_char_count.shape}, keyword_presence={keyword_presence.shape}")  # Debug print
        X_features = np.hstack([X_tfidf, url_length.reshape(-1, 1), special_char_count.reshape(-1, 1), keyword_presence.reshape(-1, 1)])
        print(f"X_features shape: {X_features.shape}")  # Debug print

        prediction = model.predict(X_features)
        # Handling different output dimensions of the model
        prediction = prediction[0] > 0.5 if prediction.ndim == 1 else prediction[0][0] > 0.5

        store_in_neo4j(data['clientID'], data['hostIP'], datetime.datetime.now(), prediction, urls[0])
        return jsonify({
            "clientID": data['clientID'],
            "hostIP": data['hostIP'],
            "timeStamp": datetime.datetime.now().isoformat(),
            "isXSS": bool(prediction),
            "message": urls[0] if prediction else None
        })
    except Exception as e:
        app.logger.error(f"Error in detection: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Store in Neo4j
def store_in_neo4j(client_id, host_ip, timestamp, is_xss, url):
    try:
        with driver.session() as session:
            session.write_transaction(create_detection_record, client_id, host_ip, timestamp, is_xss, url)
            print("Data stored successfully in Neo4j.")
    except Exception as e:
        app.logger.error(f"Error writing to Neo4j: {str(e)}")
        raise

def create_detection_record(tx, client_id, host_ip, timestamp, is_xss, url):
    query = """
    MERGE (client:Client {id: $client_id})
    MERGE (host:Host {ip: $host_ip})
    MERGE (client)-[:HAS_HOST]->(host)
    CREATE (detection:Detection {timeStamp: $timestamp, isXSS: $is_xss, url: $url})
    MERGE (host)-[:HAS_DETECTION]->(detection)
    """
    tx.run(query, client_id=client_id, host_ip=host_ip, timestamp=timestamp.isoformat(), is_xss=is_xss, url=url)

if __name__ == "__main__":
    load_resources()
    app.run(host='127.0.0.1', port=8000, debug=True, threaded=True)
