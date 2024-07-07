from flask import Flask, render_template, request
import pandas as pd
import re
from urllib.parse import urlparse, parse_qs
import joblib

app = Flask(__name__)

# Load the trained machine learning model
model = joblib.load('phishing_detection_model.joblib')

# Function to extract features from URL
def extract_features(url):
    features = {}

    # Number of Dots
    features['NumDots'] = url.count('.')

    # Subdomain Level
    parsed_url = urlparse(url)
    if parsed_url.hostname is not None:  # Check if hostname exists
        subdomain = parsed_url.hostname.split('.')
        features['SubdomainLevel'] = len(subdomain) - 2 if len(subdomain) > 2 else 0
    else:
        features['SubdomainLevel'] = 0

    # Path Level
    if parsed_url.path:
        path = parsed_url.path.strip('/').split('/')
        features['PathLevel'] = len(path)
    else:
        features['PathLevel'] = 0

    # Url Length
    features['UrlLength'] = len(url)

    # Number of Dash
    features['NumDash'] = url.count('-')

    # Number of Dash In Hostname
    if parsed_url.hostname:
        features['NumDashInHostname'] = parsed_url.hostname.count('-')
    else:
        features['NumDashInHostname'] = 0

    # At Symbol
    features['AtSymbol'] = 1 if '@' in parsed_url.netloc else 0

    # Tilde Symbol
    features['TildeSymbol'] = 1 if '~' in parsed_url.netloc else 0

    # Number of Underscore
    features['NumUnderscore'] = url.count('_')

    # Number of Percent
    features['NumPercent'] = url.count('%')

    # Number of QueryComponents
    features['NumQueryComponents'] = len(parse_qs(parsed_url.query))

    # Number of Ampersand
    features['NumAmpersand'] = url.count('&')

    # Number of Hash
    features['NumHash'] = url.count('#')

    # Number of NumericChars
    features['NumNumericChars'] = len(re.findall(r'\d', url))

    # No Https
    features['NoHttps'] = 1 if parsed_url.scheme != 'https' else 0

    # Random String
    features['RandomString'] = 1 if parsed_url.query == '' and parsed_url.path == '/' else 0

    # IP Address
    features['IpAddress'] = 1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc) else 0

    # Domain In Subdomains
    if parsed_url.hostname:
        domain = '.'.join(subdomain[-2:])
        features['DomainInSubdomains'] = 1 if domain in url else 0
    else:
        features['DomainInSubdomains'] = 0

    # Domain In Paths
    features['DomainInPaths'] = 1 if parsed_url.netloc in parsed_url.path else 0

    # Https In Hostname
    features['HttpsInHostname'] = 1 if 'https' in parsed_url.netloc else 0

    # Hostname Length
    if parsed_url.hostname:
        features['HostnameLength'] = len(parsed_url.netloc)
    else:
        features['HostnameLength'] = 0

    # Path Length
    features['PathLength'] = sum(len(segment) for segment in path) if parsed_url.path else 0

    # Query Length
    features['QueryLength'] = len(parsed_url.query)

    # Number of Double Slash In Path
    features['DoubleSlashInPath'] = url.count('//')

    # Number of Sensitive Words
    sensitive_words = ['password', 'login', 'admin']
    features['NumSensitiveWords'] = sum(1 for word in sensitive_words if word in url.lower())

    return features

# Route for the home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for handling URL input and displaying prediction
@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    features = extract_features(url)
    features_df = pd.DataFrame(features, index=[0])  # Convert features dictionary to DataFrame
    prediction = model.predict(features_df) 
    if prediction[0] == 0:
        result = "Not a phishing site" 
    else :
        result = "Phishing site"
    return render_template('result.html', prediction_text=result)

if __name__ == '__main__':
    app.run(debug=True)
