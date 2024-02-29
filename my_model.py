import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline
from flask import Flask, request, jsonify


app = Flask(__name__)

df = pd.read_csv('phishing_site_urls.csv')


X = df['URL']
y = df['Label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=42)


model = make_pipeline(TfidfVectorizer(), MultinomialNB())


model.fit(X_train, y_train)


@app.route('/predict', methods=['POST'])
def predict():
    try:

        url = request.json['url']


        prediction = model.predict([url])[0]


        ssl_validity = check_ssl_certificate(url)


        return jsonify({'prediction': prediction, 'ssl_validity': ssl_validity})

    except Exception as e:
        return jsonify({'error': str(e)})

def check_ssl_certificate(url):
    try:

        ssl._create_default_https_context = ssl._create_default_https_context # pylint: disable=protected-access


        response = requests.get(url , verfiy=True)

        # Get the SSL certificate from the response
        cert = response.connection.getpeercert()

        # Check if the certificate is expired
        if ssl.cert_time_to_seconds(cert['notAfter']) < ssl.cert_time_to_seconds(ssl.SSLContext().timestamp()):
            return 'Expired'
        else:
            return 'Valid'

    except Exception as e:
        return f'Error: {e}'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

