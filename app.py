from flask import Flask, render_template, request
import numpy as np
import pandas as pd

app = Flask(__name__, template_folder='templates')

model = pd.read_pickle(r'C:\Users\Kunal Singh\Downloads\hackathon-project-phishing-website-detector-main\hackathon-project-phishing-website-detector-main\hackathon.pkl')

@app.route('/', methods=['GET', 'POST'])
def home():
    features_list = [
        'having_ip_address', 'url_length', 'shortining_service', 'having_at_symbol', 
        'double_slash_redirecting', 'prefix_suffix', 'having_sub_domain', 'sslfinal_state', 
        'domain_registration_length', 'favicon', 'port', 'https_token', 'request_url', 
        'url_of_anchor', 'links_in_tags', 'sfh', 'submitting_to_email', 'abnormal_url', 
        'redirect', 'on_mouseover', 'rightclick', 'popupwindow', 'iframe', 'age_of_domain', 
        'dnsrecord', 'web_traffic', 'page_rank', 'google_index', 'links_pointing_to_page', 
        'statistical_report'
    ]

    if request.method == 'POST':
        features = [request.form.get(f) for f in features_list]
        features = np.array(features).reshape(1, -1)
        prediction = model.predict(features)[0]
        result = 'Unsafe' if prediction == 1 else 'Safe'
        return render_template('result.html', result=result)

    return render_template('index.html', features_list=features_list)

if __name__ == '__main__':
    app.run()
