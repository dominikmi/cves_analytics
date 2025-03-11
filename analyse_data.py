#!/usr/bin/env python3

from flask import Flask, request, render_template, send_file
import pandas as pd
import numpy as np
from datetime import datetime
import logging
import os

app = Flask(__name__)

# Set up logging
log_directory = '/Users/mikey/HomeWorks/homelab-repos/cves_analytics/logs'
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

logging.basicConfig(filename=os.path.join(log_directory, 'app.log'), level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


class VulnerabilityAnalyzer:
    def __init__(self):
        # Historical CVE data simulation for demonstration purposes only.
        historical_data = {
            'year': [2018, 2019, 2020],
            'vulnerability_type': ['buffer_overflow', 'sql_injection'],
            'severity_rating': ['low', 'high'],
            'discovered_year': [2017, 2018, 2019]
        }
        
        self.analyzer = VulnerabilityAnalyzer(historical_data)

    def predict_risk(self):
        # Monte Carlo simulation for future vulnerability prediction.
        total_years = len(range(2020, 2025))  # Predict for next 5 years
        
        predicted_risks = []
        
        for _ in range(total_years):
            year = np.random.choice(list(self.analyzer.historical_data['year']), replace=False)
            type_ = self.analyzer.analyzer.predicted_vulnerability(year).index[0]
            
            risk_level = (self.analyzer.analyzer.predicted_vulnerability(year)[type_] / 
                          sum(self.analyzer.analyzer.predicted_vulnerability(year)) * 100) if type_ else np.random.uniform(20,50)

            predicted_risks.append(risk_level)
        
        return predicted_risks
    
    def run_simulation(self):
        results = {
            'year': range(2020, 2025),
            'predicted_risk': self.predict_risk()
        }
        return results


analyzer_instance = VulnerabilityAnalyzer()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        # Run simulation and prepare data for plotting.
        simulated_results = analyzer_instance.run_simulation()
        logging.info('Simulation run successfully.')

        # Extract risk scores to visualize in Plotly.
        year_list = [str(year) for year in range(2020, 2025)]
        risks_dict = dict(zip(year_list, simulated_results['predicted_risk']))

    return render_template('index.html', data=simulated_results)

@app.route('/download_csv', methods=['POST'])
def download_csv():
    if request.method == 'POST':
        csv_content = analyzer_instance.run_simulation()
        logging.info('CSV download requested.')

        # Export as CSV.
        output_file_name = f"vulnerability_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        df = pd.DataFrame(csv_content)
        df.to_csv(output_file_name, index=False)

        return send_file(output_file_name, mimetype='text/csv', as_attachment=True)

if __name__ == '__main__':
    app.run(debug=False, port=5001)