#!/usr/bin/env python3

from flask import Flask, render_template, request, redirect, url_for
import pandas as pd
import plotly.express as px
import os

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        file = request.files['file']
        if file and file.filename.endswith('.csv'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(filepath)
            return redirect(url_for('analyze', filename=file.filename))
    return render_template('index.html')

@app.route('/analyze/<filename>', methods=['GET', 'POST'])
def analyze(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    df = pd.read_csv(filepath)
    
    # Ensure required columns exist
    required_columns = {'cve_id', 'epss_score', 'cvss_score', 'year'}
    if not required_columns.issubset(df.columns):
        return "Invalid CSV format! Ensure it contains 'cve_id', 'epss_score', 'cvss_score', and 'year'."
    
    # Filter high and critical CVEs
    df['severity'] = df['cvss_score'].apply(lambda x: 'Critical' if x >= 9 else ('High' if x >= 7 else 'Other'))
    df_filtered = df[df['severity'].isin(['High', 'Critical'])]
    
    # Plot 1: Distribution of Critical & High CVEs over years
    fig1 = px.histogram(df_filtered, x='year', color='severity', barmode='group',
                        title='Distribution of High & Critical CVEs Over Years')
    plot1 = fig1.to_html(full_html=False)
    
    # Handle EPSS threshold slider input
    epss_threshold = float(request.form.get('epss_threshold', 0.2))
    
    # Plot 2: Distribution of EPSS Scores above threshold
    fig2 = px.histogram(df[df['epss_score'] > epss_threshold], x='epss_score', nbins=50,
                        title=f'Distribution of EPSS Scores Above {epss_threshold}')
    plot2 = fig2.to_html(full_html=False)
    
    return render_template('analyse.html', plot1=plot1, plot2=plot2, epss_threshold=epss_threshold)

if __name__ == '__main__':
    app.run(debug=True)