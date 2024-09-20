from flask import Flask, render_template, request, redirect, url_for, flash, session
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import boto3

import os
access_key = os.environ.get("access_key")
secret_access_key = os.environ.get("secret_access_key")
password_rds = os.environ.get("password")
sns_topic_arn = os.environ.get('sns_topic_arn')

app = Flask(__name__)
app.secret_key = 'VCIfBZPce7LLu9O52hQLdrRSdMhBmAjtLcz/McPI'  # Replace with a strong secret key for session management

# AWS SNS Configuration
sns_client = boto3.client(
    'sns',
    region_name='ap-south-1',
    aws_access_key_id=access_key,
    aws_secret_access_key=secret_access_key
)

print(password_rds)

# Database connection function
def get_db_connection():
    print(password_rds)
    connection = mysql.connector.connect(
        host='database-1.c7qsyim0031g.ap-south-1.rds.amazonaws.com',
        user='admin',
        password=password_rds,
        database='crop_yield_db05'
    )
    return connection

# Index route with "Get Started" button
@app.route('/')
def index():
    return render_template('index.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']  # Store user ID in session
                flash('Login successful!', 'success')
                return redirect(url_for('data_entry'))

            flash('Invalid email or password', 'danger')

        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html')

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (email, password) VALUES (%s, %s)",
                (email, hashed_password)
            )
            conn.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html')

# Data entry route to handle form submissions
@app.route('/data-entry', methods=['GET', 'POST'])
def data_entry():
    if 'user_id' not in session:
        flash('You need to log in first', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        crop_name = request.form['crop_name']
        location = request.form['location']
        soil_type = request.form['soil_type']
        season = request.form['season']
        user_id = session['user_id']
        conn = get_db_connection()
        try:
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO crop_data (user_id, crop_name, location, soil_type, season) VALUES (%s, %s, %s, %s, %s)",
                (user_id, crop_name, location, soil_type, season)
            )
            conn.commit()

            # Publish SNS notification
            message = f"New crop data entered: {crop_name} at {location} with soil type {soil_type} for season {season}."
            subject = "New Crop Data Added"
            sns_client.publish(
                TopicArn=sns_topic_arn,
                Message=message,
                Subject=subject
            )

            flash('Data successfully saved and notification sent!', 'success')

        except mysql.connector.Error as err:
            conn.rollback()
            flash(f'Error: {err}', 'danger')
        
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('crop_suggestion'))

    return render_template('data_entry.html')

# Crop suggestion route to display suitable crops based on stored data
@app.route('/crop-suggestion', methods=['GET', 'POST'])
def crop_suggestion():
    crops = []
    if request.method == 'POST':
        soil_type = request.form['soil_type']
        season = request.form['season']

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            cursor.execute(
                """
                SELECT DISTINCT crop_name 
                FROM crop_data 
                WHERE soil_type = %s AND season = %s
                """,
                (soil_type, season)
            )

            crops = cursor.fetchall()

            if not crops:
                flash('No crop data available for the selected soil type and season.', 'info')

        except mysql.connector.Error as err:
            flash(f'Error: {err}', 'danger')
        
        finally:
            cursor.close()
            conn.close()

    return render_template('crop_suggestion.html', crops=crops)

# Crop data statistics route
@app.route('/crop_data_stats')
def crop_data_stats():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # Example query to get yield trends over time (Modify as per your data structure)
        cursor.execute(
            """
            SELECT crop_name, COUNT(*) as count 
            FROM crop_data 
            GROUP BY crop_name
            """
        )
        crop_trends = cursor.fetchall()

        # Example query for crop distribution by location
        cursor.execute(
            """
            SELECT location, COUNT(*) as count 
            FROM crop_data 
            GROUP BY location
            """
        )
        location_distribution = cursor.fetchall()

    except mysql.connector.Error as err:
        flash(f'Error: {err}', 'danger')
        crop_trends = []
        location_distribution = []
    
    finally:
        cursor.close()
        conn.close()

    return render_template('crop_data_stats.html', crop_trends=crop_trends, location_distribution=location_distribution)

if __name__ == '__main__':
    app.run(debug=True)