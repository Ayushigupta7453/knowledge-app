from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify, render_template_string
import psycopg2  # pip install psycopg2
import psycopg2.extras
import re
from werkzeug.security import generate_password_hash, check_password_hash
import os
import base64

from yourpackage.allocation import allocation_bp
from yourpackage.user_test import user_test_bp



app = Flask(__name__)




app.secret_key = 'cairocoders-ednalan'
app.register_blueprint(allocation_bp)

DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "shikucode"
DB_PORT = "5432" # Corrected the port number for PostgreSQL



def get_db_connection():
    return psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)

try:
     conn = get_db_connection()
except psycopg2.OperationalError as e:
    print("Error while connecting to PostgreSQL", e)
    # Add appropriate error handling here, e.g., exit or retry logic


app.register_blueprint(user_test_bp, url_prefix='/user_test')

@app.route('/')
def home():
    if 'loggedin' in session:
        # Ensure profile_picture is available in session, provide a default value if not
        profile_picture = session.get('profile_picture', None)
        return render_template('dashboard.html', profile_picture=profile_picture)
    return redirect(url_for('login'))

@app.route('/login/', methods=['GET', 'POST'])
def login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            password_rs = account['password']
            if check_password_hash(password_rs, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['email'] = account['email']
                session['profile_picture'] = account['profile_picture']  # Ensure this line is present
                session['full_name'] = f"{account['first_name']} {account['last_name']}"  # Store full name in session
                return redirect(url_for('dashboard'))
            else:
                flash('Incorrect email/password')
        else:
            flash('Incorrect email/password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST' and 'first_name' in request.form and 'password' in request.form and 'email' in request.form:
        
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password']
        email = request.form['email']
        phone = request.form['phone']
        profile_picture = request.files['profile_picture']
        _hashed_password = generate_password_hash(password)
        
        upload_folder = os.path.join('static', 'uploads')
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Save the uploaded file
        if profile_picture and profile_picture.filename != '':
            profile_picture_filename = profile_picture.filename
            profile_picture_path = os.path.join(upload_folder, profile_picture_filename)
            profile_picture.save(profile_picture_path)
            #correction
            profile_picture_path = os.path.join('uploads', profile_picture_filename).replace("\\", "/")
        else:
            profile_picture_filename = None
        

        print(f"first_name: {first_name}, last_name: {last_name}, email: {email}, phone: {phone}, profile_picture_path: {profile_picture_path}")

        try:
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            account = cursor.fetchone()
            if account:
                flash('Account already exists!')
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                flash('Invalid email address!')
            elif not re.match(r'[A-Za-z0-9]+', first_name):
                flash('Username must contain only characters and numbers!')
            elif not first_name or not password or not email:
                flash('Please fill out the form!')
            else:
                cursor.execute("""
                    INSERT INTO users (first_name, last_name, email, password, phone, profile_picture)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (first_name, last_name, email, _hashed_password, phone, profile_picture_path))  # Removed duplicated 'email' column
                conn.commit()
                flash('You have successfully registered!')
                return redirect(url_for('login'))
        except Exception as e:
            print(f"Error: {e}")
            flash('An error occurred during registration. Please try again.')

    elif request.method == 'POST':
        flash('Please fill out the form!')
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()  # Clear all session variables
    return redirect(url_for('login'))

@app.route('/profile')
def profile():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()
        cursor.close()

        # Debugging: Print fetched account data to console
        print("Fetched account data:", account)
        
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/users')
def users():
    # cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # if 'loggedin' in session:
    #     cursor.execute('SELECT * FROM users')
    #     users_list = cursor.fetchall()
    #     cursor.close()
    #     return render_template('users.html', users=users_list)
    # return redirect(url_for('login'))
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM users')
        users_list = cursor.fetchall()
        cursor.close()
        return render_template('users.html', users=users_list)
    return redirect(url_for('login'))




@app.route('/adduser', methods=['GET', 'POST'])
def adduser():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        if request.method == 'POST' and 'first_name' in request.form and 'password' in request.form and 'email' in request.form:
            
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            password = request.form['password']
            email = request.form['email']
            phone = request.form['phone']
            profile_picture = request.files['profile_picture']
            _hashed_password = generate_password_hash(password)
            
            upload_folder = os.path.join('static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)

            # Save the uploaded file
            if profile_picture and profile_picture.filename != '':
                profile_picture_filename = profile_picture.filename
                profile_picture_path = os.path.join(upload_folder, profile_picture_filename)
                profile_picture.save(profile_picture_path)
            else:
                profile_picture_filename = None

            try:
                cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
                account = cursor.fetchone()
                if account:
                    flash('Account already exists!')
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    flash('Invalid email address!')
                elif not re.match(r'[A-Za-z0-9]+', first_name):
                    flash('Username must contain only characters and numbers!')
                elif not first_name or not password or not email:
                    flash('Please fill out the form!')
                else:
                    cursor.execute("""
                        INSERT INTO users (first_name, last_name, email, password, phone, profile_picture)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (first_name, last_name, email, _hashed_password, phone, profile_picture_path))
                    conn.commit()
                    flash('User has been successfully added!')
                    return redirect(url_for('users'))
            except Exception as e:
                print(f"Error: {e}")
                flash('An error occurred while adding the user. Please try again.')
        return render_template('adduser.html')
    return redirect(url_for('login'))


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        profile_picture = request.files['profile_picture']
        
        # Update user details in the database
        cursor.execute("""
            UPDATE users 
            SET first_name = %s, last_name = %s, email = %s, phone = %s, profile_picture = %s 
            WHERE id = %s
        """, (first_name, last_name, email, phone, profile_picture.filename, user_id))
        conn.commit()
        flash('User updated successfully')
        return redirect(url_for('users'))
    
    cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    user = cursor.fetchone()
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
    conn.commit()
    flash('User deleted successfully')
    return redirect(url_for('users'))


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        cursor.execute('SELECT * FROM users WHERE id = %s', [session['id']])
        account = cursor.fetchone()

        if account and check_password_hash(account['password'], current_password):
            if new_password == confirm_password:
                _hashed_password = generate_password_hash(new_password)
                cursor.execute('UPDATE users SET password = %s WHERE id = %s', (_hashed_password, session['id']))
                conn.commit()
                flash('Password successfully changed!')
                return redirect(url_for('profile'))
            else:
                flash('New passwords do not match')
        else:
            flash('Current password is incorrect')
    return render_template('change_password.html')


@app.route('/testtype')
def testtype():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM test_entries2')
        test_list = cursor.fetchall()
        cursor.close()
        return render_template('testtype.html', tests=test_list)
    return redirect(url_for('login'))

         


@app.route('/addtest', methods=['GET', 'POST'])
def addtest():
    if 'loggedin' in session:
        if request.method == 'POST':
            # Get form data
           # test_id = request.form['Id']
            test_type = request.form['test_type']
            language = request.form['language']
            
            try:
                cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
                # Insert data into the database
                cursor.execute("""
                            INSERT INTO test_entries2(test_type, language)
                            VALUES ( %s, %s)
                        """, ( test_type, language))
                conn.commit()
                cursor.close()
                return redirect(url_for('testtype'))
            except (Exception, psycopg2.DatabaseError) as error:
                conn.rollback()
                flash(f'Error: {error}', 'danger')
        
        return render_template('addtest.html')
    flash('Please log in to access this page.', 'danger')
    return redirect(url_for('login'))

         

@app.route('/deletetest/<int:test_id>', methods=['POST'])
def deletetest(test_id):
    if 'loggedin' in session:
        try:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            # Delete data from the database
            cursor.execute('DELETE FROM test_entries2 WHERE id = %s', (test_id,))
            conn.commit()
            cursor.close()
            
            flash('Test type deleted successfully!', 'success')
        except (Exception, psycopg2.DatabaseError) as error:
            conn.rollback()
            flash(f'Error: {error}', 'danger')
    
    return redirect(url_for('testtype'))         


@app.route('/reports', methods=['GET', 'POST'])
def reports():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    
    # Fetch the test type entries for the dropdown
    cursor.execute("SELECT DISTINCT test_type FROM test_entries")
    test_types = cursor.fetchall()
    
    # Handle form submission
    report_data = []
    if request.method == 'POST':
        user = request.form.get('user')
        test_type = request.form.get('test_type')
        
        query = "SELECT * FROM test_entries WHERE 1=1"
        params = []
        
        if user:
            query += " AND user = %s"
            params.append(user)
        
        if test_type:
            query += " AND test_type = %s"
            params.append(test_type)
        
        cursor.execute(query, params)
        report_data = cursor.fetchall()
    
    cursor.close()
    
    return render_template('reports.html', test_types=test_types, report_data=report_data)

@app.route('/test_data')
def test_data():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor.execute('SELECT * FROM test_data')
        test_list = cursor.fetchall()
        cursor.close()
        return render_template('test_data.html', tests=test_list)
    return redirect(url_for('login'))

@app.route('/addtestentries', methods=['GET', 'POST'])
def addtestentries():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor.execute("SELECT DISTINCT test_type FROM test_type_allocations")
        test_types = cursor.fetchall()
        if request.method == 'POST':
            test_type = request.form['test_type']
            question = request.form['question']
            question_image = request.files['question_image']
            answer_a = request.form['answer_a']
            answer_b = request.form['answer_b']
            answer_c = request.form['answer_c']
            answer_d = request.form['answer_d']
            correct_answer = request.form['correct_answer']
            created_by = session['full_name']  # Assuming 'full_name' is stored in session

            # Save the uploaded file
            upload_folder = os.path.join('static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            if question_image and question_image.filename != '':
                question_image_filename = question_image.filename
                question_image_path = os.path.join(upload_folder, question_image_filename)
                question_image.save(question_image_path)
            else:
                question_image_filename = None

            try:
                cursor.execute("""
                    INSERT INTO test_data (test_type, question, question_image, answer_a, answer_b, answer_c, answer_d, correct_answer, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (test_type, question, question_image_filename, answer_a, answer_b, answer_c, answer_d, correct_answer, created_by))
                conn.commit()
                flash('Test data added successfully!')
                return redirect(url_for('test_data'))
            except Exception as e:
                print(f"Error: {e}")
                flash('An error occurred while adding test data. Please try again.')

        return render_template('addtestentries.html',test_types=test_types)   
    return redirect(url_for('login'))


#dashboard routing

def get_dashboard_data():
    try:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        
        cursor.execute("SELECT COUNT(*) FROM test_entries2")
        test_type_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM users")  # Note the correct table name if it's case-sensitive
        total_students = cursor.fetchone()[0]
        
        cursor.close()
        
        return test_type_count, total_students
    except psycopg2.DatabaseError as error:
        print(f"Database error occurred: {error}")
        return None, None


@app.route('/dashboard')
def dashboard():
    test_type_count, total_students = get_dashboard_data()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute("SELECT test_type, COUNT(*) as count FROM test_entries2 GROUP BY test_type")
    test_type_data = cursor.fetchall()
    cursor.close()
    return render_template('dashboard.html', test_type_count=test_type_count, total_students=total_students,test_type_data=test_type_data)

@app.route('/delete_test/<int:test_id>', methods=['POST'])
def delete_test(test_id):
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM test_data WHERE id = %s", (test_id,))
        conn.commit()
        flash('Test deleted successfully!')
    except Exception as e:
        print(f"Error: {e}")
        flash('An error occurred while deleting the test.')
    return redirect(url_for('test_data'))

#correction side bar 
@app.route('/sidebar')
def some_route():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    # Assuming session['user_id'] holds the ID of the currently logged-in user
    user_email = session.get('user_email')
    cursor.execute('SELECT * FROM users WHERE email = %s', (user_email,))
    user_details = cursor.fetchone()
    profile_picture = user_details['profile_picture'] if user_details else None
    return render_template('Sidebar.html', profile_picture=profile_picture)


################# API ENDPOINTS ###################################
@app.route('/api/login', methods=['POST'])
def api_login():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if request.method == 'POST':
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            password_rs = account['password']
            if check_password_hash(password_rs, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['email'] = account['email']
                session['profile_picture'] = account['profile_picture']
                session['full_name'] = f"{account['first_name']} {account['last_name']}"
                return jsonify({"message": "Login successful", "user": session['email']}), 200
            else:
                return jsonify({"message": "Incorrect email/password"}), 401
        else:
            return jsonify({"message": "Incorrect email/password"}), 401
    return jsonify({"message": "Bad Request"}), 400

@app.route('/api/register', methods=['POST'])
def api_register():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    data = request.get_json()
    if request.method == 'POST':
        first_name = data.get('first_name')
        last_name = data.get('last_name')
        password = data.get('password')
        email = data.get('email')
        phone = data.get('phone')
        profile_picture = data.get('profile_picture')  # Assuming profile_picture is a base64 encoded string

        _hashed_password = generate_password_hash(password)
        
        # Save the uploaded profile picture
        profile_picture_path = None
        if profile_picture:
            upload_folder = os.path.join('static', 'uploads')
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            profile_picture_filename = f"{email}_profile.png"  # You can use a better naming strategy
            profile_picture_path = os.path.join(upload_folder, profile_picture_filename)
            with open(profile_picture_path, "wb") as fh:
                fh.write(base64.b64decode(profile_picture))

        try:
            
            cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
            account = cursor.fetchone()
            if account:
                return jsonify({"message": "Account already exists!"}), 409
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                return jsonify({"message": "Invalid email address!"}), 400
            elif not re.match(r'[A-Za-z0-9]+', first_name):
                return jsonify({"message": "Username must contain only characters and numbers!"}), 400
            elif not first_name or not password or not email:
                return jsonify({"message": "Please fill out the form!"}), 400
            else:
                cursor.execute("""
                    INSERT INTO users (first_name, last_name, email, password, phone, profile_picture)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (first_name, last_name, email, _hashed_password, phone, profile_picture_path))
                conn.commit()
                return jsonify({"message": "You have successfully registered!"}), 201
        except Exception as e:
            print(f"Error: {e}")
            return jsonify({"message": "An error occurred during registration. Please try again."}), 500

    return jsonify({"message": "Bad Request"}), 400
 


if __name__ == "_main_":
    app.run(debug=True, port=5001)