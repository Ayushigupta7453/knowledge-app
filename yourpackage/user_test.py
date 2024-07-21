from flask import Blueprint, request, render_template, redirect, url_for, flash, session, jsonify
import psycopg2
import psycopg2.extras

user_test_bp = Blueprint('user_test', __name__)

DB_HOST = "localhost"
DB_NAME = "postgres"
DB_USER = "postgres"
DB_PASS = "shikucode"
DB_PORT = "5432"

def get_db_connection():
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        host=DB_HOST,
        port=DB_PORT
    )
    return conn

@user_test_bp.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT test_type FROM test_data')
    tests = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return render_template('selection.html', tests=tests)

@user_test_bp.route('/selection')
def selection():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT test_type FROM test_data')
    tests = [row[0] for row in cursor.fetchall()]
    cursor.close()
    conn.close()
    return render_template('selection.html', tests=tests)

@user_test_bp.route('/start_test', methods=['POST'])
def start_test():
    test_type = request.form['test_type']
    session['test_type'] = test_type
    return redirect(url_for('user_test.show_question'))

# @user_test_bp.route('/show_question')
# def show_question():
#     test_type = session.get('test_type')
#     conn = get_db_connection()
#     cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
#     cursor.execute('SELECT * FROM test_data WHERE test_type = %s ORDER BY id LIMIT 1', (test_type,))
#     question = cursor.fetchone()
#     cursor.close()
#     conn.close()
#     if question:
#         return render_template('user_test.html', question=question)
#     return 'No questions available for this test type.'

@user_test_bp.route('/check_answer', methods=['POST'])
def check_answer():
    question_id = int(request.form['question_id'])
    selected_answer = request.form['answer']
    test_type = request.form['test_type']

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT correct_answer FROM test_data WHERE id = %s', (question_id,))
    correct_answer = cursor.fetchone()['correct_answer']
    cursor.close()
    conn.close()

    response = {
        'correct_answer': correct_answer,
        'selected_answer': selected_answer,
        'correct': selected_answer == correct_answer
    }

    return jsonify(response)

# @user_test_bp.route('/next_question', methods=['POST'])
# def next_question():
#     question_id = int(request.form['question_id'])
#     test_type = request.form['test_type']

#     conn = get_db_connection()
#     cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
#     cursor.execute('SELECT * FROM test_data WHERE test_type = %s AND id > %s ORDER BY id LIMIT 1', (test_type, question_id))
#     next_question = cursor.fetchone()
#     cursor.close()
#     conn.close()

#     if next_question:
#         return render_template('user_test.html', question=next_question)
 #   return 'No more questions available for this test type.'
@user_test_bp.route('/show_question')
def show_question():
    test_type = session.get('test_type')
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM test_data WHERE test_type = %s ORDER BY id', (test_type,))
    questions = cursor.fetchall()
    cursor.close()
    conn.close()
    
    if questions:
        session['questions'] = [dict(q) for q in questions]  # Convert to list of dicts
        session['current_question_index'] = 0
        question = session['questions'][session['current_question_index']]
        return render_template('User_test.html', question=question)
    return 'No questions available for this test type.'

@user_test_bp.route('/next_question', methods=['POST'])
def next_question():
    question_id = int(request.form['question_id'])
    test_type = request.form['test_type']

    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    cursor.execute('SELECT * FROM test_data WHERE test_type = %s AND id > %s ORDER BY id LIMIT 1', (test_type, question_id))
    next_question = cursor.fetchone()
    cursor.close()
    conn.close()

    if next_question:
        question_html = render_template('question_partial.html', question=next_question)
        return jsonify({'html': question_html})
    return jsonify({'html': ''})



@user_test_bp.route('/test_results')
def test_results():
    return render_template('test_results.html')


