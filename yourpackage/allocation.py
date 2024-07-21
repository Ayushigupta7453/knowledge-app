from flask import Blueprint, render_template, request, redirect, url_for, session
import psycopg2
import psycopg2.extras
from datetime import datetime

# Assuming conn is your psycopg2 connection object
conn = psycopg2.connect(database="postgres", user="postgres", password="shikucode", host="localhost", port="5432")

allocation_bp = Blueprint('allocation_bp', __name__)

@allocation_bp.route('/allocations')
def allocations():
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    if 'loggedin' in session:
        cursor.execute("SELECT id, name, test_type, created_on FROM test_type_allocations")
        allocations = cursor.fetchall()
        cursor.close()
        return render_template('allocation.html', allocations=allocations)
    return redirect(url_for('login'))

@allocation_bp.route('/allocate', methods=['POST'])
def allocate():
    if 'loggedin' in session:
        name = request.form['name']
        test_type = request.form['test_type']
        
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM test_type_allocations WHERE name = %s AND test_type = %s", (name, test_type))
        existing_allocation = cursor.fetchone()
        
        if existing_allocation:
            cursor.close()
            return redirect(url_for('allocation_bp.allocations', message="User & Test Type already Exists"))

        cursor.execute("INSERT INTO test_type_allocations (name, test_type, created_on) VALUES (%s, %s, %s)", (name, test_type, datetime.utcnow()))
        conn.commit()
        cursor.close()
        
        return redirect(url_for('allocation_bp.allocations'))
    return redirect(url_for('login'))

@allocation_bp.route('/delete_allocation/<int:id>')
def delete_allocation(id):
    if 'loggedin' in session:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM test_type_allocations WHERE id = %s", (id,))
        conn.commit()
        cursor.close()
        
        return redirect(url_for('allocation_bp.allocations'))
    return redirect(url_for('login'))
