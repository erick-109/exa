#####################inicial#########################

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash # type: ignore
import sqlite3, os
from datetime import datetime

app = Flask(__name__)
# Por (usando variables de entorno):
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'clave-temporal-para-desarrollo')

# Ruta principal
@app.route('/')
def index():
    conn = get_db_connection()
    tasks = conn.execute('''
        SELECT tasks.*, users.username 
        FROM tasks 
        JOIN users ON tasks.user_id = users.id 
        WHERE completed = 0
    ''').fetchall()
    conn.close()
    return render_template('index.html', tasks=tasks)

# Configuración de la base de datos
def get_db_connection():
    conn = sqlite3.connect('tareas.db')
    conn.row_factory = sqlite3.Row
    return conn

# Crear tablas si no existen
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            completed BOOLEAN DEFAULT 0,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

#######################inicio#######################

########################autenticacion######################

# Registro de usuarios
#inisio de sesion
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        try:
            password_hash = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, password_hash, created_at)
                VALUES (?, ?, ?)
            ''', (username, password_hash, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
        except sqlite3.IntegrityError:
            flash('El usuario ya existe.', 'danger')
            return redirect(url_for('register'))
        finally:
            conn.close()
        
        flash('¡Registro exitoso! Por favor inicia sesión.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Inicio de sesión
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('¡Usuario o contraseña inválidos!', 'danger')
            return redirect(url_for('login'))
    
    return render_template('login.html')
# Cerrar sesión
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('index'))

########################autenticacion######################

####################gestion de tareas##########################
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please login to access the dashboard.')
        return redirect(url_for('login'))
    conn = get_db_connection()
    tasks = conn.execute('''
        SELECT * FROM tasks 
        WHERE user_id = ?
        ORDER BY created_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', tasks=tasks)

@app.route('/create_task', methods=['POST'])
def create_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    title = request.form['title']
    description = request.form.get('description', '')
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO tasks (title, description, user_id, created_at)
        VALUES (?, ?, ?, ?)
    ''', (title, description, session['user_id'], created_at))
    conn.commit()
    conn.close()
    
    flash('Tarea creada exitosamente','success')
    return redirect(url_for('dashboard'))

@app.route('/complete_task/<int:task_id>')
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('UPDATE tasks SET completed = 1 WHERE id = ? AND user_id = ?', 
                 (task_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Tarea Completa Exitosamente','success')
    return redirect(url_for('dashboard'))

@app.route('/edit_task/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', 
                       (task_id, session['user_id'])).fetchone()
    
    if not task:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        
        conn.execute('''
            UPDATE tasks 
            SET title = ?, description = ? 
            WHERE id = ? AND user_id = ?
        ''', (title, description, task_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Tarea completa','success')
        return redirect(url_for('dashboard'))
    
    conn.close()
    return render_template('edit_task.html', task=task)

@app.route('/delete_task/<int:task_id>')
def delete_task(task_id):
    if 'user_id' not in session:
        flash('¡Debes inciar sesion para eliminar tareas!', 'danger')
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
                 (task_id, session['user_id']))
    conn.commit()
    conn.close()
    
    flash('Tarea eliminada exitosamente!','success')
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
####################gestion de tareas##########################
