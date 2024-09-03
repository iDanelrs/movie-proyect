from flask import Flask, render_template, request, redirect, url_for, make_response, flash, session, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector

app = Flask(__name__)
app.secret_key = 'mysecret'  # Asegúrate de usar una clave secreta segura

db_connection = mysql.connector.connect(
    host="mysql",
    user="root",
    passwd="Rolonlol135",
    database="db_movies"
)

cursor = db_connection.cursor(dictionary=True)

def loguser(username):
    resp = make_response(redirect(url_for('index')))  # Redirige a 'loggedin'
    maxAge = 60 * 60
    resp.set_cookie('token', '123', max_age=maxAge, path='/', secure=False, httponly=True)
    return resp

def logged_in():
    return request.cookies.get('token')

def valid_login(username, password):
    query = "SELECT * FROM users WHERE BINARY username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    if user and check_password_hash(user['password'], password):
        return True
    return False


def register_user(email, username, password):
    acc = "INSERT INTO users (email, username, password) VALUES (%s, %s, %s)"
    user_data = (email, username, generate_password_hash(password, method='pbkdf2:sha256'))
    cursor.execute(acc, user_data)
    db_connection.commit()
    return True

@app.route('/', methods=['GET', 'POST'])
def index():
    request.cookies.get('token')
    return render_template('index.html', session_user=session.get('username'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if valid_login(username, password):
            session['username'] = username  # Guardar el usuario en la sesión
            return redirect(url_for('index'))  
        else:
            flash('Invalid username/password' , 'error')
    return render_template('login.html')

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        if register_user(request.form['email'], request.form['username'], request.form['password']):
            flash('Registration successful!' , 'success') 
            return redirect(url_for('login'))
        else:
            flash('Could not create user' , 'error')
    return render_template('register.html')

@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    resp = make_response(redirect(url_for('index')))
    return resp

@app.route('/api/terms', methods=['GET' , 'POST'])
def terms():
    return render_template('terms.html')

@app.route('/api/check_user/<username>', methods=['GET'])
def check_user(username):
    query = "SELECT * FROM users WHERE BINARY username = %s"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    if user:
        return {'exists': True}
    return {'exists': False}

@app.route('/users', methods=['GET'])
def get_user():
    query = "SELECT username,email,password FROM users"
    cursor.execute(query)
    users = cursor.fetchall()
#    usersFound = [users for users in users if users['username'] == 'admin']
#    if (len(usersFound) < 0):
#       return {'users': 'No admins found'}
    return {'users': users}  

@app.route('/users', methods=['POST'])
def create_user():
    try:
        data = request.json
        if not all(key in data for key in ('email', 'username', 'password')):
            return jsonify({'success': False, 'message': 'Faltan campos requeridos'}), 400
        
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        if register_user(data['email'], data['username'], hashed_password):
            return jsonify({'success': True}), 201
        
        return jsonify({'success': False, 'message': 'Registro fallido'}), 400
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/users/<username>', methods=['DELETE'])
def delete_user(username):
    try:
        query = "DELETE FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        db_connection.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 404
        
        return jsonify({'success': True}), 204
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/users/<username>', methods=['PUT'])
def update_user(username):
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        
        if not email and not password:
            return jsonify({'success': False, 'message': 'No se proporcionaron datos para actualizar'}), 400
        
        if password:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        else:
            hashed_password = None
        
        query = "UPDATE users SET email = %s, password = %s WHERE username = %s"
        cursor.execute(query, (email, hashed_password, username))
        db_connection.commit()
        
        if cursor.rowcount == 0:
            return jsonify({'success': False, 'message': 'Usuario no encontrado'}), 404
        
        return jsonify({'success': True}), 200
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
