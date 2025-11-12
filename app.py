import os, base64
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# === CONFIGURACIÓN DE LA APP ===
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
app.config['SECRET_KEY'] = 'clave_nutripy'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://nutripy_admin:1234@localhost/nutripy'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# === MODELOS ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(100))

class Paciente(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100))
    cedula = db.Column(db.String(20))
    telefono = db.Column(db.String(20))
    edad = db.Column(db.Integer)
    notas = db.Column(db.String(200))

class Consulta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    paciente_id = db.Column(db.Integer, db.ForeignKey('paciente.id'))
    resumen = db.Column(db.Text)
    firma_img = db.Column(db.Text)
    firma_cripto = db.Column(db.Text)
    fecha = db.Column(db.String(50))
    paciente = db.relationship('Paciente', backref=db.backref('consultas', lazy=True))

# === CLAVES RSA ===
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'keys', 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, 'keys', 'public_key.pem')

def generar_claves():
    if not os.path.exists('keys'):
        os.makedirs('keys')
    if not os.path.exists(PRIVATE_KEY_PATH):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("🔑 Claves RSA generadas correctamente.")

# === LOGIN ===
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/init')
def init():
    db.create_all()
    generar_claves()
    if not User.query.filter_by(username='admin').first():
        db.session.add(User(username='admin', password=generate_password_hash('admin123')))
        db.session.commit()
    return "Base de datos inicializada y usuario admin creado."

# === REGISTRO DE USUARIO ===
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Las contraseñas no coinciden')
            return render_template('registro.html')

        if User.query.filter_by(username=username).first():
            flash('El usuario ya existe')
            return redirect(url_for('registro'))

        hashed_password = generate_password_hash(password)
        db.session.add(User(username=username, password=hashed_password))
        db.session.commit()
        flash('Usuario creado correctamente')
        return redirect(url_for('login'))

    return render_template('registro.html')

# === RESTABLECER CONTRASEÑA ===
@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if request.method == 'POST':
        username = request.form['username']
        nuevo_pass = request.form['password']
        confirm_pass = request.form['confirm_password']

        if nuevo_pass != confirm_pass:
            flash('⚠️ Las contraseñas no coinciden')
            return redirect(url_for('reset'))

        user = User.query.filter_by(username=username).first()
        if user:
            user.password = generate_password_hash(nuevo_pass)
            db.session.commit()
            flash('✅ Contraseña actualizada correctamente')
            return redirect(url_for('login'))
        else:
            flash('⚠️ Usuario no encontrado')
            return redirect(url_for('reset'))

    return render_template('reset.html')

# === RUTAS PRINCIPALES ===
@app.route('/')
@login_required
def ver_pacientes():
    pacientes = Paciente.query.all()
    return render_template('pacientes.html', pacientes=pacientes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('ver_pacientes'))
        else:
            flash('Usuario o contraseña incorrectos')
    return render_template('login.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/paciente/nuevo', methods=['GET', 'POST'])
@login_required
def nuevo_paciente():
    if request.method == 'POST':
        nuevo = Paciente(
            nombre=request.form['nombre'],
            cedula=request.form['cedula'],
            telefono=request.form['telefono'],
            edad=request.form['edad'],
            notas=request.form['notas']
        )
        db.session.add(nuevo)
        db.session.commit()
        return redirect(url_for('ver_pacientes'))
    return render_template('paciente_form.html')

@app.route('/paciente/<int:id>/consulta', methods=['GET', 'POST'])
@login_required
def nueva_consulta(id):
    paciente = Paciente.query.get_or_404(id)
    if request.method == 'POST':
        resumen = request.form['resumen']
        firma_img = request.form['firma_img']

        # firmar el texto
        private_key = serialization.load_pem_private_key(open(PRIVATE_KEY_PATH, "rb").read(), password=None)
        texto = f"{paciente.nombre}|{resumen}|{datetime.now()}"
        firma_cripto = base64.b64encode(private_key.sign(
            texto.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )).decode()

        consulta = Consulta(
            paciente_id=id,
            resumen=resumen,
            firma_img=firma_img,
            firma_cripto=firma_cripto,
            fecha=datetime.now().strftime("%Y-%m-%d %H:%M")
        )
        db.session.add(consulta)
        db.session.commit()
        return redirect(url_for('ver_pacientes'))

    return render_template('consulta_form.html', paciente=paciente)

@app.route('/consulta/<int:id>')
@login_required
def ver_consulta(id):
    consulta = Consulta.query.options(db.joinedload(Consulta.paciente)).get_or_404(id)
    return render_template('ficha_consulta.html', consulta=consulta)

@app.route('/paciente/<int:id>/historial')
@login_required
def historial_consultas(id):
    paciente = Paciente.query.get_or_404(id)
    return render_template('historial.html', paciente=paciente)

@app.route('/paciente/<int:id>/editar', methods=['GET', 'POST'])
@login_required
def editar_paciente(id):
    paciente = Paciente.query.get_or_404(id)
    if request.method == 'POST':
        paciente.nombre = request.form['nombre']
        paciente.cedula = request.form['cedula']
        paciente.telefono = request.form['telefono']
        paciente.edad = request.form['edad']
        paciente.notas = request.form['notas']
        db.session.commit()
        flash('Paciente actualizado correctamente')
        return redirect(url_for('ver_pacientes'))
    return render_template('paciente_form.html', paciente=paciente)

if __name__ == '__main__':
    app.run(debug=True)