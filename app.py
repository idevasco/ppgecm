from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua-chave-secreta-aqui'

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(150), nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    categoria = db.Column(db.String(100), nullable=True)
    registros = db.relationship('Registro', backref='usuario', lazy=True)

class Registro(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(200), nullable=False)
    authors = db.Column(db.Text, nullable=True)
    journal = db.Column(db.String(200), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    doi = db.Column(db.String(200), unique=True, nullable=True)
    docente = db.Column(db.String(200), nullable=True)
    discente = db.Column(db.String(200), nullable=True)
    graduacao = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def home():
    sort_by = request.args.get('sort_by', 'year')
    direction = request.args.get('direction', 'asc')
    sort_column = getattr(Registro, sort_by, Registro.year)
    registros = Registro.query.order_by(
        sort_column.desc() if direction == 'desc' else sort_column.asc()
    ).all() if current_user.is_admin else Registro.query.filter_by(user_id=current_user.id).all()
    return render_template('home.html', registros=registros, current_sort=sort_by, current_direction=direction)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        flash('Usuário ou senha inválidos.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
@login_required
def signup():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        categoria = request.form['categoria']
        is_admin = 'is_admin' in request.form
        if User.query.filter_by(username=username).first():
            flash('Nome de usuário já existe.')
            return redirect(url_for('signup'))
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(full_name=full_name, username=username, password=hashed_pw, categoria=categoria, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()
        flash('Usuário criado com sucesso.')
        return redirect(url_for('manage_users'))
    return render_template('signup.html')

@app.route('/manage_users')
@login_required
def manage_users():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    sort_by = request.args.get('sort_by', 'full_name')
    direction = request.args.get('direction', 'asc')
    sort_column = getattr(User, sort_by, User.full_name)
    users = User.query.order_by(
        sort_column.desc() if direction == 'desc' else sort_column.asc()
    ).all()
    return render_template('manage_users.html', users=users, current_sort=sort_by, current_direction=direction)

@app.route('/edit_user/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_user(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(id)
    if request.method == 'POST':
        user.full_name = request.form['full_name']
        user.username = request.form['username']
        user.categoria = request.form['categoria']
        user.is_admin = 'is_admin' in request.form
        db.session.commit()
        flash('Usuário atualizado com sucesso.')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:id>')
@login_required
def delete_user(id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash('Usuário deletado com sucesso.')
    return redirect(url_for('manage_users'))

@app.route('/add_doi', methods=['GET', 'POST'])
@login_required
def add_doi():
    if request.method == 'POST':
        doi = request.form['doi'].strip()
        if Registro.query.filter_by(doi=doi).first():
            flash('Este DOI já foi cadastrado.', 'warning')
            return redirect(url_for('add_doi'))
        headers = {'Accept': 'application/vnd.citationstyles.csl+json'}
        response = requests.get(f'https://doi.org/{doi}', headers=headers)
        if response.status_code == 200:
            metadata = response.json()
            titulo = metadata.get('title', 'Título não encontrado')
            authors = [author.get("given", "") + " " + author.get("family", "") for author in metadata.get("author", [])]
            journal = metadata.get("container-title", "Revista não encontrada")
            year = None
            for key in ["published-print", "published-online", "issued"]:
                date_parts = metadata.get(key, {}).get("date-parts", None)
                if date_parts and date_parts[0]:
                    year = date_parts[0][0]
                    break
            novo_registro = Registro(
                titulo=titulo,
                authors=", ".join(authors),
                journal=journal,
                year=year,
                doi=doi,
                user_id=current_user.id
            )
            db.session.add(novo_registro)
            db.session.commit()
            return redirect(url_for('home'))
        else:
            flash('Erro ao buscar DOI.')
    return render_template('add_doi.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    registro = Registro.query.get_or_404(id)
    if registro.user_id != current_user.id and not current_user.is_admin:
        return redirect(url_for('home'))
    authors_list = registro.authors.split(', ') if registro.authors else []
    users = User.query.all()
    if request.method == 'POST':
        novo_doi = request.form['doi'].strip()
        if novo_doi != registro.doi and Registro.query.filter_by(doi=novo_doi).first():
            flash('Este DOI já está cadastrado.', 'warning')
            return redirect(url_for('edit', id=id))
        registro.titulo = request.form['titulo']
        registro.authors = request.form['authors']
        registro.journal = request.form['journal']
        registro.year = request.form['year']
        registro.doi = novo_doi
        registro.docente = request.form['docente']
        registro.discente = request.form['discente']
        registro.graduacao = request.form['graduacao']
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('edit.html', registro=registro, authors_list=authors_list, users=users)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    registro = Registro.query.get_or_404(id)
    if registro.user_id == current_user.id or current_user.is_admin:
        db.session.delete(registro)
        db.session.commit()
    return redirect(url_for('home'))
    
@app.route('/reset_db')
def reset_db():
    db.drop_all()
    db.create_all()
    return "Banco de dados reiniciado com sucesso."
    
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_pw = request.form['current_password']
        new_pw = request.form['new_password']
        confirm_pw = request.form['confirm_password']

        if not check_password_hash(current_user.password, current_pw):
            flash('Senha atual incorreta.')
        elif new_pw != confirm_pw:
            flash('As novas senhas não coincidem.')
        else:
            current_user.password = generate_password_hash(new_pw, method='pbkdf2:sha256')
            db.session.commit()
            flash('Senha alterada com sucesso.')
            return redirect(url_for('home'))
    return render_template('change_password.html')            

@app.route('/setup_admin', methods=['GET', 'POST'])
def setup_admin():
    if User.query.first():
        return redirect(url_for('login'))
    if request.method == 'POST':
        full_name = request.form['full_name']
        username = request.form['username']
        password = request.form['password']
        categoria = request.form['categoria']
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        admin_user = User(full_name=full_name, username=username, password=hashed_pw, categoria=categoria, is_admin=True)
        db.session.add(admin_user)
        db.session.commit()
        flash('Administrador criado com sucesso.')
        return redirect(url_for('login'))
    return render_template('setup_admin.html')

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)

