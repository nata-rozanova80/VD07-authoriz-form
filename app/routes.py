from flask import render_template, request, redirect, url_for, flash, get_flashed_messages
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User
from app import app, db, bcrypt
from app.forms import RegistrationForm, LoginForm, ProfileForm

@app.route('/')
@app.route('/home')
def home():
    # Получаем все сообщения из сессии
    messages = get_flashed_messages()
    return render_template('home.html', messages=messages)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Вы успешно зарегистрировались!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title='Register', messages=get_flashed_messages())

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Вы успешно вошли в систему!', 'success')  # Добавлено сообщение об успешном входе
            return redirect(url_for('home'))
        else:
            flash('Введены неверные данные', 'danger')  # Уточняем, что это ошибка
    return render_template('login.html', form=form, title='Login', messages=get_flashed_messages())

@app.route('/logout')
def logout():
    logout_user()
    flash('Вы вышли из системы', 'success')  # Добавлено сообщение о выходе
    return redirect(url_for('home'))

@app.route('/account')
@login_required
def account():
    return render_template('account.html', messages=get_flashed_messages())

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = ProfileForm()
    if form.validate_on_submit():
        current_user.username = form.name.data
        current_user.email = form.email.data
        if form.password.data:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            current_user.password = hashed_password
        db.session.commit()
        flash('Ваш профиль был обновлен!', 'success')
        return redirect(url_for('edit_profile'))
    elif request.method == 'GET':
        form.name.data = current_user.username
        form.email.data = current_user.email
    return render_template('edit_profile.html', form=form, title='Edit Profile', messages=get_flashed_messages())