from flask import render_template, url_for, flash, redirect, request
from datetime import datetime, timedelta
from flaskweb.forms import RegistrationForm, LoginForm
from flaskweb.models import User
from flaskweb import app, db, bcrypt
from flask_login import login_user, current_user, logout_user
import jwt


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/reg', methods=['GET', 'POST'])
def reg():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashes_psw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        token = jwt.encode({'user': form.email.data, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                           app.config['SECRET_KEY'])
        user = User(username=form.username.data, email=form.email.data, password=hashes_psw, token=token)
        db.session.add(user)
        db.session.commit()
        flash(f'Your account has been create. Please log in!', 'success')
        return redirect(url_for('index'))
    return render_template('reg.html', title='Register', form=form)


@app.route('/log', methods=['GET', 'POST'])
def log():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            token = jwt.encode({'user': form.email.data, 'exp': datetime.utcnow() + timedelta(minutes=30)},
                               app.config['SECRET_KEY'])
            user.token = token
            db.session.add(user)
            db.session.commit()
            flash(f'Login successful. Welcome, {user.username}', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login unsuccessful, please check email and password', 'danger')
    return render_template('log.html', title="Login", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/protected')
def protected():
    token = request.args.get('token')
    user = User.query.filter_by(token=token).first()
    if user:
        return '<h1>The token has been verified {}</h1>'.format(token)
    return '<h1>Could not verify your token</h1>'
