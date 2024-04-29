#Imports
from flask import Flask, redirect, render_template, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_login import UserMixin, login_user, logout_user, current_user, login_required, LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo


#Some declarations and configs ===============================================================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'KYbCwiGAepocU0lQu7dmSEVhqgxHBFv2tr'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
db = SQLAlchemy(app)
db.metadata.clear()
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#Classes and definitions =====================================================================================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    expenses = db.relationship('Expense', backref='owner', lazy='dynamic')

    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)

with app.app_context():
    db.create_all()


#Login and register forms validation ===========================================================================================================
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=40)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Route definitions ============================================================================================================================
@app.route('/')
@login_required
def index():
    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', expenses=user_expenses)

@app.route('/dashboard')
@login_required
def dashboard():
    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', expenses=user_expenses)

@app.route('/add', methods=['POST'])
@login_required
def add_expense():
    description = request.form.get('description')
    amount = request.form.get('amount')
    if description and amount:
        new_expense = Expense(description=description, amount=float(amount),user_id=current_user.id)
        db.session.add(new_expense)
        db.session.commit()
        return redirect(url_for('index'))
    return 'There was an issue adding your expense'

@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):
    expense_to_delete = Expense.query.filter_by(id=id, user_id=current_user.id).first_or_404()
    db.session.delete(expense_to_delete)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = User.hash_password(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login(): #Check if user is already authenticated
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

#Quite self-explanatory what this does
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Run program
if __name__ == '__main__':
    app.run(debug=True)