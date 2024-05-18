#=====================================================================================================================================
#To run the program:
#
#1. Install the required packages from requirements.txt
#2. Run the app from app.py
#3. The application will be available at 127.0.0.1:5000 by default
#4. Register a new account (no accounts are available before creating one)
#5. Login
#6. Enjoy :)
#=====================================================================================================================================

#Imports
from flask import Flask, redirect, render_template, request, url_for, flash
from flask_sqlalchemy import SQLAlchemy # type: ignore
from flask_login import UserMixin, login_user, logout_user, current_user, login_required, LoginManager
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import DecimalField, StringField, PasswordField, SubmitField, ValidationError
from wtforms.validators import DataRequired, Length, EqualTo


#Program declarations and configs ===============================================================================================================
app = Flask(__name__) 
app.config['SECRET_KEY'] = 'KYbCwiGAepocU0lQu7dmSEVhqgxHBFv2tr' #CSRF token
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db' #Database connection
db = SQLAlchemy(app) #DB object
bcrypt = Bcrypt(app) #User for password encryption
login_manager = LoginManager() #Required for session control
login_manager.init_app(app) #init login manager
login_manager.login_view = 'login' #used by auth. Redirect to /login in case needed
@login_manager.user_loader 
def load_user(user_id):
    return User.query.get(int(user_id))
@login_manager.unauthorized_handler
def unauthorized_callback():
    flash('You need to be logged in to view this page.', 'warning') #Custom unauthorized handler and warning message
    return redirect(url_for('login')) #Redirect to login


#Database schema and definitions ==================================================================================================================
#User table and password functions
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    expenses = db.relationship('Expense', backref='owner', lazy='dynamic')

    #Encrypt the passwords for safety
    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')
    
    #Function for checking password matches in backend
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

#Expense table
class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) #To link user and expense together
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)  #Added category field, cannot be empty
    
with app.app_context(): #Create database tables (if missing one or many)
    db.create_all()

#Website form models and validation ===========================================================================================================
#Form to enter expenses
class ExpenseForm(FlaskForm):
    description = StringField('Description', validators=[DataRequired()])
    amount = DecimalField('Amount', validators=[DataRequired()])
    category = StringField('Category', validators=[DataRequired()])
    submit = SubmitField('Update Expense')

#Form for registering
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    #Confirm no duplicate usernames are allowed
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

#Form for login page. Checks that data is actually entered
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

#Route definitions ============================================================================================================================
#redirect user from "/" to "/dashboard"
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

#Main view for the user. Includes expenses, new entry fields, mod and delete buttons
@app.route('/dashboard')
@login_required
def dashboard():

    form = ExpenseForm()
    
    user_expenses = Expense.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', form=form, expenses=user_expenses)


#Insert expenses. The expense will be owned by the user entering it. In database, Foreign key "user.id"
@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_expense():

    form = ExpenseForm()

    if form.validate_on_submit():

        description = form.description.data
        amount = form.amount.data
        category = form.category.data
        
        new_expense = Expense(description=description, amount=amount, user_id=current_user.id, category=category)
        db.session.add(new_expense)
        db.session.commit()

        flash('Expense record has been added!', 'success')

        return redirect(url_for('index'))
    
    else:
        flash("Adding expense failed!","danger")

     


def suggest_category(description):

    #Suggest category based on past entries with the same description, fetch all records matching the description and user_id
    similar_expenses = Expense.query.filter_by(description=description, user_id=current_user.id).all()
    
    #In case more than two entries exist, get categories and return the most common category
    if len(similar_expenses) >= 2:
        
        categories = [expense.category for expense in similar_expenses if expense.category]
        
        if categories:
            
            #Create a dictionary to count occurrences of each category
            category_count = {}

            for category in categories:

                if category in category_count:
                    category_count[category] += 1
                else:
                    category_count[category] = 1
            
            #Sort the categories based on their frequency in descending order
            sorted_categories = sorted(category_count, key=category_count.get, reverse=True)
            
            #Return the most frequent category
            return sorted_categories[0]
        
    #Else return empty
    return ''


#This route is only used by the automatic category suggestion feature
@app.route('/suggest_category', methods=['POST'])
@login_required
def suggest_category_route():

    description = request.form.get('description')
    if description:
        suggested_category = suggest_category(description)
        return suggested_category if suggested_category else '', 200
    return '', 400

#Delete expenses the user owns. Auth required
@app.route('/delete/<int:id>')
@login_required
def delete_expense(id):

    #Try to get the wanted record, if found and owner by current user ID delete. Otherwise flash error message
    try:
    
        #Try to get the expense with the given id if it matches the user id
        expense_to_delete = Expense.query.filter_by(id=id, user_id=current_user.id).one()
        db.session.delete(expense_to_delete)
        db.session.commit()
        flash('Expense record has been removed!', 'success')

    #Errors
    except:
    
        # Handle the case where no expense is found
        flash('Error deleting expense record!', 'danger')
    
    return redirect(url_for('index'))

    

#Edit any expense the user owns. Auth required
@app.route('/edit/<int:expense_id>', methods=['GET', 'POST'])
@login_required
def edit_expense(expense_id):

    #The below line either gets the expense with certain id if it matches the user id too, otherwise aborts and returns 404
    expense = Expense.query.filter_by(id=expense_id, user_id=current_user.id).first_or_404()
    form = ExpenseForm()

    #If form data is valid, update expense
    if form.validate_on_submit():
        expense.description = form.description.data
        expense.amount = form.amount.data
        expense.category = form.category.data
        db.session.commit()
        flash('Expense record updated!', 'success')
        return redirect(url_for('index'))
    
    elif request.method == 'GET':
        form.description.data = expense.description
        form.amount.data = expense.amount
        form.category.data = expense.category

    return render_template('edit.html', title='Edit Expense', form=form, expense_id=expense_id)

#Create a new user. No auth required as anyone can register
@app.route('/register', methods=['GET', 'POST'])
def register():
    
    #If user is authenticated, redirect to login -> redirects to index
    if current_user.is_authenticated:

        return redirect(url_for('login'))
    
    form = RegistrationForm()

    #If form data is valid, create password hash and submit data to database
    if form.validate_on_submit():

        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()

        #Show message and go to login
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

#For user login. Requires no auth to access
@app.route('/login', methods=['GET', 'POST'])
def login():

    #In case user is logged in
    if current_user.is_authenticated:

        return redirect(url_for('index'))
    
    form = LoginForm()

    #Check form data
    if form.validate_on_submit():

        user = User.query.filter_by(username=form.username.data).first()

        #Check user info, login and redirect to index
        if user and user.check_password(form.password.data):

            login_user(user)
            return redirect(url_for('index'))
        
        #If login failed
        else:
            flash('Login Unsuccessful. Please check username and password', 'warning')

    return render_template('login.html', title='Login', form=form)

#Logout page and function, redierct to login. Requires auth to access
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

#Run program (run in debug mode for develeopment purposes, this is not production version yet)
if __name__ == '__main__':
    app.run(debug=True) 