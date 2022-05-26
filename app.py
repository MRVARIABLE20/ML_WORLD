from io import BytesIO
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField , SelectField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user

app = Flask(__name__, template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['UPLOADS_FOLDER'] = './uploads'
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))


class Upload(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(50))
    filetype = db.Column(db.String(100))
    description = db.Column(db.String(200))
    data = db.Column(db.LargeBinary)

    def __init__(self,filename,filetype,data,description):
          self.filename =  filename
          self.filetype = filetype
          self.description = description
          self.data = data

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('USERNAME', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('PASSWARD', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('REMEMBER ME')

class RegisterForm(FlaskForm):
    email = StringField('EMAIL', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('USERNAME', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('PASSWARD', validators=[InputRequired(), Length(min=8, max=80)])

class DescriptionForm(FlaskForm):
    filetype = SelectField('PROJECT TYPE',choices=[('SUPERVISED ML','SUPERVISED ML'),('UNSUPERVISED ML','UNSUPERVISED ML'),('REINFORCEMENT ML','REINFORCEMENT ML'),('DATA ANALYTICS','DATA ANALYTICS'),('BIG DATA','BIG DATA')],validators=[InputRequired()])
    description = StringField('DESCRIPTION')



@app.route('/')
@app.route('/home')
def home_page():
    return render_template('home.html')


@app.route('/submit', methods=['GET', 'POST'])
@login_required
def index():
    form = DescriptionForm()
    if request.method == 'POST':
        

           file = request.files['file']
           upload = Upload(filename=file.filename, filetype= form.filetype.data, description=form.description.data,data=file.read())
           db.session.add(upload)
           db.session.commit()
           return redirect(url_for('market_page'))
           
    return render_template('index.html', form=form)



@app.route('/download/<upload_id>')
def download(upload_id):
    upload = Upload.query.filter_by(id=upload_id).first()
    return send_file(BytesIO(upload.data), attachment_filename=upload.filename, as_attachment=True)


@app.route('/delete/<delete_id>')
@login_required
def delete(delete_id):

        delete1 = Upload.query.filter_by(id=delete_id).first()
        db.session.delete(delete1)
        db.session.commit()
        return redirect(url_for('market_page'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('market_page'))
            return '<h1>INVALID USERNAME OR PASSWARD</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return '<h1>NEW USER HAS BEEN CREATED</h1>'
    return render_template('signup.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home_page'))

@app.route('/market')
def market_page():
    upload = Upload.query.all()
    return render_template('market.html', items=upload)




if __name__ == '__main__':
    app.run(debug=False,host='0.0.0.0')