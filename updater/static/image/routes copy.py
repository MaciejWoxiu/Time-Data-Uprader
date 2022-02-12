import os
import zipfile
import filecmp  
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import render_template, url_for, flash, redirect, request, send_from_directory
from updater import app, db, bcrypt
from updater.forms import RegistrationForm, LoginForm
from updater.models import User
from flask_login import login_user, current_user, logout_user, login_required

UPLOAD_FOLDER = os.path.dirname(os.path.realpath(__file__))
MIESIACE = ['Styczen', 'Luty', 'Marzec', 'Kwiecien', 'Maj', 'Czerwiec', 'Lipiec', 'Sierpien', 'Wrzesien', 'Pazdziernik', 'Listopad', 'Grudzien']
DNI = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]


#class Post(db.Model):
#    id = db.Column(db.Integer, primary_key=True)
#    title = db.Column(db.String(100), nullable=False)
#    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
#    content = db.Column(db.Text, nullable=False)
#    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

#    def __repr__(self):
#        return f"Post('{self.title}', '{self.date_posted}')"

@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413

@app.route('/upload')
def index():
    files = os.listdir(app.config['UPLOAD_PATH'])
    return render_template('upload.html', files=files)

def logs(log_name, log_error, log_info, actual_time):
    logs = open("updater/DATA/logs/log.txt", "a")
    logslooks = open("updater/DATA/logs/loglooks.txt", "a")
    logbuffer = [log_name, ' | ', log_info, ' | ', log_error, ' | ', actual_time, '\n' ]
    logbuffer_looks = [log_name, ' | ', log_info, ' | ', log_error, ' | ', actual_time, ' | ' ]
    logs.writelines(logbuffer)
    logslooks.writelines(logbuffer_looks)
    logs.close()
    logslooks.close()

def unzipper(uploaded_files, filenames):
    uploaded_files.save(os.path.join(app.config['UPLOAD_PATH'], filenames))
    zip_ref = zipfile.ZipFile(os.path.join(app.config['UPLOAD_PATH'], filenames), 'r')
    zip_ref.extractall(app.config['UPLOAD_PATH'])
    zip_ref.close()
    print("ZIP file is expanded")
    return 'pliki zostaly rozpakowane w poczekalni', 110

def make_tree(path):
    tree = dict(name=os.path.basename(path), children=[])
    try: lst = os.listdir(path)
    except OSError:
        pass #ignore errors
    else:
        for name in lst:
            fn = os.path.join(path, name)
            if os.path.isdir(fn):
                tree['children'].append(make_tree(fn))
            else:
                tree['children'].append(dict(name=name))
    return tree


#def create_folder():
#    new_folder = os.path.join(app.config['UPLOAD_PATH'], symbol)
#    os.mkdir(new_folder)
#    return ('created new folder') 
  
@app.route('/upload', methods=['POST'])
def upload_files():
    uploaded_file = request.files['file']
    filename = secure_filename(uploaded_file.filename)
    if '.txt' in filename and 'sym' in filename:
        symbol = filename.split('.')[0]
        days = filename.split('.')[1]
        months = filename.split('.')[2]
        years = filename.split('.')[3]
        numbers = filename.split('.')[4]
        date_format = days + '.' + months + '.' + years
    else:
        return 'Wrong file format, look below', 409
    path_exist = app.config['UPLOAD_PATH'] + '/' + symbol
    year_folder = path_exist + '/' + years
    file_exist = year_folder + '/' + filename
    file_name = os.path.splitext(filename)[0]
    file_ext = os.path.splitext(filename)[1]
    file_new_name = file_name + '1' + file_ext
    file_exist_new = year_folder + '/' + file_new_name
    now = datetime.now() # current date and time
    date_time = now.strftime("%d/%m/%Y, %H:%M:%S")

    if os.path.exists(file_exist):
        info = 'File exists in database'
        error = 'File has been MODIFIED'
    else:
        info = 'File does not exists'
        error = 'File has been UPLOADED'
    if filename != '':
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            return "Invalid file format", 400
#        print(path_exist)
#        print(os.path.exists(path_exist))
        if '.zip' in filename:
            unzipper(uploaded_file, filename)
        else:   
            if '.txt' in filename: 
                if 'sym' in filename:
                    if int(years) > 1990 and int(years) < 2022 :
                        if int(months) <= 12 and int(months) > 0:
                            if int(days) < DNI[int(months)-1] and int(days) > 0:  
                                    if not os.path.exists(path_exist):
                                        new_folder_symbol = os.path.join(app.config['UPLOAD_PATH'], symbol)
                                        os.mkdir(new_folder_symbol)
                                    if not os.path.exists(year_folder):
                                        new_folder_year = os.path.join(app.config['UPLOAD_PATH'], symbol, years)
                                        os.mkdir(new_folder_year)
                                    if os.path.exists(file_exist):
                                        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], symbol, years, file_new_name))
                                        if filecmp.cmp(file_exist, file_exist_new):
                                            #print(filecmp.cmp(file_exist, file_exist_new))
                                            #print(symbol, days, MIESIACE[int(months)-1], years, DNI[int(months)-1], 'Taki plik juz istnieje')
                                            os.remove(file_exist_new)
                                        else:
                                            #print(file_exist)
                                            #print(file_exist_new)
                                            #print(filecmp.cmp(file_exist, file_exist, shallow = False))
                                            updated_data = open(file_exist, "a")
                                            data_updater = open(file_exist_new, "r")
                                            update_buffer = data_updater.read()
                                            #updated_data.truncate(0)
                                            updated_data.writelines('\n\nUpdate ' + date_time + '\n')
                                            updated_data.writelines(update_buffer)
                                            updated_data.close()
                                            data_updater.close()
                                            #print(symbol, days, MIESIACE[int(months)-1], years, DNI[int(months)-1], 'ma inne dane ;o')
                                            os.remove(file_exist_new)
                                        logs(file_name, error, info, date_time)
                                    else:        
                                        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], symbol, years, filename))
                                        #print(symbol, days, MIESIACE[int(months)-1], years, DNI[int(months)-1], not os.path.exists(symbol in app.config['UPLOAD_PATH']))
                                        logs(file_name, error, info, date_time)
                                        return 'ITS GOOOOOOD'
                            else:
                                error = 'Blad: Nieprawidlowy dzien'
                                #print(symbol, days, MIESIACE[int(months)-1], years, DNI[int(months)-1], 'bad')
                                logs(file_name, error, info, date_time)
                                return 'Blad: Nieprawidlowy dzien', 411
                        else:
                            error = 'Blad: Nieprawidlowy miesiac'
                            logs(file_name, error, info, date_time)
                            return 'Blad: Nieprawidlowy miesiac', 412
                    else:
                        error = 'Blad: Pliki nie moga byc starsze niz z 1991 roku...'
                        logs(file_name, error, info, date_time)
                        return 'Blad: Pliki nie moga byc starsze niz z 1991 roku...', 413
                else:
                    error = 'Blad: Nieprawidlowy format, sprobuj symx. data(xx.xx.xxxx). number'
                    logs(file_name, error, info, date_time)                        
                    return 'Blad: Nieprawidlowy format, sprobuj symx. data(xx.xx.xxxx). number', 410       
    return '', 204

@app.route('/logs')
def print_logs():   
	with open('updater/DATA/logs/loglooks.txt', 'r') as loglooks:
	    return render_template('logs.html', text=loglooks.read())
 
@app.route('/files')
def dirtree():
    path = app.config['UPLOAD_PATH']
#os.path.expanduser(u'~')
    return render_template('dirtree.html', tree=make_tree(path))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Twoje konto zostało utworzone! Możesz się teraz zalogować', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Logowanie nie powiodło się. Sprawdź e-mail i hasło', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')


@app.route('/uploads/<filename>')
def upload(filename):
    return send_from_directory(app.config['UPLOAD_PATH'], filename)

