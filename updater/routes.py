from datetime import datetime
from werkzeug.utils import secure_filename
from flask import render_template, url_for, flash, redirect, request, send_from_directory
from updater import app, db, bcrypt
from updater.forms import RegistrationForm, LoginForm, UpdateAccountForm
from updater.models import User
from flask_login import login_user, current_user, logout_user, login_required
from pandas import DataFrame, read_csv
from dateutil.parser import parse
from PIL import Image
import secrets
import logging
import os
import zipfile
import pandas as pd

debug = eval(os.environ.get("DEBUG", "False"))
CORRECT_DATE = "%Y-%m-%d"
filename = ''
Frame = ''

logging.basicConfig(filemode = 'w')
formatter = logging.Formatter('%(message)s')

def try_date(text):
    try:
        formated = parse(str(text)).strftime(CORRECT_DATE)
        return formated
    except ValueError:
        pass

@app.errorhandler(413)
def too_large(e):
    return "File is too large", 413

def check_file_path(filename):
    for (root, dirs, files) in os.walk('.'):
        if filename in files:
            path_to_file = root
            return path_to_file
    if filename not in files:
        return app.config['UPLOAD_PATH']

def sort_Frame(filename):
    filename_save = check_file_path(filename) + '/' + filename
    df = pd.read_csv(filename_save, sep=',')
    Framer = pd.DataFrame(df.values, columns=['symbol', 'data', 'numer'])
    try: Framer["data"] = pd.to_datetime(Framer["data"], errors='raise')
    except:
        return 'program twierdzi że to nie data', 403
    Framer = Framer.sort_values(by="data")
    Framer.to_csv(filename_save, index=False)
    return Frame

def setup_logger(name, log_file, level=logging.INFO):
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.FileHandler(log_file)
        handler.setFormatter(formatter)
        logger.setLevel(level)
        logger.removeHandler(handler)
        logger.addHandler(handler)
    return logger

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

def find_symbol(symbol):
    for (root, dirs, files) in os.walk('./updater/DATA/DANE'):
        for z in range(0, len(files)):
            file_path_symbol_check = root + '/' + files[z]
            check_symbol = open(file_path_symbol_check, 'r')
            try_symbol = check_symbol.read().splitlines()
            readed_symbol = try_symbol[1].split(',')[0]
            if symbol == readed_symbol:
                return files[z]

@app.route('/upload', methods=['POST', 'GET'])
def index():
    upload = request.form.getlist('confirmed')
    refresh = request.form.getlist('refresh')
    submiter = request.form.getlist('submiter')
    if request.method == 'POST' and not upload and not refresh and not submiter:
        uploaded_file = request.files['file']
        global filename
        filename = secure_filename(uploaded_file.filename)
        file_ext = os.path.splitext(filename)[1]
        if file_ext not in app.config['UPLOAD_EXTENSIONS']:
            return "Nieprawidłowy format", 400
        uploaded_file.save(os.path.join(app.config['UPLOAD_PATH'], filename))
        upload = request.form.getlist('confirmed')
        filename_save = check_file_path(filename) + '/' + filename
        df = pd.read_csv(filename_save, header=None, sep=',', engine='python')
        global Frame
        Frame = pd.DataFrame(df.values, columns=['symbol', 'data', 'numer'])
        if filename != '':
            upload_frame(filename)
            os.remove(filename_save)
            with open('first_logfile.log', 'r') as framelog:
                return render_template('upload.html', tables=[Frame.to_html(classes="display", table_id="datatable")], titles=['SYMBOL', 'DATA', 'NUMER'],  text=framelog.read(), refresh=refresh, submiter=submiter)
    elif request.method == 'POST' and filename != '' and 'Usuń plik' in refresh and not upload:
        open("first_logfile.log", "w").close
        Frame = ''
        return render_template('upload.html', tables='', titles=['SYMBOL', 'DATA', 'NUMER'], refresh='', submiter='', text='' )
    elif request.method == 'POST' and filename != '' and (('Prześlij plik' in refresh and not upload) or ('Zatwierdź' in submiter and not upload)):
        with open('first_logfile.log', 'r') as framelog:
            return render_template('upload.html', tables=[Frame.to_html(classes="display", table_id="datatable")], titles=['SYMBOL', 'DATA', 'NUMER'],  text=framelog.read(), refresh=refresh, submiter=submiter)
    elif request.method == 'POST' and 'approved' in upload:
        open("first_logfile.log", "w").close
        upload_files(filename)
        filename = ''
        return render_template('upload.html', tables='', titles=['SYMBOL', 'DATA', 'NUMER'], refresh='', submiter='', text='' )
    elif request.method == 'POST' and 'denied' in upload:
        open("first_logfile.log", "w").close
        filename = ''
        return render_template('upload.html', tables='', titles=['SYMBOL', 'DATA', 'NUMER'], refresh='', submiter='', text='' )
    else:
        open("first_logfile.log", "w").close
        if filename != '':
            filename = ''
        return render_template('upload.html', tables='', titles=['SYMBOL', 'DATA', 'NUMER'], refresh='', submiter='', text='' )

def upload_frame(filename):
    i=0
    logger = setup_logger('first_logger', 'first_logfile.log')
    now = datetime.now()
    for x in range(0, len(Frame)):
        i += 1
        if x >= len(Frame):
            break
        else:
            symbol = Frame.iloc[x].symbol
            if try_date(Frame.iloc[x].data) is None or datetime.strptime(try_date(Frame.iloc[x].data), CORRECT_DATE) > now:
                logger.info(f'{filename}, {i}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Błędna data,')
                i += 1
                Frame.drop(x, inplace=True, axis=0)
                pass
            if try_date(Frame.iloc[x].data) is not None:
                symbol = Frame.iloc[x].symbol
                Frame_Checker = Frame.iloc[x].symbol+ ',' + try_date(Frame.iloc[x].data)
                filename_symbol = find_symbol(symbol)
                try:
                    file_path_symbol = check_file_path(filename_symbol) + '/' + filename_symbol
                except:
                    pass
            if filename_symbol is None:
                logger.info(f'{filename}, {i}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Nie ma pliku z wierszami o takim symbolu,')
            else:
                if os.path.exists(file_path_symbol):
                    check_data = open(file_path_symbol, "r")
                    check_data_frame = check_data.read()
                    if Frame_Checker in check_data_frame:
                        logger.info(f'{filename}, {i}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Ten wiersz już istnieje,')
                    else:
                        logger.info(f'{filename}, {i}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Ten wiersz nie widnieje w bazie,')

@app.route('/upload')
def upload_files(filename, charset='utf-8'):
    open("logfile_last_after.log", "w").close
    overwrite = request.form.getlist('overwrite')
    super_logger = setup_logger('second_logger', 'logfile_after.log')
    last_update_logger = setup_logger('third_logger', 'logfile_last_after.log')
    now = datetime.now()
    date_time = now.strftime("%d/%m/%Y %H:%M:%S")
    for x in range(0, len(Frame)):
        symbol = Frame.iloc[x].symbol
        filename_symbol = find_symbol(symbol)
        if try_date(Frame.iloc[x].data) is not None:
            Frame_Checker = Frame.iloc[x].symbol+ ',' + try_date(Frame.iloc[x].data)
            Frame_Data = Frame.iloc[x].symbol+ ',' + try_date(Frame.iloc[x].data)+ ',' + str(Frame.iloc[x].numer)
            if filename_symbol is not None:
                file_path_symbol = check_file_path(filename_symbol) + '/' + filename_symbol
                check_data = open(file_path_symbol, "r")
                check_data_frame = check_data.read()
                check_frame = pd.read_csv(file_path_symbol, index_col = False, sep=',')
                Framer = pd.DataFrame(check_frame.values, columns=['symbol', 'data', 'numer'])
                if Frame_Checker in check_data_frame:
                    if 'approved' in overwrite:
                        for f in range(0, len(Framer)):
                            frame_to_find = Framer.iloc[f].symbol+ ',' + try_date(Framer.iloc[f].data)
                            if frame_to_find == Frame_Checker:
                                Framer.loc[f, 'numer'] = Frame.loc[x, 'numer']
                                Framer.to_csv(file_path_symbol, index=False)
                        super_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Zaktualizowany,' + date_time +',')
                        last_update_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Zaktualizowany,' + date_time +',')
                    else:
                        super_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Pominięty,' + date_time+',')
                        last_update_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Pominięty,' + date_time+',')

                else:
                    with open(file_path_symbol, 'a') as new:
                        new.write(Frame_Data + '\n')
                        new.close()
                    super_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Nowy wiersz,' + date_time+',')
                    last_update_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Nowy wiersz,' + date_time+',')
            else:
                file_path_new_symbol = app.config['NEW_PATH_FILE'] + '/' + symbol + '.txt'
                with open(file_path_new_symbol, 'a') as new:
                    new.write('symbol,data,numer' + '\n')
                    new.write(Frame_Data + '\n')
                    new.close()
                super_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Plik został utworzony,' + date_time+',')
                last_update_logger.info(f'{filename}, {x}, {Frame.iloc[x].symbol},{Frame.iloc[x].data}, {Frame.iloc[x].numer},'+' Plik został utworzony,' + date_time+',')
    for (root, dirs, files) in os.walk('./updater/DATA/DANE'):
        for y in range(0, len(files)):
            sort_Frame(files[y])
    return 'yes'

@app.route('/logs', methods=['GET', 'POST'])
def print_logs():
    option = request.form.getlist('options')
    if not option:
        option = 'exist_logs'
    if 'remove_logs' in option:
        open('logfile_after.log', 'w').close()
    if 'last_update' in option:
        if 'all_logs' in option and 'error_logs' not in option and 'exist_logs' in option  and 'worked_logs' in option and 'created_logs' in option:
            option = ['last_update', 'exist_logs', 'worked_logs', 'created_logs']
        elif 'all_logs' in option and 'exist_logs' not in option and 'error_logs' in option  and 'worked_logs' in option and 'created_logs' in option:
            option = ['last_update','error_logs', 'worked_logs', 'created_logs']
        elif 'all_logs' in option and 'worked_logs' not in option and 'exist_logs' in option  and 'error_logs' in option and 'created_logs' in option:
            option = ['last_update','error_logs', 'exist_logs', 'created_logs']
        elif 'all_logs' in option and 'created_logs' not in option and 'exist_logs' in option  and 'worked_logs' in option and 'error_logs' in option:
            option = ['last_update','error_logs', 'exist_logs', 'worked_logs']
        elif 'all_logs' in option:
            option = ['last_update', 'exist_logs', 'error_logs', 'worked_logs', 'created_logs', 'all_logs']
        with open('logfile_last_after.log', 'r') as loglooks:
            return render_template('logs.html', text=loglooks.read(), option=option)
    if 'all_logs' in option and 'error_logs' not in option and 'exist_logs' in option  and 'worked_logs' in option and 'created_logs' in option:
        option = ['exist_logs', 'worked_logs', 'created_logs']
    elif 'all_logs' in option and 'exist_logs' not in option and 'error_logs' in option  and 'worked_logs' in option and 'created_logs' in option:
        option = ['error_logs', 'worked_logs', 'created_logs']
    elif 'all_logs' in option and 'worked_logs' not in option and 'exist_logs' in option  and 'error_logs' in option and 'created_logs' in option:
        option = ['error_logs', 'exist_logs', 'created_logs']
    elif 'all_logs' in option and 'created_logs' not in option and 'exist_logs' in option  and 'worked_logs' in option and 'error_logs' in option:
        option = ['error_logs', 'exist_logs', 'worked_logs']
    elif 'all_logs' in option:
        option = ['exist_logs', 'error_logs', 'worked_logs', 'created_logs', 'all_logs']
    with open('logfile_after.log', 'r') as loglooks:
	    return render_template('logs.html', text=loglooks.read(), option=option)

@app.route('/files')
def dirtree():
    path = app.config['UPLOAD_PATH'] + '/DANE'
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

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('account.html', title='Account',
                           image_file=image_file, form=form)

@app.route('/files/<filename>')
def download_file(filename):
    filename = secure_filename(filename)
    file_path = check_file_path(filename)[10:]
    return send_from_directory(file_path, filename)
