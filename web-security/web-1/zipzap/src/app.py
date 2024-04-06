import flask
from flask import request, render_template, redirect, flash, url_for
from flask import send_file, abort, make_response
import secrets
import os
import subprocess
import hashlib
import hmac
import re

app = flask.Flask(__name__)
app.config['USERPATH'] = os.environ.get('USERPATH', '/tmp')
app.config['APP_SECRET'] = os.environ.get('SECRET', secrets.token_hex(10))
app.secret_key = app.config['APP_SECRET']
app.config['MAX_UNCOMPRESSED_SIZE'] = os.environ.get(
    'MAX_UNCOMPRESSED_SIZE', 4096)


class FileTooBigException(Exception):
    pass


@app.route('/', methods=['GET', 'POST'])
def index():
    #
    # Sign in a user. This function create a sandbox directory, in which there will be
    # all files uploaded by the user
    #
    if request.method == 'GET':
        return render_template('index.html')

    try:
        username = request.form['username']
        password = request.form['password']
    except KeyError:
        flash('you need to choose an username/password')
        return render_template('index.html')

    # a stupid way to generate random uuid from an username and a password.
    pwd = hashlib.md5(password.encode()).digest()
    tmp_dir = hmac.new(app.config['APP_SECRET'].encode(),
                       pwd + username.encode(),  hashlib.sha1).hexdigest()

    # next we create the tmp dir
    path = os.path.join(app.config['USERPATH'], tmp_dir)

    try:
        os.mkdir(path)
    except FileExistsError:
        pass

    return redirect(url_for('list_files', uid=tmp_dir))


@app.route('/<uid>')
def list_files(uid):
    #
    # List every file uploaded by the user
    #
    uid = os.path.basename(uid)
    path = os.path.join(app.config['USERPATH'], uid)
    try:
        files = [file for file in os.listdir(path)]
    except (FileNotFoundError, NotADirectoryError):
        return redirect(url_for('index'))

    return render_template('list.html', files=files, uid=uid)


@app.route('/<uid>', methods=['POST'])
def upload(uid):
    #
    # Upload a zip file and then extract it
    #
    uid = os.path.basename(uid)
    path = os.path.join(app.config['USERPATH'], uid)

    # is the user logged in?
    if not os.path.exists(path):
        abort(401)

    # some sanity check
    try:
        f = request.files['zip']
        if f.filename == '':
            raise ValueError
    except ValueError:
        flash('You must provide a file')
        return redirect(url_for('list_files', uid=uid))

    # Save the file
    zip_filename = secrets.token_urlsafe(8) + '.zip'
    zip_path = os.path.join(path, zip_filename)
    try:
        f.save(zip_path)
    except IsADirectoryError:
        abort(400)

    # Calc length: we don't want any files larger than 4kb
    try:
        # unzip -Zt return a string similar to: 4 files, 49 bytes uncompressed, 44 bytes compressed:  10.2%
        # a quick and dirty way to parse this is to split the string, with ' ' as delimiter,
        # and then parse the 3rd. This is also a _very_ dirty way to check if the file is a valid
        # zip file.
        command = 'unzip -Zt ' + zip_path
        out = subprocess.run(command.split(' '),
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=5)

        size = out.stdout.decode()
        size = size.split(' ')[2]
        size = int(size)

        if size > app.config['MAX_UNCOMPRESSED_SIZE']:
            raise FileTooBigException

        # Now we can unzip everything
        command = 'unzip -j -o {}'.format(zip_path)
        with open(os.devnull, 'wb') as devnull:
            # exec unzip in the user directory
            subprocess.run(command.split(' '), stdout=devnull,
                           stderr=devnull, shell=False, cwd=path)
    except subprocess.TimeoutExpired:
        abort(500)
    except (ValueError, IndexError):
        abort(500)
    except FileTooBigException:
        flash('Zip file too big')
        return redirect(url_for('list_files', uid=uid))
    finally:
        os.remove(os.path.join(path, zip_path))

    return redirect(url_for('list_files', uid=uid))


@app.route('/<uid>/zip')
def zip(uid):
    #
    # Create a zip file from user's uploaded files
    #
    path = os.path.join(app.config['USERPATH'], uid)

    try:
        # file list. This simple check should prevent a zip recursion. Also yea, users
        # can't upload any zip file
        files = [filename for filename in os.listdir(
            path) if not filename.endswith('.zip')]

        #
        # Now some security checks
        #

        def get_fullpath(filename): return os.path.join(
            path, filename)

        # Sort the file list.
        files = sorted(files)

        # Sanitize all filenames.
        files = map(lambda x: os.path.basename(x), files)

        # check that we aren't zipping directories
        files = filter(lambda x: not os.path.isdir(get_fullpath(x)), files)

        # Limit the len of the files we are zipping. Yeah, there can't be
        # be any files greater that app.config['MAX_UNCOMPRESSED_SIZE'], but you never know
        files = filter(lambda x: os.stat(get_fullpath(x)).st_size <
                       app.config['MAX_UNCOMPRESSED_SIZE'], files)

        # We don't want to compress more that 20 files
        files = list(files)
        if len(files) > 20:
            files = files[:20]  # out of one? idk and I don't care
    except (FileNotFoundError, NotADirectoryError):
        return redirect(url_for('index'))

    # create a random zip name
    new_zip_name = secrets.token_urlsafe(8) + '.zip'
    new_zip_path = os.path.join(path, new_zip_name)

    # create the command
    command = ['zip', new_zip_path]
    command += files

    with open(os.devnull, 'wb') as devnull:
        # exec unzip in the user directory
        subprocess.run(command, stdout=devnull, stderr=devnull,
                       shell=False, cwd=path, timeout=5)
    try:
        resp = make_response(
            send_file(new_zip_path, as_attachment=True, attachment_filename=new_zip_name))
        resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        return resp
    except:
        abort(500)
    finally:
        if os.path.exists(new_zip_path):
            os.remove(os.path.join(path, new_zip_path))


@app.route('/<uid>/remove/<f>')
def remove(uid, f):
    #
    # Remove a file
    #
    path = os.path.join(app.config['USERPATH'], uid)
    f = os.path.basename(f)
    to_remove = os.path.join(path, f)

    try:
        os.remove(to_remove)
    except:
        pass

    return redirect(url_for('list_files', uid=uid))


@app.route('/<uid>/download/<f>')
def show(uid, f):
    #
    # Download a file
    #
    path = os.path.join(app.config['USERPATH'], uid)
    path = os.path.join(path, f)

    try:
        return send_file(path, mimetype='text/plain')
    except:
        abort(404)


if __name__ == '__main__':
    app.run(debug=True)
