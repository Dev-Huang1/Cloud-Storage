from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import resend
import random
import os
import bcrypt
from peewee import *
from dotenv import load_dotenv

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# 从环境变量中设置Resend API Key
resend.api_key = os.getenv('RESEND_API_KEY')

# 设置数据库
db = SqliteDatabase('users.db')

class User(Model):
    email = CharField(unique=True)
    password = CharField()
    is_verified = BooleanField(default=False)
    storage_used = IntegerField(default=0)

    class Meta:
        database = db

db.connect()
db.create_tables([User])

def generate_verification_code():
    """生成6位数的随机验证码"""
    return str(random.randint(100000, 999999))

def send_verification_code(email_address, verification_code):
    """发送包含6位数验证码的邮件"""
    email_content = f"""
    <html>
    <head>
        <style>
            body {{font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333333; padding: 20px;}}
            .container {{max-width: 600px; margin: 0 auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);}}
            .header {{text-align: center; padding-bottom: 20px;}}
            .verification-code {{font-size: 24px; font-weight: bold; color: #0066ff; text-align: center;}}
            .footer {{margin-top: 20px; font-size: 12px; color: #666666; text-align: center;}}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Verification Code</h1>
            </div>
            <strong>Hi!</strong>
            <p>Thank you for using our service. Here is your verification code:</p>
            <p class="verification-code">{verification_code}</p>
            <div class="footer">
                <p>This email is sent automatically by the system, Please do not reply.</p>
                <p>If you did not request this code, please do not share it with anyone.</p>
            </div>
        </div>
    </body>
    </html>
    """

    params = {
        "from": "noreply@xyehr.cn",
        "to": [email_address],
        "subject": f"Your Tech-Art Platform account verification code is: {verification_code}",
        "html": email_content,
    }

    resend.Emails.send(params)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            user = User.create(email=email, password=hashed_password)
            verification_code = generate_verification_code()
            session['verification_code'] = verification_code
            session['user_id'] = user.id
            send_verification_code(email, verification_code)
            return redirect(url_for('verify'))
        except IntegrityError:
            return 'Email already registered'

    return render_template('register.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form['code']
        if code == session.get('verification_code'):
            user = User.get(User.id == session.get('user_id'))
            user.is_verified = True
            user.save()
            session.pop('verification_code', None)
            return redirect(url_for('login'))
        else:
            return 'Verification code incorrect'

    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        try:
            user = User.get(User.email == email)
            if user.is_verified and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            else:
                return 'Invalid credentials or email not verified'
        except User.DoesNotExist:
            return 'Invalid credentials or email not verified'

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.get(User.id == session['user_id'])
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join('users', str(user.id), file.filename)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            file.save(file_path)
            user.storage_used += os.path.getsize(file_path)
            user.save()

    files = os.listdir(os.path.join('users', str(user.id))) if os.path.exists(os.path.join('users', str(user.id))) else []
    return render_template('dashboard.html', files=files, storage_used=user.storage_used / 1024 / 1024)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/download/<filename>')
def download(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.get(User.id == session['user_id'])
    file_path = os.path.join('users', str(user.id), filename)
    if os.path.exists(file_path):
        return send_file(file_path)
    return 'File not found', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

