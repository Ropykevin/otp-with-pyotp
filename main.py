from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_mail import Mail, Message
from flask_login import LoginManager, login_required, login_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import ResetPasswordForm, LoginForm, RegisterForm, OTPForm, PasswordForm
import pyotp
from flask_wtf.csrf import CSRFProtect
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

app = Flask(__name__)

# Configurations
app.config['SECRET_KEY'] = 'sjdjdfkkkfk'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'ropykevin@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'ropykevin@gmail.com'
app.config['MAIL_PASSWORD'] = 'tmyo uibe fiod wzlf'

mail = Mail(app)
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# SQLAlchemy setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///authh.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    otp_secret = db.Column(db.String(16), nullable=True)
    otp_expiry = db.Column(db.DateTime)
    email_verified = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("home.html")


@app.route('/page')
@login_required
def page():
    return render_template("mypage.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if request.method == 'POST':
        email = form.email.data
        user = db.session.query(User).filter(User.email == email).first()
        if not user:
            flash("User does not exist", "error")
        elif not user.email_verified:
            flash(
                "Email not verified. Please verify your email before logging in.", "error")
        else:
            check_password = check_password_hash(
                user.password, form.password.data)
            if not check_password:
                flash("Wrong password", "error")
            else:
                login_user(user)
                flash('Login successful', 'success')
                return redirect(url_for('page'))
    return render_template("login.html", form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            if user:
                flash("User already exists. Please login", 'error')
            else:
                hashed_password = generate_password_hash(form.password.data)
                otp_secret = pyotp.random_base32()
                otp_expiry = datetime.utcnow() + timedelta(minutes=1)
                new_user = User(name=form.name.data, email=form.email.data,
                                password=hashed_password, otp_secret=otp_secret, otp_expiry=otp_expiry)
                db.session.add(new_user)
                db.session.commit()

                # Generate OTP and send it via email
                totp = pyotp.TOTP(otp_secret).now()
                # print(totp)
                # otp = totp.now()
                message = Message(
                    f"Verify your email address", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[form.email.data])
                message.body = f'Your OTP code for email verification is {
                    totp}'
                try:
                    mail.send(message)
                    
                    session['verify_user_id'] = new_user.id
                    return redirect(url_for('verify_email', otp_expiry_time=otp_expiry.isoformat()))
                except Exception as e:
                    flash(f"Error sending mail: {e}", "error")
    return render_template("register.html", form=form)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    form = OTPForm()
    otp_expiry_time = None
    user = None

    if session.get('verify_user_id'):
        user = User.query.get(session['verify_user_id'])
        if user and user.otp_expiry:
            otp_expiry_time = user.otp_expiry.isoformat()  # Convert to ISO format string

    if request.method == 'POST':
        if form.validate_on_submit():
            otp = form.otp.data
            if user:
                if datetime.utcnow() > user.otp_expiry:
                    flash("OTP expired. Please request a new one.", "error")

                totp = pyotp.TOTP(user.otp_secret)
                if totp.verify(otp):
                    user.email_verified = True
                    db.session.commit()
                    session.pop('verify_user_id', None)
                    flash("Email verified successfully! You can now log in.", "success")
                    return redirect(url_for('login'))
                else:
                    flash(f"Invalid OTP: {otp}. Expected OTP was {totp.now()}.", "error")
            else:
                flash("User not found", "error")

    return render_template("verify_email.html", form=form, otp_expiry_time=otp_expiry_time)


@app.route('/otpverification', methods=['GET', 'POST'])
def verify_otp():
    form = OTPForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            otp = form.otp.data
            user_id = session.get('reset_user_id')
            user = User.query.get(user_id)
            if user:
                totp = pyotp.TOTP(user.otp_secret)
                if totp.verify(otp):
                    flash("OTP verified. You can now reset your password.", "success")
                    return redirect(url_for('password_reset'))
                else:
                    flash(f"Invalid or expired OTP input a valid otp", "error")
            else:
                flash("User not found", "error")
    return render_template("otp.html", form=form)



@app.route('/resend_otp', methods=['POST'])
def resend_otp():
    user_id = session.get('verify_user_id')
    user = User.query.get(user_id)
    if user:
        totp = pyotp.TOTP(user.otp_secret)
        otp = totp.now()
        message = Message(
            f"Verify your email address", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user.email])
        message.body = f'Your new OTP code for email verification is {otp}'
        try:
            mail.send(message)
            flash("New OTP sent successfully. Please check your email.", "success")
        except Exception as e:
            flash(f"Error sending mail: {e}", "error")
    else:
        flash("User not found", "error")
    return redirect(url_for('verify_email'))


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    form = ResetPasswordForm()
    if request.method == 'POST':
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            if user.otp_secret:
                totp = pyotp.TOTP(user.otp_secret)
                print(totp)
                otp = totp.now()
                print(otp)
                message = Message(
                    f"OTP for password reset", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email])
                message.body = f'Your OTP code for password reset is {otp}'
                try:
                    mail.send(message)
                    flash("OTP sent successfully", "success")
                    session['reset_user_id'] = user.id
                    return redirect(url_for('verify_otp'))
                except Exception as e:
                    flash(f"Error sending mail: {e}", "error")
            else:
                flash("OTP secret not set for this user", "error")
        else:
            flash("User does not exist", "error")
    return render_template('reset.html', form=form)




@app.route('/passwordreset', methods=['GET', 'POST'])
def password_reset():
    form = PasswordForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            password = form.password.data
            confirm_password = form.confirm_password.data
            if password == confirm_password:
                hashed_password = generate_password_hash(password)
                user_id = session.get('reset_user_id')
                user = User.query.get(user_id)
                if user:
                    user.password = hashed_password
                    db.session.commit()
                    session.pop('reset_user_id', None)
                    flash("Password changed successfully. Please log in.", 'success')
                    return redirect(url_for('login'))
                else:
                    flash("User not found", "error")
            else:
                flash("Passwords don't match", "error")
    return render_template("resetpassword.html", form=form)


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
    app.run(debug=True)
