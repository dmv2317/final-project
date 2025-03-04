import os
from flask import Flask, abort, render_template, redirect, send_file, send_from_directory, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask import Flask, jsonify, request
from werkzeug.utils import secure_filename



app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "supersecretkey"
app.config['UPLOAD_FOLDER'] = 'static/uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Extensions
csrf = CSRFProtect(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
CORS(app)

# Flask-Login Setup
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User Model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

# Book Model
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)  # ✅ Add file path column
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Book Upload Form
class BookUploadForm(FlaskForm):
    book_name = StringField("Book Name", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    category = StringField("Category", validators=[DataRequired()])
    description = TextAreaField("Description")
    book = FileField("Book", validators=[DataRequired()])
    submit = SubmitField("Upload")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Username already exists!", "danger")
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password_hash=hashed_password)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash("Account created! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/about')
@login_required
def about():
    return render_template('about.html', username=current_user.username)

@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html', username=current_user.username)

@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html', username=current_user.username)

@app.route('/my-library', methods=['GET', 'POST'])
@login_required
def my_library():
    form = BookUploadForm()
    books = Book.query.filter_by(uploaded_by=current_user.id).all()

    if form.validate_on_submit():
        book_file = form.book.data
        filename = secure_filename(book_file.filename)  # Secure the filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

        # Save the file to the uploads folder
        book_file.save(file_path)

        # Save book details to the database
        new_book = Book(
            title=form.book_name.data,
            author=form.author.data,
            category=form.category.data,
            description=form.description.data,
            filename=filename,
            file_path=file_path,  # ✅ Store the file path in the database
            uploaded_by=current_user.id
        )
        db.session.add(new_book)
        db.session.commit()
        flash("Book uploaded successfully!", "success")
        print(Book.query.filter_by(uploaded_by=current_user.id).all())


        return redirect(url_for('my_library'))

    return render_template('my-library.html', username=current_user.username, uploaded_books=books, form=form)

@app.route('/fantasy')
@login_required
def fantasy():
    books = Book.query.filter_by(category="Fantasy").all()
    return render_template('fantasy.html', username=current_user.username, books=books)


@app.route('/science')
@login_required
def science():
    return render_template('science.html', username=current_user.username)

@app.route('/biographies')
@login_required
def biographies():
    return render_template('biographies.html', username=current_user.username)

@app.route('/technology')
@login_required
def technology():
    return render_template('technology.html', username=current_user.username)

@app.route('/eduvault')
@login_required
def eduvault():
    return render_template('eduvault.html', username=current_user.username)

@app.route('/comics')
@login_required
def comics():
    return render_template('comics.html', username=current_user.username)

@app.route('/fiction')
@login_required
def fiction():
    return render_template('fiction.html', username=current_user.username)

@app.route('/History')
@login_required
def history():
    return render_template('history.html', username=current_user.username)

@app.route('/mystery')
@login_required
def mystery():
    return render_template('mystery.html', username=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "success")
    return redirect(url_for('login'))

@app.route('/science-books', methods=['GET'])
def get_science_books():
    
    science_books = Book.query.filter_by(category="Science").all()

    
    books_list = [
        {
            "title": book.title,
            "author": book.author,
            "image": book.image_url,
            "file": book.file_path
        }
        for book in science_books
    ]

    return jsonify(books_list)



from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, FileField, SubmitField
from wtforms.validators import DataRequired

from wtforms import SelectField

class BookUploadForm(FlaskForm):
    book_name = StringField("Book Name", validators=[DataRequired()])
    author = StringField("Author", validators=[DataRequired()])
    category = SelectField("Category", choices=[
        ('Biographies', 'Biographies'),
        ('Comics', 'Comics'),
        ('Fantasy', 'Fantasy'),
        ('Science', 'Science'),
        ('Technology', 'Technology'),
        ('Mystery', 'Mystery'),
        ('Edu Vault', 'Edu Vault')
    ], validators=[DataRequired()])
    description = TextAreaField("Description")
    book = FileField("Book", validators=[DataRequired()])
    submit = SubmitField("Upload")

@app.route('/category/<category_name>')
def get_books(category_name):
    books = Book.query.filter_by(category=category_name).all()

    if not books:
        return jsonify([])  # Return an empty list if no books are found

    books_data = [
        {
            "id": book.id,
            "title": book.title,
            "author": book.author,
            "filename": book.filename  # Ensure this is the correct field
        }
        for book in books
    ]
    return jsonify(books_data)

UPLOAD_FOLDER = "static/uploads"  # Ensure this folder exists

@app.route('/download/<int:book_id>')
def download_book(book_id):
    book = Book.query.get(book_id)

    if not book:
        return abort(404, description="Book not found")

    file_path = os.path.join(UPLOAD_FOLDER, book.filename)

    if not os.path.exists(file_path):
        return abort(404, description="File not found")

    return send_from_directory(UPLOAD_FOLDER, book.filename, as_attachment=True)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)