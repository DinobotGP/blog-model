from datetime import date
from functools import wraps
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship
import sqlalchemy.exc
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm


'''
Make sure the required packages are installed: 
Open the Terminal in PyCharm (bottom left). 

On Windows type:
python -m pip install -r requirements.txt

On MacOS type:
pip3 install -r requirements.txt

This will install the packages from the requirements.txt for this project.
'''

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

login_manager = LoginManager(app)
login_manager.init_app(app)


# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)

# CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    username = db.Column(db.String(100))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)


class Comment(db.Model, UserMixin):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.Text, nullable=False)


with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    error = None
    form = RegisterForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            email = form.email.data
            original_password = form.password.data
            hashed_password = generate_password_hash(original_password,
                                                     method='pbkdf2:sha256',
                                                     salt_length=8)

            if db.session.execute(db.select(User).where(User.username == username)).scalar():
                error = 'Username already in use!'
                print(error)
                return render_template('register.html', logged_in=current_user.is_authenticated, form=form, error=error)

            if db.session.execute(db.select(User).where(User.email == email)).scalar():
                error = 'Email already registered!'
                print(error)
                return render_template('register.html', logged_in=current_user.is_authenticated, form=form, error=error)

            new_user = User(username=username,
                            email=email,
                            password=hashed_password)

            try:
                db.session.add(new_user)
                db.session.commit()

                new_user = db.session.execute(db.select(User).where(User.username == username)).scalar()
                print(f"new user id = {new_user.id}")

                login_user(new_user)

                return redirect(url_for('get_all_posts'))
            except sqlalchemy.exc.IntegrityError:
                error = 'Something went wrong when registering the new user!'
                print(error)
                return render_template('register.html', logged_in=current_user.is_authenticated, form=form, error=error)

    return render_template("register.html", logged_in=current_user.is_authenticated, form=form, error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    error = None
    form = LoginForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            user = db.session.execute(db.select(User).where(User.username == username)).scalar()

            if user is None:
                error = 'Username not found!'
                print(error)
                return render_template('login.html', logged_in=current_user.is_authenticated, form=form, error=error)

            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                error = 'Invalid credentials'
                return render_template('login.html', logged_in=current_user.is_authenticated, form=form, error=error)

    return render_template("login.html", logged_in=current_user.is_authenticated, form=form, error=error)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", logged_in=current_user.is_authenticated, all_posts=posts)



@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    form = CommentForm()
    error = None
    requested_post = db.get_or_404(BlogPost, post_id)

    if request.method == "POST":
        if form.validate_on_submit():
            new_comment = Comment(
                text=form.body.data,
                comment_author=current_user,
                parent_post=requested_post
            )

            try:
                db.session.add(new_comment)
                db.session.commit()

                return redirect(url_for('show_post', post_id=post_id))
            except sqlalchemy.exc.IntegrityError:
                error = 'Something went wrong when registering the comment!'
                print(error)
                return redirect(url_for('show_post', post_id=post_id))

    return render_template("post.html", logged_in=current_user.is_authenticated, post=requested_post, form=form)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
