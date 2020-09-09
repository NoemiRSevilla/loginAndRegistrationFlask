from flask import Flask, render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL
import re

app = Flask(__name__)
app.secret_key = 'keep it secret, keep it safe'
bcrypt = Bcrypt(app)


@app.route("/")
def index():
    return render_template("index.html")


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')

@app.route("/", methods=["POST"])
def registration():
    is_valid = True
    session['first_name']=request.form['first_name']
    session['last_name']=request.form['last_name']
    session['email']=request.form['email']
    if not EMAIL_REGEX.match(request.form['email']):
        is_valid = False
        flash("<div class='ohno'>Please enter valid email</div>")
    if not NAME_REGEX.match(request.form['first_name']):
        is_valid = False
        flash("<div class='ohno'>First name must contain only letters</div>")
    if len(request.form['first_name']) < 2:
        is_valid = False
        flash("<div class='ohno'>First name must contain at least two letters</div>")
    if not NAME_REGEX.match(request.form['last_name']):
        is_valid = False
        flash("<div class='ohno'>Last name must contain only letters</div>")
    if len(request.form['last_name']) < 2:
        is_valid = False
        flash("<div class='ohno'>Last name must contain at least two letters</div>")
    
    if len(request.form['password']) < 8:
        is_valid = False
        flash("<div class='ohno'>Password must be between 8-15 characters</div>")
    if len(request.form['password']) > 15:
        is_valid = False
        flash("<div class='ohno'>Password must be between 8-15 characters</div>")
    if request.form['confirmpassword'] != request.form['password']:
        is_valid = False
        flash("<div class='ohno'>Passwords must match</div>")
    if is_valid == False:
        return redirect('/')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])  
        mysql = connectToMySQL("loginAndRegistration")
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(first_name)s,%(last_name)s, %(email)s, %(password_hash)s, NOW(), NOW());"
        data = {
            "first_name": request.form['first_name'],
            "last_name": request.form['last_name'],
            "email": request.form['email'],
            "password_hash": pw_hash,
        }
        new_user_id = mysql.query_db(query, data)
        session["first_name"]=request.form["first_name"]
        print(new_user_id)
        return redirect('/success')

@app.route("/success")
def success():
    if not checklogin():
        return redirect('/')
    return render_template ("success.html")

@app.route("/login", methods=['POST'])
def login():
    mysql = connectToMySQL("loginAndRegistration")
    query ="SELECT * FROM users WHERE email=%(email)s;"
    data ={
        "email": request.form["email"]
    }
    result=mysql.query_db(query, data)
    if len(result) > 0:
        # assuming we only have one user with this username, the user would be first in the list we get back
        # of course, we should have some logic to prevent duplicates of usernames when we create users
        # use bcrypt's check_password_hash method, passing the hash from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['password']):
            # if we get True after checking the password, we may put the user id in session
            session['first_name'] = result[0]['first_name']
            return redirect('/success')
        else:
            flash("<div class='ohno'>You could not be logged in</div>") 
    else:
        flash("<div class='ohno'>You could not be logged in</div>") 
        return redirect('/')
    

@app.route("/logout")
def logout():
    if "email" in session:
        session.pop("email")
    if "first_name" in session:
        session.pop("first_name")
    print(session)
    return redirect ("/")

def checklogin():
    print(session)
    if "first_name" not in session:
        flash("<div class='ohno'>Please log in</div>")
        return False
    return True

if __name__ == "__main__":
    app.run(debug=True)
