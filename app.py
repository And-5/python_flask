from flask import Flask, request, session, jsonify
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
app.secret_key = "testing"


def MongoDB():
    client = MongoClient("mongodb://localhost:27017")
    db = client.get_database('total_records')
    user = db.users
    return user


records = MongoDB()


@app.route("/registration", methods=["POST", "GET"])
def registration():
    if "email" in session:
        message = 'You are login'
        return jsonify(message=message)
    if request.method == "POST":
        user = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return jsonify(message=message)
        if email_found:
            message = 'This email already exists in database'
            return jsonify(message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return jsonify(message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            return jsonify(name=user, email=email)
    message = 'Form registration'
    return jsonify(message=message)


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Login form'
    if "email" in session:
        return jsonify(email=session["email"])

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']

            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                message = 'You are login'
                return jsonify(message=message)
            else:
                if "email" in session:
                    message = 'You are login'
                    return jsonify(message=message)
                message = 'Wrong password'
                return jsonify(message=message)
        else:
            message = 'Email not found'
            return jsonify(message=message)
    return jsonify(message=message)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
        message = 'Logout'
        return jsonify(message=message)
    else:
        message = 'Email not found'
        return jsonify(message=message)

