from cs50 import SQL
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jsglue import JSGlue
from flask import Flask, jsonify, flash, redirect, render_template, request, session
from helpers import apology, login_required

# Configure application
app = Flask(__name__)
JSGlue(app)

if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///prospects.db")

@app.route("/")
def index():
    """Show portfolio of stocks"""

    # Gets user id
    user = session.get("user_id")

    print(user)

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST" or not user == None:

        # returns the template with passed in values
        return render_template("home.html")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("welcome.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was submitted
        elif not request.form.get("newPassword"):
            return apology("must match the password", 403)

        # Ensure both the new password and the confirmed new password match
        elif not request.form.get("password") == request.form.get("newPassword"):
            return apology("Confirmation must match password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 0:
            return apology("Username already exists", 403)

        # Inserts new user info into db
        user = db.execute("INSERT INTO users (username, password) VALUES (:user, :password)",
                            user=request.form.get("username"),
                            password=generate_password_hash(request.form.get("password")))

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")

@app.route("/prospects")
def prospects():
    """Show portfolio of stocks"""
    return render_template("prospects.html")

@app.route("/clients")
def clients():
    """Show portfolio of stocks"""
    return render_template("clients.html")

@app.route("/asyncInsert", methods=["GET", "POST"])
def asyncInsert():
    """Show portfolio of stocks"""
    if request.method == "GET":
        compName = request.args.get("companyName")
        phone = request.args.get("companyPhone")
        address = request.args.get("companyStreet")
        city = request.args.get("companyCity")
        state = request.args.get("companyState")
        zipCode = request.args.get("companyZip")
        country = request.args.get("companyCountry")
        status = request.args.get("companyStatus")

        contactName = request.args.get("contactName")
        contactEmail = request.args.get("contactEmail")
        contactPhone = request.args.get("contactPhone")

        client = 'f'

        companyData = [compName, phone, address, city, state, zipCode, country, status]
        contactData = [contactName, contactEmail, contactPhone]

        print(companyData)
        print(contactData)

        for item in companyData:
            if item == None:
                return jsonify(result="Must provide required information")
            str(item)

        if str(companyData[7].lower()) == "client":
            client = 't'

        userId = session.get("user_id")

        checkDup = db.execute("SELECT * FROM companies WHERE user_id = :user AND name = :name",
                                user = userId,
                                name = companyData[0])

        if len(checkDup) > 0:
            return jsonify(result="Company Already exists")

        insert = db.execute("INSERT INTO companies VALUES (NULL, :user, :name, :phone, :address, :city, :state, :zipCode, :country, :status)",
                                user=userId,
                                name=companyData[0],
                                phone=companyData[1],
                                address=companyData[2],
                                city=companyData[3],
                                state=companyData[4],
                                zipCode=companyData[5],
                                country=companyData[6],
                                status=client)

        containsContact = False

        if contactData[0] == "" and contactData[1] == "" and contactData[2] == "":
            return jsonify(result="Company successfully added!!!")

        else:
            comp = db.execute("SELECT comp_id FROM companies WHERE user_id = :user AND name = :name",
                                    user = userId,
                                    name = companyData[0])

            insert = db.execute("INSERT INTO contacts VALUES (NULL, :comp_id, :name, :email, :phone)",
                                    comp_id=comp[0]["comp_id"],
                                    name=contactData[0],
                                    email=contactData[1],
                                    phone=contactData[2])

        return jsonify(result="Company and contact successfully added!!!")
    else:
        return jsonify(result="FAILURE!!!")

@app.route("/insert")
def insert():
    """Show portfolio of stocks"""
    return render_template("insert.html")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    """Reset Password"""
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Ensure password was submitted
        elif not request.form.get("newPassword"):
            return apology("must provide password", 403)

        # Ensure password was submitted
        elif not request.form.get("reNewPassword"):
            return apology("must provide password", 403)

        # Gets user's id
        user_id = session.get("user_id")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE user_id = :user",
                          user=user_id)

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Ensure new password and confirmed new password match
        if not request.form.get("newPassword") == request.form.get("reNewPassword"):
            return apology("New passwords must match", 403)

        # Updates the user's password to the new password
        updatePass = db.execute("UPDATE users SET password = :newPass WHERE user_id = :user",
                                    newPass=generate_password_hash(request.form.get("newPassword")),
                                    user=user_id)

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("reset.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
