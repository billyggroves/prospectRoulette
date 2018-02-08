import os
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash
from flask_jsglue import JSGlue
from flask import Flask, jsonify, flash, redirect, render_template, request, session
from company import Company
from contact import Contact
from message import Message
from helpers import apology, login_required, hasNumbers, hasCaps, hasLower

import random
from datetime import datetime, timedelta

# Configure application
app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
db = SQLAlchemy(app)
class Users(db.Model):

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), unique=False, nullable=False)

    def __init__(self, username, password):
        self.username = username
        self.password = password

class Companies(db.Model):

    comp_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, unique=False, nullable=False)
    name = db.Column(db.String(200), unique=False, nullable=False)
    phone = db.Column(db.String(80), unique=False, nullable=False)
    address = db.Column(db.String(200), unique=False, nullable=False)
    city = db.Column(db.String(200), unique=False, nullable=False)
    state = db.Column(db.String(200), unique=False, nullable=False)
    zip = db.Column(db.String(80), unique=False, nullable=False)
    country = db.Column(db.String(200), unique=False, nullable=False)
    isClient = db.Column(db.String(10), unique=False, nullable=False)
    time = db.Column(db.DateTime, unique=False, nullable=False)

    def __init__(self, comp_id, user_id, name,
                phone, address, city, state,
                zip, country, isClient, time):
        self.comp_id = comp_id
        self.user_id = user_id
        self.name = name
        self.phone = phone
        self.address = address
        self.city = city
        self.state = state
        self.zip = zip
        self.country = country
        self.isClient = isClient
        self.time = time


class Contacts(db.Model):

    contact_id = db.Column(db.Integer, primary_key=True)
    comp_id = db.Column(db.Integer, unique=False, nullable=False)
    name = db.Column(db.String(200), unique=False, nullable=False)
    email = db.Column(db.String(80), unique=False, nullable=True)
    phone = db.Column(db.String(80), unique=False, nullable=True)
    title = db.Column(db.String(80), unique=False, nullable=True)

    def __init__(self, contact_id, comp_id, name, email, phone, title):
        self.contact_id = contact_id
        self.comp_id = comp_id
        self.name = name
        self.email = email
        self.phone = phone
        self.title = title


class Messages(db.Model):

    message_id = db.Column(db.Integer, primary_key=True)
    comp_id = db.Column(db.Integer, unique=False, nullable=False)
    message = db.Column(db.Text, unique=False, nullable=False)
    time = db.Column(db.DateTime, unique=False, nullable=False)

    def __init__(self, message_id, comp_id, message, email):
        self.message_id = message_id
        self.comp_id = comp_id
        self.message = message
        self.time = time

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

@app.route("/")
def index():
    """
        Shows either the homepage or the welcome page

        If the user is logged in the homepage is propagated
        with up to ten prospects for the user to call.

    """

    # Gets user id
    user = session.get("user_id")

    # User reached route via POST (as by submitting a form via POST) and user is logged in
    if request.method == "POST" or not user == None:

        # Var's are initiated
        current = datetime.now()
        print(current)
        companies = []
        prospects = []
        contacts = []
        messages = []
        count = 10
        numId = 0

        # Pulls user's list of prospects
        proComp = Companies.query.filter_by(user_id=user, isClient='f')
        # proComp = db.execute("SELECT * FROM companies WHERE user_id = :user AND isclient = :client",
        #                         user=user,
        #                         client='f')

        if proComp != None:
            for comp in proComp:
                companies.append(Company(comp.comp_id, comp.name, comp.address, comp.phone, None, None))

            # If user has 10 or less prospects, then the list pulls all ten to call for the user
            if len(companies) <= 10:

                # Loops through the list of prospects
                for comp in proComp:

                    # Creates company object info for each prospect
                    numId = numId + 1
                    newid = numId
                    name = comp.name
                    address = comp.city + ", " + comp.state
                    phone = comp.phone
                    message = Messages.query.filter_by(comp_id=comp.comp_id).order_by(time.desc())
                    # messages = db.execute("SELECT message FROM messages WHERE comp_id = :comp ORDER BY time DESC",
                    #                         comp=comp["comp_id"])
                    conts = Contacts.query.filter_by(comp_id=comp.comp_id)
                    # conts = db.execute("SELECT * FROM contacts WHERE comp_id = :comp",
                    #                         comp=comp["comp_id"])

                    # Loops through contacts adding contact objects to add to list of contacts for Company Object
                    for cont in conts:
                        contacts.append(Contact(newid, cont.name, cont.title, cont.phone, cont.email))

                    for mess in message:
                        messages.append(Message(mess.comp_id, mess.message_id, mess.message, mess.time))

                    # Adds the Company Object to the list of prospects
                    prospects.append(Company(newid, name, address, phone, messages[0].message, contacts))

            # If the user has more than 10 prospects, then the ten prospects are randomly chosen
            else:

                # Loops through process the number of times count is equal to
                for i in range(count):

                    # Generates random int between 0 and the number of prospects the user has
                    rand = random.randint(0,len(companies)-1)

                    # Pulls the prospect info at the random position
                    comp = companies[rand]
                    message = Messages.query.filter_by(comp_id=comp.comp_id).order_by(time.desc())
                    for mess in message:
                        messages.append(Message(mess.comp_id, mess.message_id, mess.message, mess.time))
                    # messages = db.execute("SELECT message FROM messages WHERE comp_id = :comp ORDER BY time DESC",
                    #                         comp=comp)

                    # If the prospect had been contacted within seven days, then it will reset the loop
                    if (datetime.strptime(comp.time, '%Y-%m-%d %H:%M:%S') > (current - timedelta(days=7))) and (len(messages) > 1):
                        i = i - 1

                    # If the prospect hasn't been contacted in the last 7 days then that prospects info is pulled
                    else:

                        # Pulls prospect's info and makes it a company object
                        numId = numId + 1
                        newid = numId
                        name = comp.name
                        address = comp.city + ", " + comp.state
                        phone = comp.phone
                        message = messages[0].message
                        conts = Contacts.query.filter_by(comp_id=comp.comp_id)
                        # conts = db.execute("SELECT * FROM contacts WHERE comp_id = :comp",
                        #                         comp=comp["comp_id"])

                        # Loops through contacts adding contact objects to add to list of contacts for Company Object
                        for cont in conts:
                            contacts.append(Contact(newid, cont.name, cont.title, cont.phone, cont.email))

                        # Adds the Company Object to the list of prospects
                        prospects.append(Company(newid, name, address, phone, message, contacts))

            # returns the template with passed in list of prospects
            return render_template("home.html", prospects=prospects)

        else:
            return render_template("home.html", prospects=prospects)

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
        rows = Users.query.filter_by(username=request.form.get("username")).first()
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                   username=request.form.get("username"))

        # Ensure username exists and password is correct
        if rows == None or not check_password_hash(rows.password, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows.id

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
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Checks if password if longer than eight chars long
        if len(request.form.get("newPassword")) <= 8:
            return apology("Password must be greater than eight charaters long", 403)

        # Checks if password contains number
        if hasNumbers(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one number", 403)

        # Checks if password contains capitalized character
        print(request.form.get("newPassword"))
        print(hasCaps(request.form.get("newPassword")))
        if hasCaps(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one capitalized character", 403)

        # Checks if password contains lowercased character
        if hasLower(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one lowercased character", 403)

        # Ensure password was submitted
        if not request.form.get("newPassword"):
            return apology("must match the password", 403)

        # Ensure both the new password and the confirmed new password match
        if not request.form.get("password") == request.form.get("newPassword"):
            return apology("Confirmation must match password", 403)

        # Query database for username
        rows = Users.query.filter_by(username=request.form.get("username")).first()
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                   username=request.form.get("username"))

        # Ensure username exists and password is correct
        if rows != None:
            return apology("Username already exists", 403)

        # Inserts new user info into db
        user = Users(request.form.get("username"), generate_password_hash(request.form.get("password")))
        db.session.add(user)
        db.session.commit()
        # user = db.execute("INSERT INTO users (username, password) VALUES (:user, :password)",
        #                     user=request.form.get("username"),
        #                     password=generate_password_hash(request.form.get("password")))

        # Query database for username
        rows = Users.query.filter_by(username=request.form.get("username")).first()
        # rows = db.execute("SELECT * FROM users WHERE username = :username",
        #                   username=request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows.id

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/prospects")
@login_required
def prospects():
    """Pulls and displays all of user's prospects"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Gets user's id
        user = session.get("user_id")

        # Grabs the user's owned stocks
        companies = Companies.query.filter_by(user_id=user, isClient='f').all()
        # companies = db.execute("SELECT * FROM companies WHERE user_id = :user_id AND isclient = :client",
        #                     user_id=user,
        #                     client="f")

        # Initialize vars
        prospects = []
        contacts = []
        messes = []
        numId = 0

        # Creates instances of Stock and adds them to the stocks array
        for comp in companies:
            numId = numId + 1
            newid = numId
            name = comp.name
            address = comp.address + ", " + comp.city + ", " + comp.state + " " + comp.zip
            phone = comp.phone
            messId = 0
            messages = Messages.query.filter_by(comp_id=comp.comp_id).order_by(time.desc())
            # messages = db.execute("SELECT * FROM messages WHERE comp_id = :comp ORDER BY time DESC",
            #                         comp=comp["comp_id"])
            conts = Contacts.query.filter_by(comp_id=comp.comp_id).all()
            # conts = db.execute("SELECT * FROM contacts WHERE comp_id = :comp",
            #                         comp=comp["comp_id"])
            for message in messages:
                messes.append(Message(newid, messId, message.message, message.time))
                messId = messId + 1
            for cont in conts:
                contacts.append(Contact(newid, cont.name, cont.title, cont.phone, cont.email))
            prospects.append(Company(numId, name, address, phone, messes, contacts))

        # Returns the template with passed in values
        return render_template("prospects.html", prospects=prospects)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("prospects.html")


@app.route("/clients")
@login_required
def clients():
    """Pulls and displays all of user's clients"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Gets user's id
        user = session.get("user_id")

        # Grabs the user's owned stocks
        companies = Companies.query.filter_by(user_id=user, isClient='t')
        # companies = db.execute("SELECT * FROM companies WHERE user_id = :user_id AND isclient = :client",
        #                     user_id=user,
        #                     client="t")

        # Initialize vars
        clients = []
        contacts = []
        messes = []
        numId = 0


        # Creates instances of Stock and adds them to the stocks array
        for comp in companies:
            numId = numId + 1
            newid = numId
            name = comp.name
            address = comp.address + ", " + comp.city + ", " + comp.state + " " + comp.zip
            phone = comp.phone
            messId = 0
            messages = Messages.query.filter_by(comp_id=comp.comp_id).order_by(time.desc())
            # messages = db.execute("SELECT * FROM messages WHERE comp_id = :comp ORDER BY time DESC",
            #                         comp=comp["comp_id"])
            conts = Contacts.query.filter_by(comp_id=comp.comp_id).all()
            # conts = db.execute("SELECT * FROM contacts WHERE comp_id = :comp",
            #                         comp=comp["comp_id"])
            for message in messages:
                messes.append(Message(newid, messId, message.message, message.time))
                messId = messId + 1
            for cont in conts:
                contacts.append(Contact(newid, cont.name, cont.title, cont.phone, cont.email))
            clients.append((Company(numId, name, address, phone, messes, contacts)))

        # Returns the template with passed in values
        return render_template("clients.html", clients=clients)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("clients.html")


@app.route("/asyncInsert", methods=["GET", "POST"])
@login_required
def asyncInsert():
    """Inserts a user's new prospect or a new client"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Pulls all data sent by the javascript object
        compName = request.args.get("companyName")
        phone = request.args.get("companyPhone")
        address = request.args.get("companyStreet")
        city = request.args.get("companyCity")
        state = request.args.get("companyState")
        zipCode = request.args.get("companyZip")
        country = request.args.get("companyCountry")
        status = request.args.get("companyStatus")

        message = request.args.get("companyMessage")

        contactName = request.args.get("contactName")
        contactEmail = request.args.get("contactEmail")
        contactPhone = request.args.get("contactPhone")
        contactTitle = request.args.get("contactTitle")

        client = 'f'

        # Pulls all of the provided data into an array
        companyData = [compName, phone, address, city, state, zipCode, country, status, message]
        contactData = [contactName, contactEmail, contactPhone, contactTitle]

        # Loops through the company data
        for item in companyData:

            # Checks if all required data was provided
            if item == None:
                return jsonify(result="Must provide required information")

            # Else, makes the item a String variable
            str(item)

        # Checks if new company is a client or prospect
        if str(companyData[7].lower()) == "client":
            client = 't'

        # Gets user's id
        userId = session.get("user_id")

        # Pulls any company with matching names under that user
        checkDup = Companies.query.filter_by(user_id=userId, name=companyData[0]).first()
        # checkDup = db.execute("SELECT * FROM companies WHERE user_id = :user AND name = :name",
        #                         user = userId,
        #                         name = companyData[0])

        # If the new company is a duplicate, then return and do not insert
        if checkDup != None:
            return jsonify(result="Company Already exists")

        # Inserts the new company into the user's database
        inComp = Companies(None,
                            userId,
                            companyData[0],
                            companyData[1],
                            companyData[2],
                            companyData[3],
                            companyData[4],
                            companyData[5],
                            companyData[6],
                            client,
                            None)
        db.session.add(inComp)
        db.session.commit()
        # insert = db.execute("""INSERT INTO companies (user_id, name, phone, address, city, state, zip, country, isclient)
        #                     VALUES (:user, :name, :phone, :address, :city, :state, :zipCode, :country, :status)""",
        #                         user=userId,
        #                         name=companyData[0],
        #                         phone=companyData[1],
        #                         address=companyData[2],
        #                         city=companyData[3],
        #                         state=companyData[4],
        #                         zipCode=companyData[5],
        #                         country=companyData[6],
        #                         status=client)

        # Pulls the new company's comp_id
        comp = Companies.query.filter_by(user_id=userId, name=companyData[0]).first()
        # comp = db.execute("SELECT comp_id FROM companies WHERE user_id = :user AND name = :name",
        #                         user = userId,
        #                         name = companyData[0])

        # Inserts provided message into the new company's message pool
        inMess = Messages(comp.comp_id, companyData[8])
        db.session.add(inMess)
        db.session.commit()
        # inMess = db.execute("INSERT INTO messages (comp_id, message) VALUES (:comp_id, :message)",
        #                         comp_id=comp[0]["comp_id"],
        #                         message=companyData[8])

        # If no contact information was provided, then return Success Message
        if contactData[0] == "" and contactData[1] == "" and contactData[2] == "":
            return jsonify(result="Company successfully added!!!")

        # If contact info was provided then insert the company's contact info
        else:

            # Inserts the company's contact information
            inCont = Contacts(comp.comp_id, contactData[0], contactData[1], contactData[2], contactData[3])
            db.session.add(inCont)
            db.session.commit()
            # insert = db.execute("INSERT INTO contacts VALUES (NULL, :comp_id, :name, :email, :phone, :title)",
            #                         comp_id=comp[0]["comp_id"],
            #                         name=contactData[0],
            #                         email=contactData[1],
            #                         phone=contactData[2],
            #                         title=contactData[3])

        # Returns Success Message once all info is inserted
        return jsonify(result="Company and contact successfully added!!!")

    # If reached via post, then return Failure Message
    else:
        return jsonify(result="FAILURE!!!")


@app.route("/contactInsert")
@login_required
def contactInsert():
    """Inserts contact information for user's existing client or prospect"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Grabs the user's id
        userId = session.get("user_id")

        # Pulls info provided by javascript object
        compName = request.args.get("companyName")
        compPhone = request.args.get("companyPhone")
        contactName = request.args.get("contactName")
        contactEmail = request.args.get("contactEmail")
        contactPhone = request.args.get("contactPhone")
        contactTitle = request.args.get("contactTitle")

        # Pulls the information of the company that the contact is being inserted to
        company = Companies.query.filter_by(name=compName, phone=compPhone).first()
        # company = db.execute("SELECT * FROM companies WHERE name = :name AND phone = :phone",
        #                         name=compName,
        #                         phone=compPhone)

        # Checks if contact already exists
        dups = Contacts.query.filter_by(comp_id=company.comp_id, name=contactName).first()
        # dups = db.execute("SELECT * FROM contacts WHERE comp_id = :comp AND (name = :name OR email = :email)",
        #                         comp=company[0]["comp_id"],
        #                         name=contactName,
        #                         email=contactEmail)

        # If contact is not a duplicate, then it is inserted
        if(dups == None):

            # Inserts the new contact
            inCont = Contacts(company.comp_id,
                                contactName,
                                contactEmail,
                                contactPhone,
                                contactTitle)
            db.session.add(inCont)
            db.session.commit()
            # insertContact = db.execute("INSERT INTO contacts VALUES (NULL, :comp_id, :name, :email, :phone, :title)",
            #                         comp_id=company[0]["comp_id"],
            #                         name=contactName,
            #                         email=contactEmail,
            #                         phone=contactPhone,
            #                         title=contactTitle)

            # Returns Success Message once the contact has successfully been inserted
            return jsonify(result="SUCCESS!!!")

        # If contact is a duplicate then, return the Failure Message
        else:
            return jsonify(result="FAILURE!!!")

    # Else, return the Failure Message
    else:
        return jsonify(result="FAILURE!!!")


@app.route("/messageInsert")
@login_required
def messageInsert():
    """Inserts message for user's existing client or prospect"""

    # User reached route via GET (as by clicking a link or via redirect)
    if request.method == "GET":

        # Grabs the user's id
        userId = session.get("user_id")

        # Pulls info provided by javascript object
        compName = request.args.get("companyName")
        compPhone = request.args.get("companyPhone")
        newMessage = request.args.get("newMessage")

        # Pulls the information of the company that the message is being inserted to
        company = Companies.query.filter_by(name=compName, phone=compPhone).first()
        # company = db.execute("SELECT * FROM companies WHERE name = :name AND phone = :phone",
        #                         name=compName,
        #                         phone=compPhone)

        # Checks if message already exists
        dups = Messages.query.self.filter_by(comp_id=company[0].comp_id, message=newMessage).first()
        # dups = db.execute("SELECT * FROM messages WHERE comp_id = :comp AND message = :message",
        #                         comp=company[0]["comp_id"],
        #                         message=newMessage)

        # If message is not a duplicate, then it is inserted
        if(dups == None):

            # Inserts the new message
            inMess = Messages(company.comp_id, newMessage)
            db.session.add(inMess)
            db.session.commit()
            # insertMessage = db.execute("INSERT INTO messages (comp_id, message) VALUES (:comp_id, :message)",
            #                         comp_id=company[0]["comp_id"],
            #                         message=newMessage)

            # Returns Success Message once the message has successfully been inserted
            return jsonify(result="SUCCESS!!!")

        # If message is a duplicate then, return the Failure Message
        else:
            return jsonify(result="FAILURE!!!")

    # Else, return the Failure Message
    else:
        return jsonify(result="FAILURE!!!")


@app.route("/insert")
@login_required
def insert():
    """Renders the insert.html template on /insert or navbar clicked"""
    return render_template("insert.html")

@app.route("/reset", methods=["GET", "POST"])
@login_required
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
        rows = Users.query.filter_by(id=user_id).first()
        # rows = db.execute("SELECT * FROM users WHERE user_id = :user",
        #                   user=user_id)

        # Ensure username exists and password is correct
        if rows == None or not check_password_hash(rows.password, request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Checks if password if longer than eight chars long
        if len(request.form.get("newPassword")) <= 8:
            return apology("Password must be greater than eight charaters long", 403)

        # Checks if password contains at least one number
        if hasNumbers(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one number", 403)

        # Checks if password contains at least one capitalized character
        if hasCaps(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one capitalized character", 403)

        # Checks if password contains at least one lowercased character
        if hasLower(request.form.get("newPassword")) == False:
            return apology("Password must contain at least one lowercased character", 403)

        # Ensure new password and confirmed new password match
        if not request.form.get("newPassword") == request.form.get("reNewPassword"):
            return apology("New passwords must match", 403)

        # Updates the user's password to the new password
        rows.password = generate_password_hash(request.form.get("newPassword"))
        db.session.commit()
        # updatePass = db.execute("UPDATE users SET password = :newPass WHERE user_id = :user",
        #                             newPass=generate_password_hash(request.form.get("newPassword")),
        #                             user=user_id)

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("reset.html")

@app.route("/logout")
@login_required
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")
