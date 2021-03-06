import csv
import urllib.request
import re
from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Renders message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/0.12/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(session.get("user_id"))
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def hasNumbers(inputString):
    """Checks if str contains  a number"""

    # returns true if str contains number
    return bool(re.search(r'\d', inputString))


def hasCaps(inputString):
    """Checks if str contains copitalized character"""

    # returns true if str contains copitalized character
    return bool(re.search('[A-Z]+', inputString))


def hasLower(inputString):
    """Checks if str contains lowercased character"""

    # returns true if str contains lowercased character
    return bool(re.search('[a-z]+', inputString))
