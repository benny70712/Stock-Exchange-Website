import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_info = db.execute("SELECT * FROM users where id = ?", session["user_id"])
    history_rows = db.execute("SELECT * FROM history where user_id = ?", session["user_id"])

    total_money = user_info[0]["cash"]
    for row in history_rows:
        stock_price = float(lookup(row["symbol"])["price"])
        db.execute("UPDATE history SET price = ? where user_id = ? AND symbol = ?", stock_price, session["user_id"], row["symbol"])
        total_money += stock_price * row["shares"]


    return render_template("index.html", user_cash=user_info[0]["cash"], history_rows=history_rows, total=total_money)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    else:
        symbol = request.form.get("symbol").upper()

        stock_info = lookup(symbol)

        if not symbol:
            return apology("Missing symbol", 400)

        shares = request.form.get("shares")

        if not shares:
            return apology("Missing shares", 400)

        try:
            shares = int(shares)
        except:
            return apology("Shares must be a number", 400)

        if type(shares) == float:
            return apology("Shares can't be a float", 400)

        shares = int(shares)

        if shares <= 0:
            return apology("Shares must be positive", 400)


        if stock_info == None:
            return apology("Invalid Symbol", 400)

        price = stock_info["price"]
        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        user_money = rows[0]["cash"]
        purchase_money = int(shares) * float(price)


        if purchase_money > user_money:
            return apology("Cannot afford", 400)

        db.execute("UPDATE users SET cash = ? WHERE id = ? ", user_money - purchase_money, session["user_id"])

        history_rows = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])

        for row in history_rows:
            if row["symbol"] == symbol:

                db.execute("UPDATE history SET shares = ? WHERE user_id =?", int(shares) + int(row["shares"]), session["user_id"])
                db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted_time) VALUES (?,?,?,?, datetime('now'))", session["user_id"], symbol, shares, price)
                return redirect("/")

        db.execute("INSERT INTO history (user_id, symbol, shares, price) VALUES (?,?,?,?)", session["user_id"], symbol, shares, price)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted_time) VALUES (?,?,?,?, datetime('now'))", session["user_id"], symbol, shares, price)


        return redirect("/")






@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = ?", session["user_id"])
    return render_template("history.html", transactions=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():

    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        user_symbol = request.form.get("symbol")
        stock_info = lookup(user_symbol)

        if stock_info == None:
            return apology("Invalid Symbol",400)

        symbol = stock_info["symbol"]
        price = stock_info["price"]


        return render_template("quoted.html", symbol=symbol, price=price)





@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    if request.method == "POST":

        if not username:
            return apology("must provide username", 400)

        elif not password:
            return apology("must provide password", 400)

        elif len(password) < 8:
            return apology("password must be at least 8 characters.")

        elif not confirmation:
            return apology("must provide confirmation", 400)

        elif password != confirmation:
            return apology("password doesn't match with confirmation", 400)

        check_rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if len(check_rows) != 0:
            return apology("User name is already taken", 400)

        db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, generate_password_hash(password))
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        session["user_id"] = rows[0]["id"]
        return redirect("/")
    else:

        return render_template("register.html")




@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    rows = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])
    if request.method == "GET":
        return render_template("sell.html", rows=rows)
    else:

        selected_symbol = request.form.get('symbol')
        sell_shares = request.form.get("shares")

        if not selected_symbol:
            return apology("Missing symbol", 400)

        if int(sell_shares) <= 0:
            return apology("Shares must be positive", 400)


        for row in rows:
            if row["symbol"] == selected_symbol and int(sell_shares) > row["shares"]:

                return apology("Too many shares", 400)

        sell_price = lookup(selected_symbol)["price"] * int(sell_shares)

        # reduce the user cash
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash[0]['cash'] + sell_price, session["user_id"])

        # get the shares
        shares = db.execute("SELECT shares FROM history WHERE user_id = ? AND symbol = ?", session["user_id"], selected_symbol)
        user_shares = shares[0]["shares"]

        # update the shares
        db.execute("UPDATE history SET shares = ? WHERE user_id = ? AND symbol = ?", user_shares - int(sell_shares), session["user_id"], selected_symbol)

        # if the updated shares = 0, then delete it from the history
        updated_shares = db.execute("SELECT shares from history where user_id = ? AND symbol= ?", session["user_id"], selected_symbol)
        if int(updated_shares[0]["shares"]) == 0:
            db.execute("DELETE FROM history WHERE user_id = ? AND symbol = ?", session["user_id"], selected_symbol)

        # record the sell transaction
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, transacted_time) VALUES (?,?,?,?, datetime('now'))", session["user_id"], selected_symbol, -1 * int(sell_shares), sell_price)


        return redirect("/")



