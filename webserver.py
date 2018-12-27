from flask import Flask, render_template, request, make_response, redirect, flash, url_for, session as login_session, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Item, Category, User
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
from functools import wraps
import httplib2, datetime
import json, random, string, requests

app = Flask(__name__)

# binds the app to the db and creates a db session
engine = create_engine('sqlite:///items.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function

# main page
@app.route('/')
@app.route('/categories/')
def show_home():
	categories = session.query(Category).all()
	latest_items = session.query(Item).order_by("date_added desc")
	if 'username' not in login_session:
		return render_template('home.html', categories = categories, latest_items = latest_items)
	else:
		return render_template('user_home.html', categories = categories, latest_items = latest_items)

@app.route('/categories/new', methods=['GET', 'POST'])
@login_required
def create_category():
	if request.method == 'POST':
		if 'user_id' not in login_session and 'email' in login_session:
			login_session['user_id'] = get_user_id(login_session)
		new_category = Category(
			name = request.form['name'],
			user_id = login_session['user_id'])
		session.add(new_category)
		session.commit()
		flash("New category created")
		return redirect(url_for("show_home"))
	if request.method == 'GET':
		return render_template('new_category.html')

@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
	category = session.query(Category).filter_by(id = category_id).one()
	# if user is not authorized to edit this category
	if category.user_id != login_session['user_id']:
		return "<script> function foo() {alert('You are not authorized to edit this category.')}</script><body onload='foo()'>"
	if request.method == 'POST':
		if request.form['name']:
			category.name = request.form['name']
			flash('Category successfully edited as ' + category.name)
			return redirect(url_for('show_home'))
	if request.method == 'GET':
		return render_template('edit_category.html', category = category)

@app.route('/categories/<int:category_id>')
def show_category(category_id):
	category = session.query(Category).filter_by(id = category_id).one()
	items = session.query(Item).filter_by(category_id = category_id)
	return render_template('category.html', category = category, items = items)

@app.route('/categories/<int:category_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_category(category_id):
	category = session.query(Category).filter_by(id = category_id).one()
	items = session.query(Item).filter_by(category_id = category_id)
	if category.user_id != login_session['user_id']:
		return "<script>function foo() {alert('You are not authorized!')}</script><body onload='foo()'>"
	if request.method == 'POST':
		session.delete(category)
		session.commit()
		for item in items:
			session.delete(item)
			session.commit()
		flash(category.name + ' and all its items were successfully deleted')
		return redirect(url_for('show_home'))
	if request.method == 'GET':
		return render_template('delete_category.html', category = category)

@app.route('/categories/<int:category_id>/add', methods=['GET', 'POST'])
@login_required
def create_item(category_id):
	category = session.query(Category).filter_by(id = category_id).one()
	if request.method == 'POST':
		item = Item(
			name = request.form['name'],
			description = request.form['description'],
			price = request.form['price'],
			date_added = datetime.datetime.now(),
			category_id = category.id,
			user_id = login_session['user_id'])
		session.add(item)
		session.commit()
		flash("New item successfully created")
		return redirect(url_for('show_category', category_id = category_id))
	if request.method == 'GET':
		return render_template('new_item.html', category = category)

@app.route('/categories/<int:category_id>/item/<int:item_id>')
def show_item(category_id, item_id):
    category = session.query(Category).filter_by(id = category_id).one()
    item = session.query(Item).filter_by(id = item_id).one()
    user = get_user(category.user_id)
    return render_template('item.html', item = item, category = category, user = user)

@app.route('/categories/<int:category_id>/item/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_item(category_id, item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    category = session.query(Category).filter_by(id = category_id).one()
    # if user is not authorized to edit this item
    if item.user_id != login_session['user_id']:
        return "<script> function foo() {alert('You are not authorized to edit this item.')}</script><body onload='foo()'>"
    if request.method == 'POST':
        if request.form['name']:
            item.name = request.form['name']
        if request.form['price']:
            item.price = request.form['price']
        if request.form['description']:
            item.description = request.form['description']
        flash(item.name + ' successfully edited')
        return redirect(url_for('show_item', category_id = category.id, item_id = item.id))
    if request.method == 'GET':
        return render_template('edit_item.html', item = item, category = category)

@app.route('/categories/<int:category_id>/item/<int:item_id>/delete', methods=['GET', 'POST'])
@login_required
def delete_item(category_id, item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    category = session.query(Category).filter_by(id = category_id).one()
    if item.user_id != login_session['user_id']:
        return "<script>function foo() {alert('You are not authorized!')}</script><body onload='foo()'>"
    if request.method == 'POST':
        session.delete(item)
        session.commit()
        flash(item.name + ' was successfully deleted')
        return redirect(url_for('show_category', category_id = category_id))
    if request.method == 'GET':
        return render_template('delete_item.html', item = item, category = category)

@app.route('/catalog/json')
# returns all the items in all of the categories
def show_catalog_json():
    items = session.query(Item).order_by("date_added desc")
    return jsonify(items = [i.serialize for i in items])

@app.route('/categories/json')
# returns all the categories
def show_categories_json():
    categories = session.query(Category).all()
    return jsonify(categories = [c.serialize for c in categories])

@app.route('/categories/<int:category_id>/item/<int:item_id>/json')
# returns selected item
def show_item_json(category_id, item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    return jsonify(item = item.serialize)


# Login route, create anit-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits) for x in range(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

# google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data
    print(request.args.get('state'))
    print(login_session['state'])

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if not create new user
    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_new_user(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '  # noqa
    flash("you are now logged in as %s" % login_session['username'], 'success')
    print("done!")
    return output

@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-type'] = 'application/json'
        return response
    # execute HTTP GET request to revoke current token
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # reset the user's session
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    else:
        # token given is invalid
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

# User helper functions
def get_user_id(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def get_user(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def create_new_user(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

if __name__ == '__main__':
	app.secret_key = 'secret_key'
	app.debug = True
	app.run(host='0.0.0.0', port=5000)