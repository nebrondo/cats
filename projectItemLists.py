from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
from functools import wraps

from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

# New imports for google security test
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
import os
dir_path = os.path.dirname(os.path.realpath(__file__))
app = Flask(__name__)
CLIENT_ID = json.loads(open(dir_path+'/client_secrets.json', 'r').read())[
    'web']['client_id']
APPLICATION_NAME = "Items by Category App"

# Connect to Database and create database session
engine = create_engine('postgresql:///items')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


class Env:
    """
    Env class: used to send parameters to templates in a unifor way
    Args:
        title (data type: str): used in templates for title
    """
    def __init__(self, title=None):
        if 'email' in login_session:
            self.__currentUser = login_session
        else:
            self.__currentUser = []
        if title:
            self.__title = title
        else:
            self.__title = "Categories App"

    @property
    def title(self):
        return self.__title

    @title.setter
    def title(self, title):
        self.__title = title

    @property
    def creator(self):
        return self.__creator

    @creator.setter
    def creator(self, creator):
        self.__creator = creator

    @property
    def currentUser(self):
        return self.__currentUser

    @currentUser.setter
    def currentUser(self, currentUser):
        self.__currentUser = currentUser


@app.route('/login')
def showLogin():
    """
    showLogin: displays login page
    Returns:
        return templates having a state and environment object
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    env = Env("Login Page")
    # return render_template(dir_path+'/templates/login.html', STATE=state, env=env)
    return render_template('login.html', STATE=state, env=env)

def login_required(f):
    """
    login_required decorator: used to validate if a particular method requires
    start a session
    Args:
        f (data type: function): function to be validated for login
    Returns:
        returns the function to decorate or redirects to login page if access
        is not granted
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'email' in login_session:
            return f(*args, **kwargs)
        else:
            flash('Please log-in first...')
            return redirect('/login')
    return decorated_function


@login_required
def check_creator(category_id=None):
    """
    check_creator method: validates the creator to allow operations such as
    edit and delete
    Args:
        category_id (data type: int): used to get user_id for category
    Returns:
        returns True or False to allow or deny UD operations
    """
    if category_id:
        editCat = session.query(Category).filter_by(id=category_id).one()
        user = editCat.user_id
    if user == login_session['email']:
        return True
    else:
        flash('You are not allowed to change this record')
        return False


# Create a state token to prevent request forgery.
# Store it in the session for latter validation.
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    """
    fbconnect: provides means to authenticate and authorize via fb apis
    Returns:
        returns the html with the results of the operation
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    app_id = json.loads(open(dir_path+'/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(open(dir_path+'/fb_client_secrets.json', 'r').read())[
        'web']['app_secret']
    url = 'https://graph.facebook.com'
    url += '/oauth/access_token?grant_type=fb_exchange_token'
    url += '&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    userinfo_url = 'https://graph.facebook.com/v2.2/me'
    token = result.split('&')[0]
    url = 'https://graph.facebook.com/v2.2/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['facebook_id'] = data['id']
    # Get picture
    url = 'https://graph.facebook.com/v2.2/me/'
    url += 'picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)
    login_session['picture'] = data['data']['url']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['email'] = user_id
    output = ''
    output += 'Welcome, '
    output += login_session['username']
    output += '!'
    output += '<img src="'
    output += login_session['picture']
    output += '" style="width:50px;height:50px;border-radius:10px;'
    output += '-webkit-border-radius:10px;-moz-border-radius:10px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/gconnect', methods=['POST'])
def gconnect():
    """
    gconnect: provides means to authenticate and authorize via google apis
    Returns:
        returns the html with the results of the operation
    """
    # return request.args.get('state')
    # return login_session['state']
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # request.get_data()
    code = request.data  # .decode('utf-8')
    try:
        oauth_flow = flow_from_clientsecrets(dir_path+'/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentals = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code', 401))
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentals.access_token
    # 'https://accounts.google.com/o/oauth2/token'
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' %
           access_token)
    h = httplib2.Http()
    response = h.request(url, 'GET')[1]
    str_response = response.decode('utf-8')
    result = json.loads(str_response)

    if result.get('error') is not None:
        response = make_response(json.dumps(result('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = credentals.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps(
            'Token\'s user_id does not match given user ID'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps(
            'Token\'s CLIENT Information does not match app\'s'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user ID already connected'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token for later use
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    user_id = getUserID(login_session['email'])

    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += 'Welcome, '
    output += login_session['username']
    output += '!'
    output += '<img src="'
    output += login_session['picture']
    output += '" style="width:50px;height:50px;border-radius:10px;'
    output += '-webkit-border-radius:10px;-moz-border-radius:10px;">'
    flash("You are now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    """
    fbconnect: provides means to disconnect from fb
    Returns:
        returns message after disconnected
    """
    # Only disconnect a connected user
    facebook_id = login_session.get('facebook_id')
    url = 'https://graph.facebook.com/%s/permissions' % facebook_id
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    return 'You have been logged out.'


@app.route('/gdisconnect')
def gdisconnect():
    """
    gdisconnect: provides means to disconnect from google
    Returns:
        returns json message after disconnected
    """
    # Only disconnect a connected user
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(json.dumps(
            'Current user not connected.', 401))
        response.headers['Content-Type'] = 'application/json'
        return response
        access_token = credentials.access_token
        url = 'https://accounts.google.com'
        url += '/o/oauth2/revoke?token=%s' % access_token
        h = httplib2.Http()
        result = h.request(url, 'GET')[0]
        if result['status'] == '200':
            # Reset user session
            response = make_response(json.dumps(
                'Successfully disconnected', 200))
            response.headers['Content-Type'] = 'application/json'
            return response


@app.route('/disconnect')
def disconnect():
    """
    disconnect: generic method used for both fb and google disconnect
    Returns:
        return redirection to categories page
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            # del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']

        # del login_session['user_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        # login_session['provider'] = 'google'
        flash("You were not logged in to begin with!")
        return redirect(url_for('showCategories'))

# PROJECT RELATED
# JSON APIs to view Category Information


@app.route('/category/<int:category_id>/item/JSON')
@login_required
def categoryItemJSON(category_id):
    """
    categoryItemJSON method: displays items related to a category in JSON
    format
    Args:
        category_id (data type: int): category to be used to query items
    Returns:
        returns serialized JSON with a list of Items
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/item/<int:item_id>/JSON')
@login_required
def itemJSON(item_id):
    """
    itemJSON method: displays a single item based on ID in JSON format
    Args:
        item_id (data type: int): item to be used to query items
    Returns:
        returns serialized JSON with a list of Items
    """
    item = session.query(Item).filter_by(id=item_id).one()
    return jsonify(item=item.serialize)


@app.route('/category/JSON')
@login_required
def categoriesJSON():
    """
    categoriesJSON method: displays all categories in JSON format
    Returns:
        returns serialized JSON with a list of Categories
    """
    categories = session.query(Category).order_by(Category.name).all()
    return jsonify(categories=[c.serialize for c in categories])


@app.route('/user/JSON')
@login_required
def userJSON():
    """
    userJSON method: displays all users in JSON format
    Returns:
        returns serialized JSON with a list of Users
    """
    users = session.query(User).order_by(User.name).all()
    return jsonify(users=[u.serialize for u in users])


@app.route('/allitems/JSON')
@login_required
def allItemsJSON():
    """
    allItemsJSON method: displays all items in JSON format
    Returns:
        returns serialized JSON with a list of Items
    """
    items = session.query(Item).order_by(Item.created_date).all()
    return jsonify(items=[i.serialize for i in items])


# Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
    """
    showCategories method: generates categories page based on session status
    Returns:
        return categories page
    """
    categories = session.query(Category).order_by(asc(Category.name)).all()
    items = session.query(Item).order_by(desc(Item.created_date)).all()
    env = Env()
    env.title = "Categories"
    if 'username' not in login_session:
        # return render_template('publiccategories.html',
        # categories=categories,items=items,env=env)
        return render_template('categories.html', categories=categories,
                               items=items, env=env)
    else:
        return render_template('categories.html', categories=categories,
                               items=items, env=env)


# Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
@login_required
def newCategory():
    """
    newCategory method: generates  new category page based on session status
    Returns:
        return new category page
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newCategory = Category(
            name=request.form['name'], user_id=login_session['email'])
        session.add(newCategory)
        flash('New Category %s Successfully Created' % newCategory.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        env = Env()
        env.title = "New Categories"
        return render_template('newCategory.html', env=env)


# Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
@login_required
def editCategory(category_id):
    """
    editCategory method: generates edit category page based on session status
    Args:
    category_id (data type: int): category to be edited
    Returns:
        return edit category page
    """
    if check_creator(category_id):
        editedCategory = session.query(
            Category).filter_by(id=category_id).one()
        if request.method == 'POST':
            if request.form['name']:
                editedCategory.name = request.form['name']
                flash('Category Successfully Edited %s' % editedCategory.name)
                return redirect(url_for('showCategories'))
        else:
            env = Env("Edit Category")
            return render_template('editCategory.html',
                                   category=editedCategory, env=env)
    else:
        return redirect('/category/%s/' % str(category_id))


# Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
@login_required
def deleteCategory(category_id):
    """
    deleteCategory method: generates  new category page based on session status
    Args:
    category_id (data type: int): category to be deleted
    Returns:
        return new category page
    """
    if check_creator(category_id):
        categoryToDelete = session.query(
            Category).filter_by(id=category_id).one()
        if request.method == 'POST':
            session.delete(categoryToDelete)
            flash('%s Successfully Deleted' % categoryToDelete.name)
            session.commit()
            return redirect(url_for('showCategories', category_id=category_id))
        else:
            env = Env("Delete Category")
            return render_template('deleteCategory.html',
                                   category=categoryToDelete, env=env)
    else:
        return redirect('/category/%s/' % str(category_id))


# Show a category item
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/')
def showItem(category_id):
    """
    method/class name: short description
    Args:
        arg1 (data type: int/str/ etc): argument description
        etc ...
    Returns:
        return value description
    """
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(
        category_id=category_id).order_by(asc(Item.created_date)).distinct()
    creator = getUserInfo(category.user_id)
    env = Env()
    env.title = "Items By Category"
    env.creator = creator
    # if 'username' not in login_session or creator.email !=
    # login_session['email']:
    if 'email' not in login_session:
        return render_template('item.html', items=items, category=category,
                               env=env)
    else:
        return render_template('item.html',
                               items=items, category=category, env=env)


# Create a new item
@app.route('/category/<int:category_id>/item/new/', methods=['GET', 'POST'])
@login_required
def newItem(category_id):
    """
    newItem method: generates new item page based on session status
    Args:
    category_id (data type: int): category associated to the item to be
    created.
    Returns:
        return new item page depending on session status
    """
    if check_creator(category_id):
        category = session.query(Category).filter_by(id=category_id).one()
        env = Env()
        env.title = "New Item"
        if request.method == 'POST':
            newItem = Item(name=request.form['name'], category_id=category_id,
                           user_id=category.user_id)
            session.add(newItem)
            session.commit()
            flash('New %s Item Successfully Created' % (newItem.name))
            return redirect(url_for('showItem', category_id=category_id))
        else:
            return render_template('newitem.html',
                                   category_id=category_id, env=env)
    return redirect('/category/%s/item/' % str(category_id))


# Edit a item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
@app.route('/category/<int:category_id>/items/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editItem(category_id, item_id):
    """
    editItem method: generates edit item page based on session status
    Args:
    category_id (data type: int): category associated to the item to be
    edited.
    Returns:
        return edit item page depending on session status
    """
    if check_creator(category_id):
        editedItem = session.query(Item).filter_by(id=item_id).one()
        category = session.query(Category).filter_by(id=category_id).one()
        if request.method == 'POST':
            if request.form['name']:
                editedItem.name = request.form['name']
            session.add(editedItem)
            session.commit()
            flash('Item Successfully Edited')
            return redirect(url_for('showItem', category_id=category_id))
        else:
            env = Env("Edit Item")
            return render_template('editItem.html',
                                   category_id=category_id,
                                   item=editedItem, env=env)
    else:
        return redirect('/category/%s/item/' % str(category_id))


# Delete a item
@app.route('/category/<int:category_id>/items/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteItem(category_id, item_id):
    """
    deleteItem method: generates edit item page based on session status
    Args:
    category_id (data type: int): category associated to the item to be deleted
    item_id (data type: int): item to be deleted
    Returns:
        return delete item page depending on session status and redirect to the
        category page when item was deleted
    """
    if check_creator(category_id):
        category = session.query(Category).filter_by(id=category_id).one()
        itemToDelete = session.query(Item).filter_by(id=item_id).one()
        if request.method == 'POST':
            session.delete(itemToDelete)
            session.commit()
            flash('Item Successfully Deleted')
            return redirect(url_for('showItem', category_id=category_id))
        else:
            env = Env("Delete Item")
            return \
                render_template('deleteItem.html', item=itemToDelete, env=env)
    else:
        return redirect('/category/%s/item/' % str(category_id))


# GENERAL STUFF
def getUserID(email):
    """
    getUserID method: get user id based on email
    Args:
    email (data type: str): email to be used to retreive ID
    Returns:
        returns user id
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.email
    except:
        return None


def getUserInfo(user_id):
    """
    getUserInfo method: gets a user object based on user_id
    Args:
    user_id (data type: str): email to be used to retreive user
    Returns:
        returns user object
    """
    try:
        user = session.query(User).filter_by(email=user_id).one()
    except:
        user = None
    return user


def createUser(login_session):
    """
    createUser method: creates user based on login session
    Args:
    login_session (data type: object): login_session to be used to create user
    Returns:
        returns email of newly created user
    """
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.email


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=80)
