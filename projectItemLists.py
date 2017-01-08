from flask import Flask, render_template, request, redirect,jsonify, url_for, flash


from sqlalchemy import create_engine, asc, desc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

#New imports for google security test
from flask import session as login_session
import random, string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)
CLIENT_ID = json.loads(open('client_secrets.json','r').read())['web']['client_id']
APPLICATION_NAME = "Items by Category App"

#Connect to Database and create database session
engine = create_engine('sqlite:///items.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create a state token to prevent request forgery.
# Store it in the session for latter validation.
class Env:
    def __init__(self,title=None):
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
  state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
  login_session['state'] = state
  env = Env("Login Page")
  return render_template('login.html',STATE=state,env=env)

@app.route('/fbconnect',methods=['POST'])
def fbconnect():
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter'),401)
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = request.data
  app_id = json.loads(open('fb_client_secrets.json','r').read())['web']['app_id']
  app_secret = json.loads(open('fb_client_secrets.json','r').read())['web']['app_secret']
  url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id,app_secret,access_token)
  h = httplib2.Http()
  result = h.request(url,'GET')[1]
  userinfo_url = 'https://graph.facebook.com/v2.2/me'
  token = result.split('&')[0]
  url = 'https://graph.facebook.com/v2.2/me?%s&fields=name,id,email' % token
  h = httplib2.Http()
  result = h.request(url,'GET')[1]
  data = json.loads(result)
  login_session['provider'] = 'facebook'
  login_session['username'] = data['name']
  login_session['email'] = data['email']
  login_session['facebook_id'] = data['id']
  # Get picture
  url = 'https://graph.facebook.com/v2.2/me/picture?%s&redirect=0&height=200&width=200' % token
  h = httplib2.Http()
  result = h.request(url,'GET')[1]
  data = json.loads(result)
  login_session['picture'] = data['data']['url']

  user_id = getUserID(login_session['email'])
  if not user_id:
    user_id = createUser(login_session)
  else:
    updateUser(login_session)
  login_session['email']=user_id
  output = ''
  output += 'Welcome, '
  output += login_session['username']
  output += '!'
  output += '<img src="'
  output += login_session['picture']
  output += '"  style="width:50px;height:50px;border-radius:10px;-webkit-border-radius:10px;-moz-border-radius:10px;">'
  flash("You are now logged in as %s" % login_session['username'])
  return output

@app.route('/gconnect',methods=['POST'])
def gconnect():
  # return request.args.get('state')
  # return login_session['state']
  if request.args.get('state') != login_session['state']:
    response = make_response(json.dumps('Invalid state parameter'),401)
    response.headers['Content-Type'] = 'application/json'
    return response
  request.get_data()
  code = request.data #.decode('utf-8')
  try:
    oauth_flow = flow_from_clientsecrets('client_secrets.json',scope='')
    oauth_flow.redirect_uri = 'postmessage'
    credentals = oauth_flow.step2_exchange(code)
  except FlowExchangeError:
    response = make_response(json.dumps('Failed to upgrade the authorization code',401))
    response.headers['Content-Type'] = 'application/json'
    return response
  access_token = credentals.access_token
         # 'https://accounts.google.com/o/oauth2/token'
  url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
  h = httplib2.Http()
  response = h.request(url,'GET')[1]
  str_response = response.decode('utf-8')
  result = json.loads(str_response)

  if result.get('error') is not None:
    response = make_response(json.dumps(result('error')),500)
    response.headers['Content-Type'] = 'application/json'
    return response

  gplus_id = credentals.id_token['sub']
  if result['user_id'] != gplus_id:
    response = make_response(json.dumps('Token\'s user_id does not match given user ID'),401)
    response.headers['Content-Type'] = 'application/json'
    return response
  if result['issued_to'] != CLIENT_ID:
    response = make_response(json.dumps('Token\'s CLIENT Information does not match app\'s'),401)
    response.headers['Content-Type'] = 'application/json'
    return response
  stored_access_token = login_session.get('access_token')
  stored_gplus_id = login_session.get('gplus_id')
  if stored_access_token is not None and gplus_id == stored_gplus_id:
    response = make_response(json.dumps('Current user ID already connected'),200)
    response.headers['Content-Type'] = 'application/json'
    return response

  # Store the access token for later use
  login_session['access_token'] = access_token
  login_session['gplus_id'] = gplus_id

  # Get user info
  userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
  params = {'access_token':access_token,'alt':'json'}
  answer = requests.get(userinfo_url,params=params)
  data = answer.json()

  login_session['provider'] = 'google'
  login_session['username'] = data['name']
  login_session['picture'] = data['picture']
  login_session['email'] = data['email']
  user_id = getUserID(login_session['email'])

  if not user_id:
    user_id = createUser(login_session)
  else:
    updateUser(login_session)
  login_session['user_id'] = user_id


  output = ''
  output += 'Welcome, '
  output += login_session['username']
  output += '!'
  output += '<img src="'
  output += login_session['picture']
  output += '" style="width:50px;height:50px;border-radius:10px;-webkit-border-radius:10px;-moz-border-radius:10px;">'
  flash("You are now logged in as %s" % login_session['username'])
  return output


@app.route('/fbdisconnect')
def fbdisconnect():
    # Only disconnect a connected user
  facebook_id = login_session.get('facebook_id')
  url = 'https://graph.facebook.com/%s/permissions' % facebook_id
  h = httplib2.Http()
  result = h.request(url,'DELETE')[1]

  return 'You have been logged out.'

@app.route('/gdisconnect')
def gdisconnect():
  # Only disconnect a connected user
  credentials = login_session.get('credentials')
  if credentials is None:
    response = make_response(json.dumps('Current user not connected.',401))
    response.headers['Content-Type'] = 'application/json'
    return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url,'GET')[0]
    if result['status'] == '200':
      # Reset user session
      response = make_response(json.dumps('Successfully disconnected',200))
      response.headers['Content-Type'] = 'application/json'
      return response

@app.route('/disconnect')
def disconnect():
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

####################PROJECT RELATED######################################

#JSON APIs to view Category Information
@app.route('/category/<int:category_id>/item/JSON')
def categoryItemJSON(category_id):
    category = session.query(Category).filter_by(id = category_id).one()
    items = session.query(Item).filter_by(category_id = category_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/item/<int:item_id>/JSON')
def itemJSON(item_id):
    item = session.query(Item).filter_by(id = item_id).one()
    return jsonify(item=item.serialize)

@app.route('/category/JSON')
def categoriesJSON():
    categories = session.query(Category).order_by(Category.name).all()
    return jsonify(categories= [c.serialize for c in categories])

@app.route('/user/JSON')
def userJSON():
    users = session.query(User).order_by(User.name).all()
    return jsonify(users= [u.serialize for u in users])

@app.route('/allitems/JSON')
def allItemsJSON():
    items = session.query(Item).order_by(Item.created_date).all()
    return jsonify(items= [i.serialize for i in items])

#Show all categories
@app.route('/')
@app.route('/category/')
def showCategories():
  categories = session.query(Category).order_by(asc(Category.name)).all()
  items = session.query(Item).order_by(desc(Item.created_date)).all()
  env = Env()
  env.title = "Categories"
  if 'username' not in login_session:
    # return render_template('publiccategories.html', categories=categories,items=items,env=env)
    return render_template('categories.html', categories=categories,items=items,env=env)
  else:
    return render_template('categories.html', categories=categories,items=items,env=env)

#Create a new category
@app.route('/category/new/', methods=['GET','POST'])
def newCategory():
  if 'username' not in login_session:
    return redirect('/login')
  if request.method == 'POST':
    newCategory = Category(name = request.form['name'],user_id=login_session['email'])
    session.add(newCategory)
    flash('New Category %s Successfully Created' % newCategory.name)
    session.commit()
    return redirect(url_for('showCategories'))
  else:
    env = Env()
    env.title = "New Categories"
    return render_template('newCategory.html',env=env)

#Edit a category
@app.route('/category/<int:category_id>/edit/', methods = ['GET', 'POST'])
def editCategory(category_id):
  editedCategory = session.query(Category).filter_by(id = category_id).one()
  if request.method == 'POST':
    if request.form['name']:
      editedCategory.name = request.form['name']
      flash('Category Successfully Edited %s' % editedCategory.name)
      return redirect(url_for('showCategories'))
  else:
    env = Env("Edit Category")
    return render_template('editCategory.html', category = editedCategory,env=env)


#Delete a category
@app.route('/category/<int:category_id>/delete/', methods = ['GET','POST'])
def deleteCategory(category_id):
  categoryToDelete = session.query(Category).filter_by(id = category_id).one()
  if request.method == 'POST':
    session.delete(categoryToDelete)
    flash('%s Successfully Deleted' % categoryToDelete.name)
    session.commit()
    return redirect(url_for('showCategories', category_id = category_id))
  else:
    env = Env("Delete Category")
    return render_template('deleteCategory.html',category = categoryToDelete,env=env)

#Show a category item
@app.route('/category/<int:category_id>/')
@app.route('/category/<int:category_id>/item/')
def showItem(category_id):
  category = session.query(Category).filter_by(id = category_id).one()
  items = session.query(Item).filter_by(category_id = category_id).order_by(asc(Item.created_date)).distinct()
  creator = getUserInfo(category.user_id)
  env = Env()
  env.title = "Items By Category"
  env.creator = creator
  # if 'username' not in login_session or creator.email != login_session['email']:
  if 'email' not in login_session:
    return render_template('item.html', items = items, category = category,env = env)
  else:
    return render_template('item.html', items = items, category = category,env = env)



#Create a new item
@app.route('/category/<int:category_id>/item/new/',methods=['GET','POST'])
def newItem(category_id):
  category = session.query(Category).filter_by(id = category_id).one()
  env = Env()
  env.title = "New Item"
  if request.method == 'POST':
      newItem = Item(name = request.form['name'], category_id = category_id,user_id=category.user_id)
      session.add(newItem)
      session.commit()
      flash('New %s Item Successfully Created' % (newItem.name))
      return redirect(url_for('showItem', category_id = category_id))
  else:
      return render_template('newitem.html', category_id = category_id,env=env)

#Edit a item
@app.route('/category/<int:category_id>/items/<int:item_id>/edit', methods=['GET','POST'])
def editItem(category_id, item_id):

    editedItem = session.query(Item).filter_by(id = item_id).one()
    category = session.query(Category).filter_by(id = category_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showItem', category_id = category_id))
    else:
        env = Env("Edit Item")
        return render_template('edititem.html', category_id = category_id,item = editedItem,env=env)


#Delete a item
@app.route('/category/<int:category_id>/items/<int:item_id>/delete', methods = ['GET','POST'])
def deleteItem(category_id,item_id):
    category = session.query(Category).filter_by(id = category_id).one()
    itemToDelete = session.query(Item).filter_by(id = item_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Successfully Deleted')
        return redirect(url_for('showItem', category_id = category_id))
    else:
        env = Env("Delete Item")
        return render_template('deleteItem.html', item = itemToDelete,env = env)


##########################GENERAL STUFF###################################
def getUserID(email):
  try:
    user = session.query(User).filter_by(email = email).one()
    return user.email
  except:
    return None


def getUserInfo(user_id):
  try:
    user = session.query(User).filter_by(email = user_id).one()
  except:
    user = None
  return user


def createUser(login_session):
  newUser = User(name = login_session['username'], email = login_session['email'],picture=login_session['picture'])
  session.add(newUser)
  session.commit()
  user = session.query(User).filter_by(email=login_session['email']).one()
  return user.email

def updateUser(login_session):
  user = User(name = login_session['username'], email = login_session['email'],picture=login_session['picture'])
  user.picture = login_session['picture']
  #session.add(user)
  session.commit()
  return


if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 5000)
