import os
import re
from string import letters
import hashlib
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

#HASHING SECURE FUNCTIONS and these are some changes for a second commit
def hash_str(s):
    x = secret + s
    return hashlib.md5(x).hexdigest()

def make_secure_val(h):
    return "%s|%s" % (h, hash_str(h))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val

secret = "alksjdhflkasjhflaksjhfalskjhflaskdjhfalskjhflaksjfh"

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)
    created = db.DateTimeProperty(auto_now_add = True)
    
class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BaseHandler):

    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)
                      
        q = db.GqlQuery("SELECT * FROM User WHERE username = :1", username)
        for Username_exists in q:
            if Username_exists.username == username:
                params['error_exists'] = "That username already exists"
                have_error = True

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        
        else:
            hashpassword = hash_str(password)
            
            if username and password:
                a = User(username = username, password = hashpassword, email = email)
                a.put()
                
            userid = str(a.key().id())
            cookie = make_secure_val(userid)
            
            self.response.headers.add_header('Set-Cookie', 'userid=%s' %cookie)
            
            self.redirect('/')

class Login(BaseHandler):

    def get(self):
        self.render("login-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        hashpassword = hash_str(password)

        params = dict(username = username)
                      
        q = db.GqlQuery("SELECT * FROM User WHERE username = :1 AND password = :2", username, hashpassword)
        user = q.get()
        if user:  
            userid = str(user.key().id())
            cookie = make_secure_val(userid)
            self.response.headers.add_header('Set-Cookie', 'userid=%s' %cookie)
            
            self.redirect('/')
        
        else: 
            params['error'] = "There was a problem with your login information."
            have_error = True
            if have_error:
                self.render('login-form.html', **params)

COOKIE_RE = re.compile(r'.+=;\s*Path=/')
def valid_cookie(cookie):
    return cookie and COOKIE_RE.match(cookie)

class Logout(BaseHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'userid=; Path=/')
        self.redirect('/signup')
       
        
class Welcome(BaseHandler):
    def get(self):
        # self.response.headers['Content-Type'] = 'text/plain'
        cookie = self.request.cookies.get('userid', '0')
        userid = check_secure_val(cookie)
        username = ""
        
        if userid:
           q = User.get_by_id(int(userid))
           username = q.username
        
        if username != "":
            logouturl = "/logout"
            self.render('welcome.html', username = username, logouturl = logouturl)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([('/logout', Logout),
                               ('/signup', Signup),
                               ('/login', Login),
                               ('/', Welcome)],
                              debug=True)
