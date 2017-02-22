import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

secret = 'BlogHashSecret'

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

"""
def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
"""
class MainPage(BlogHandler):
  def get(self):
      self.write('Hello, Udacity!')

##### User Stuff

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls( name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

##### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

# Entity

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    author_id = db.StringProperty(required = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class Comments(db.Model):

    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    comment = db.TextProperty(required=True)
    author_id = db.StringProperty()

    @classmethod
    def by_post(cls, post):
        key = db.GqlQuery('select * from Comments where post = :1 order by created desc', post)
        return key

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    def render(self):
        self._render_text = self.comment.replace('\n', '<br>')
        return render_str('comments.html', c = self)

class Likes(db.Model):
    post = db.ReferenceProperty(Post, required=True)
    user = db.ReferenceProperty(User, required=True)

    @classmethod
    def by_post(cls, post):
        key = db.GqlQuery('select * from Likes where post = :1', post)
        return key

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def liked(cls, post, user):
        key = db.GqlQuery('select * from Likes where post = :1 and user = :2', post,user)
        return key

    @classmethod
    def find(cls, post, user):
        key = db.GqlQuery('select * from Likes where post = :1 and user = :2', post,user)
        return key.get()

    def render(self):
        return render_str('Likes.html', c = self)

# Main Page
class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = db.GqlQuery("select * from Post order by created desc")
        self.render('front.html', posts = posts)

# Recently Posted Blog
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        comments = Comments.by_post(post)
        likes = Likes.by_post(post)
        if self.user:
            liked = Likes.liked(post,self.user).count()
        else:
            liked = 0;
        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked)

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        comments = Comments.by_post(post)
        likes = Likes.by_post(post)
        liked = Likes.liked(post,self.user).count()
        if self.user:
            if self.request.get('delete'):
                if post.author_id == str(self.user.key().id()):
                    post.delete()
                    time.sleep(0.5)
                    self.redirect('/blog/')
                else:
                    error = "You don't have permission to delete this post"
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked, error = error)

            if self.request.get('edit'):
                if post.author_id == str(self.user.key().id()):
                    self.redirect('/blog/editpost/%s' %str(post.key().id()))
                else:
                    error = "You don't have permission to edit this post"
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked, error = error)

            if self.request.get('comment'):
                comment_text = self.request.get('comment_text')
                if comment_text:
                    comment = Comments(post = post,
                                       user = User.by_id(self.user.key().id()),
                                       comment = comment_text,
                                       likes = likes,
                                       liked = liked,
                                       author_id = str(self.user.key().id()))
                    comment.put()
                    time.sleep(0.5)
                    self.redirect('/blog/%s' %str(post.key().id()))
                else:
                    comment_error = "Comment cannot be empty."
                    self.render("permalink.html", post = post,
                                 comments = comments,
                                 likes = likes,
                                 liked = liked,
                                 comment_error = comment_error)

            if self.request.get('delete_comment'):
                comment_id = self.request.get('delete_comment_id')
                comment = Comments.by_id(int(comment_id))
                if comment.author_id == str(self.user.key().id()):
                    comment.delete()
                    time.sleep(0.5)
                    self.redirect('/blog/%s' %str(post.key().id()))
                else:
                    comment_error = "You don't have permission to delete this comment"
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked, comment_error = comment_error)

            if self.request.get('edit_comment'):
                comment_id = self.request.get('comment_id')
                comment = Comments.by_id(int(comment_id))
                if comment.author_id == str(self.user.key().id()):
                    comment.comment = self.request.get('new_comment')
                    comment.put()
                    time.sleep(0.5)
                    self.redirect('/blog/%s' %str(post.key().id()))
                else:
                    comment_error = "You don't have permission to edit this comment"
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked, comment_error = comment_error)

            if self.request.get('like'):
                if not Likes.liked(post,self.user).count():
                    l = Likes(post = post, user = self.user)
                    l.put()
                    time.sleep(0.3)
                    self.redirect('/blog/%s' %str(post.key().id()))
                else:
                    error = "Already Liked"
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked, error = error)

            if self.request.get('unlike'):
                like = Likes.liked(post,self.user)
                if like.count():
                    like.get().delete()
                    time.sleep(0.2)
                    self.redirect('/blog/%s' %str(post.key().id()))
                else:
                    self.render("permalink.html", post = post, comments = comments, likes = likes, liked = liked)
        else:
            self.redirect('/blog/login')

# Post New Blog
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", heading = "New Post")
        else:
            self.redirect("/blog/login")

    def post(self):
        if self.user:
            if self.request.get('cancel'):
                self.redirect('/blog/')

            if self.request.get('post'):
                subject = self.request.get('subject')
                content = self.request.get('content')
                if subject and content:
                    p = Post(subject = subject, content = content, author_id = str(self.user.key().id()))
                    p.put()
                    self.redirect('/blog/%s' % str(p.key().id()))
                else:
                    error = "subject and content, please!"
                    self.render("newpost.html", heading = "New Post",subject=subject, content=content, error=error)
        else:
            self.redirect('/blog/login')

#Edit Post
class EditPost(BlogHandler):
    def get(self, post_id):
        if not self.user:
            self.redirect("/blog/login")

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        subject = post.subject
        content = post.content
        self.render("newpost.html", heading = "Edit Post", subject = subject, content = content)

    def post(self, post_id):

        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if self.user:
            if self.request.get('cancel'):
                self.redirect('/blog/%s' % str(post.key().id()))
            if self.request.get('post'):
                if post.author_id == str(self.user.key().id()):
                    subject = self.request.get('subject')
                    content = self.request.get('content')
                    if subject and content:
                        post.subject = subject
                        post.content = content
                        post.put()
                        time.sleep(1)
                        self.redirect('/blog/%s' % str(post.key().id()))
                    else:
                        error = "subject and content, please!"
                        self.render("newpost.html", heading = "New Post",subject=subject, content=content, error=error)
                else:
                    self.redirect('/blog/%s' % str(post.key().id()))
        else:
            self.redirect('/blog/login')

class Comment:
    def get(self,post_id):
        self.redirect('/blog')

##### Sign Up

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Signup(BlogHandler):
    def get(self):
        self.render("signup.html")
    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")
        have_error = False
        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True
        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup.html",**params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Sign_up(Signup):
    def done(self):
        self.redirect('/unit2/welcome?username=' + self.username)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')


class Welcome(BlogHandler):
    def get(self):
        username = self.request.get("username")
        if valid_username(username):
            self.render('welcome.html', username = username)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/blog/?', BlogFront),
                               ('/blog/welcome', Welcome),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/signup', Register),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout),
                               ('/blog/editpost/([0-9]+)', EditPost),
                               ('/blog/comment/([0-9]+)',Comment),
                               ],
                              debug=True)