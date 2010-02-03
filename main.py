import os
import re

import wsgiref.handlers

from google.appengine.ext import webapp
from django.utils import simplejson

from BeautifulSoup import BeautifulSoup
import urllib2

import oauth.consumer
import oauth.db.appengine
import config
import model

callback = "http://%s/twitter/callback" % os.environ['HTTP_HOST']
twitter = oauth.consumer.Twitter(config.twitter.CONSUMER_KEY, config.twitter.CONSUMER_SECRET, callback, db=oauth.db.appengine)

callback = "http://%s/yahoo/callback" % os.environ['HTTP_HOST']
yahoo = oauth.consumer.Yahoo(config.yahoo.CONSUMER_KEY, config.yahoo.CONSUMER_SECRET, callback, db=oauth.db.appengine)

callback = "http://%s/google/callback" % os.environ['HTTP_HOST']
google = oauth.consumer.Google(config.google.CONSUMER_KEY, config.google.CONSUMER_SECRET, callback, db=oauth.db.appengine, scope="http://www-opensocial.googleusercontent.com/api/people/")

class MainHandler(webapp.RequestHandler):

    def get(self):
        r = '<html><head><meta name="google-site-verification" content="FwxmHGqAai6mpX3d-gZB2DidmXlJJ1tbVzh9e31lzso" /></head><body><form action="relmeauth">Sign In:<input name="url"/><input type="submit"></form>'
        self.response.out.write(r)

def checkBacklink(href, url):
    page = urllib2.urlopen(href).read()
    soup = BeautifulSoup(page)
    othermes = soup.findAll(rel=re.compile(r'\bme\b'))
    for otherme in othermes :
        if otherme['href'] == url :
            return True
    return False

def getRelMe(url):
    builtins = (
        ('twitter.com', twitter, '/twitter'), 
#        ('yahoo.com', yahoo, '/yahoo'),
        ('google.com', google, '/google'),
    )
    for prefix, app, endpoint in builtins:
        if prefix in url:
            return endpoint
    
    page = urllib2.urlopen(url).read()
    soup = BeautifulSoup(page)
    mes = soup.findAll(rel=re.compile(r'\bme\b'))
    for me in mes :
        href = me['href']
        for prefix, app, endpoint in builtins:
            if prefix in href:
                if checkBacklink(href, url):
                    return endpoint, href
    return False

class RelMeAuth(webapp.RequestHandler):
    def get(self):
        url = self.request.get('url')
        endpoint, href = getRelMe(url)
        if endpoint:
            session = model.Session(url=url)
            session.put()
            self.response.headers.add_header(
                'Set-Cookie',
                'session=%s; expires=Fri, 31-Dec-2038 23:59:59 GMT' \
                    % session.key().id())

            self.redirect(endpoint)
            return

        self.response.out.write('Please put a rel="me" on your page to your twitter, yahoo, or google acount')

class TwitterHandler(webapp.RequestHandler):

    def get(self):
        user, url = twitter.start()
        self.redirect(url)
        self.response.headers.add_header(
            'Set-Cookie',
            'twitter=%s; expires=Fri, 31-Dec-2038 23:59:59 GMT' \
                % user.get_key().encode())

class TwitterCallbackHandler(webapp.RequestHandler):

    def get(self):
        token = self.request.get("oauth_token")
        verifier = self.request.get("oauth_verifier", None)
        user = self.request.cookies.get("twitter")
        twitter.verify(user, token, verifier)
        session_id = int(self.request.cookies.get("session"))
        session = model.Session.get_by_id(session_id)
        if not session.url.startswith("http://twitter.com"):
            result = twitter.fetch("http://twitter.com/account/verify_credentials.json", user).read()
            url = simplejson.loads(result)['url']
            if url != session.url :
                self.response.out.write("EVIL HACKER %s != %s" % (url, session.url))
                return

        self.redirect("/test")

class YahooHandler(webapp.RequestHandler):

    def get(self):
        user, url = yahoo.start()
        self.redirect(url)
        self.response.headers.add_header(
            'Set-Cookie',
            'yahoo=%s; expires=Fri, 31-Dec-2038 23:59:59 GMT' \
                % user.get_key().encode())

class YahooCallbackHandler(webapp.RequestHandler):

    def get(self):
        token = self.request.get("oauth_token")
        verifier = self.request.get("oauth_verifier", None)
        user = self.request.cookies.get("yahoo")
        yahoo.verify(user, token, verifier)
        self.redirect("/test")

class GoogleHandler(webapp.RequestHandler):

    def get(self):
        user, url = google.start()
        self.redirect(url)
        self.response.headers.add_header(
            'Set-Cookie',
            'google=%s; expires=Fri, 31-Dec-2038 23:59:59 GMT' \
                % user.get_key().encode())


class GoogleCallbackHandler(webapp.RequestHandler):

    def get(self):
        token = self.request.get("oauth_token")
        verifier = self.request.get("oauth_verifier", None)
        user = self.request.cookies.get("google")
        google.verify(user, token, verifier)
        session_id = int(self.request.cookies.get("session"))
        session = model.Session.get_by_id(session_id)
        if not session.url.startswith("http://www.google.com"):
            result = google.fetch("http://www-opensocial.googleusercontent.com/api/people/@me", user).read()
            gid = simplejson.loads(result)['entry']['id']
            url = "http://www.gogole.com/profiles/" + gid
            try: 
                fetched = urllib2.urlopen(url)
            except urllib2.HTTPError:
                self.response.out.write("EVIL HACKER No profile @ %s" % (url))
                return
                
            url = fetched.geturl()
            if url != getRelMe(session.url)[1] :
                self.response.out.write("EVIL HACKER %s != %s" % (url, getRelMe(session.url)[1]))
                return
        self.redirect("/test")


class TestHandler(webapp.RequestHandler):

    def get(self):
        session_id = int(self.request.cookies.get("session"))
        session = model.Session.get_by_id(session_id)
        self.response.out.write("You are " + session.url)


def main():
    application = webapp.WSGIApplication([
                                        ('/', MainHandler),
                                        ('/relmeauth', RelMeAuth),
                                        ('/twitter', TwitterHandler),
                                        ('/twitter/callback', TwitterCallbackHandler),
                                        ('/yahoo', YahooHandler),
                                        ('/yahoo/callback', YahooCallbackHandler),
                                        ('/google', GoogleHandler),
                                        ('/google/callback', GoogleCallbackHandler),
                                        ('/test', TestHandler),
                                       ],
                                       debug=True)
    wsgiref.handlers.CGIHandler().run(application)


if __name__ == '__main__':
    main()
