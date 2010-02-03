from google.appengine.ext import db
class Session(db.Model):
    """Auth Token.

       Implemented on Appengine DB, but could be stored anywhere that you have available.
       Just implement all the methods in another data store of your choice
    """
    url = db.TextProperty(required=True)
