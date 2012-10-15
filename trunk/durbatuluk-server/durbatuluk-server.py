#
# Durbatuluk is Copyright (c) 2012 Joel Odom
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import webapp2
import re
from google.appengine.ext import db
import datetime

class Command(db.Model):
  content = db.TextProperty()
  datetime = db.DateTimeProperty(auto_now_add = True)

class MainPage(webapp2.RequestHandler):
  def get(self):
    self.response.out.write('<html><body><form action="/post" method="post">'
      '<div><textarea name="command" rows="20" cols="60"></textarea></div>'
      '<div><input type="submit" value="Add Command"></div>'
      '</form></body></html>')

class CommandPost(webapp2.RequestHandler):
  def get(self):
    self.redirect('/')

  def post(self):
    # validate the command
    content = self.request.get('command')
    if not re.match('<durbatuluk>[A-Za-z0-9\+\/]+</durbatuluk>$', content):
      # refuse this command
      self.error(403)
      return

    # save the command
    command = Command()
    command.content = content
    command.put()

class CommandLog(webapp2.RequestHandler):
  def get(self):
    self.response.headers['Content-Type'] = 'text/plain'

    # fetch all commands posted within the last five minutes
    commands = db.GqlQuery("SELECT * FROM Command WHERE datetime > :cutoff",
      cutoff = datetime.datetime.now() + datetime.timedelta(minutes = -5))
    for command in commands:
      self.response.write(command.content)

app = webapp2.WSGIApplication([
  ('/', MainPage),
  ('/log', CommandLog),
  ('/post', CommandPost),
  ], debug=True)
