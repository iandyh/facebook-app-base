import os
import tornado.auth
import tornado.ioloop
import tornado.web
import tornado.httpserver
import urllib2

from mako.template import Template
from mako.lookup import TemplateLookup
from tornado.options import define, options
from tornado import escape

define('port', default=9001)
define('facebook_api_key', default='')
define('facebook_secret', default='')
define('redirect_url', default='http://localhost:9001/auth')

class Application(tornado.web.Application):
    def __init__(self):
        handlers = [
           (r'/', MainHandler),
           (r'/start', RedirectHandler),
           (r'/auth', AuthHandler),
        ]
        settings = dict(
            facebook_api_key=options.facebook_api_key,
            facebook_secret=options.facebook_secret,
            redirect_url=options.redirect_url,
        )
        tornado.web.Application.__init__(self, handlers, **settings)
        
class BaseHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    def render(self, t_name, **kwargs):
        template = Template(filename=t_name)
        self.write(template.render(**kwargs))

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")

class RedirectHandler(BaseHandler):
    def post(self):
        extra_params=dict(
            scope='user_likes',
            state=os.urandom(10)
        )
        self.authorize_redirect(redirect_uri=self.settings['redirect_url'], 
        client_id=self.settings['facebook_api_key'],
        extra_params=extra_params)

class AuthHandler(BaseHandler):
    def get(self):
        code = self.get_argument('code', False)
        if code:
            token_url = self._oauth_request_token_url(
                redirect_uri=self.settings['redirect_url'],
                client_id=self.settings['facebook_api_key'],
                client_secret=self.settings['facebook_secret'],
                code=code,
            )
            req = urllib2.Request(token_url)
            response = urllib2.urlopen(req)
            args = escape.parse_qs_bytes(escape.native_str(response.read()))
            access_token = args['access_token'][-1]
        
def main():
    tornado.options.parse_command_line()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()
    
if __name__ == '__main__':
    main()
    
        