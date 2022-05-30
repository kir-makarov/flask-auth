from gevent import monkey
from gevent.pywsgi import WSGIServer
from app import app, create_app

monkey.patch_all()

http_server = WSGIServer(("", 5000), create_app(app))
http_server.serve_forever()
