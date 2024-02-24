#!/usr/bin/python3
import requests


server = requests.get('http://127.0.0.1:80/f3185303e9fff83e392569a749c1e634')
print(server.text)