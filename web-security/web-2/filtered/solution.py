import requests
from bs4 import BeautifulSoup

URL  = 'http://filtered.challs.cyberchallenge.it/post.php?id=1'


response = requests.get(URL + '1')

