from fastapi import FastAPI, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi_login import LoginManager #Loginmanager Class
from fastapi_login.exceptions import InvalidCredentialsException #Exception class
from fastapi.responses import JSONResponse,HTMLResponse
from pydantic import BaseModel
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, long_to_bytes
import storage
import os
import requests
import hashlib
import random


dispatcher_url = 'http://10.10.0.1:8123'


class GameModel(BaseModel):

    tower1: list
    tower2: list
    initialization_secret: str
    first_prize: str
    partial_prize: str


class PlayModel(BaseModel):

    id: str
    moves: list


class UserModel(BaseModel):

    username: str
    password: str
    info: str

class UserLogin(BaseModel):

    username: str
    password: str

class TicketsModel(BaseModel):
    id: str
    public: str
    tickets: list
    signature: str


class MergeModel(BaseModel):
    id: str
    public: str
    partial_p: tuple


class Game:

    def __init__(self, s1, s2): 

        assert len(s1) == len(s2)
        assert len(s1) >= 2
        self.s1 = s1
        self.s2 = s2
        self.len = len(s1)
        self.player1_idx = 0
        self.player2_idx = 0

    def play_move(self, move):

        if move not in [0, 1]:
            return None
        if self.s1[self.player1_idx] == move:
            self.player1_idx += 1
        if self.s2[self.player2_idx] == move:
            self.player2_idx += 1

        if self.player1_idx == self.len or self.player2_idx == self.len:
            return self.lose()

        if self.player1_idx == self.player2_idx == self.len - 1:
            return self.win()

        return None

    def win(self):

         return 0, "You won!"

    def lose(self):

        return 1, "You lost :("


class TokenEmitter:

    def __init__(self, key):

        assert len(key) == 16
        self.key = key
    
    def _xor(self, a, b):

        assert len(a) == len(b)
        return bytes([x ^ y for x, y in zip(a, b)])

    def sign(self, tickets):

        sig = self.key
        for ticket in tickets:
            ticket = bytes.fromhex(ticket)
            assert len(ticket) == 16
            c = AES.new(sig, AES.MODE_ECB)
            sig = c.encrypt(ticket)
        return sig.hex()
    
    def verify(self, tickets, sig):

        s = self.sign(tickets)
        print(s, sig)
        return s == sig


class SecretGenerator:

    def __init__(self, key):

        random.seed(key)
        self.p = getPrime(128, random.randbytes)
        self.q = getPrime(128, random.randbytes)
        self.r = getPrime(128, random.randbytes)
        self.s = random.getrandbits(128*3) % (self.p*self.q*self.r)

    def get_partial(self, selector):

        if selector == 'p':
            return self.s % self.p, self.p

        if selector == 'q':
            return self.s % self.q, self.q

        if selector == 'r':
            return self.s % self.r, self.r
        
        return None

    def build_from_partial(self, s, p):

        assert len(s) == len(p) == 3

        res = []
        n = p[0] * p[1] * p[2]
        
        for i in range(3):
            x = n // p[i]
            res.append(s[i] * pow(x, -1, p[i]) * x)
        return sum(res) % n

SECRET = os.urandom(16)

manager = LoginManager(SECRET, token_url="/login", use_cookie=True)
manager.cookie_name = "some-name"

app = FastAPI()

origins = [
    "*",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@manager.user_loader()
def load_user(username):
    return {"username": username}

@app.post("/games")
def post_game(game: GameModel, user = Depends(manager)):
    l1 = len(game.tower1)
    l2 = len(game.tower2)

    if not ((2 <= l1 <= 500) and (2 <= l2 <= 500) and l1 == l2):
        return {"error": "incorrect length"}
    
    if any([c not in [0, 1] for c in game.tower1 + game.tower2]):
        return {"error": "invalid character detected"}
    
    if game.tower1[-1] != game.tower2[-1]:
        return {"error": "incorrect configuration"}

    try:
        initialization_secret = bytes.fromhex(game.initialization_secret)
    except:
        return {"error": "incorrect initialization_secret"}

    if len(initialization_secret) != 32:
        return {"error": "incorrect initialization_secret"}

    tower1 = [True if x else False for x in game.tower1]
    tower2 = [True if x else False for x in game.tower2]

    id = requests.post(f'{dispatcher_url}/games').json()
    storage.game_create(id, initialization_secret, tower1, tower2, game.partial_prize, game.first_prize)
    
    return {"id": id}


@app.get("/games/{gameid}")
def get_game(gameid):

    game = storage.game_load(gameid)

    if game[0] is None:
        return {"error": "no such game"}

    return {
        "id": gameid,
        "tower1": game[1],
        "tower2": game[2],
        }


@app.post("/games/play")
def play_game(play: PlayModel):

    if any([m not in [0, 1] for m in play.moves]):
        return {"error": "invalid move detected"}

    loaded_game = storage.game_load(play.id)

    if loaded_game[0] is None:
        return {"error": "no such game"}

    if len(play.moves) == 0:
        return {"error": "invalid moves length"}

    game = Game(loaded_game[1], loaded_game[2])

    public = os.urandom(20)
    key = hashlib.sha256(loaded_game[0] + public).digest()[:16]

    emitter = TokenEmitter(key)
    tickets = [os.urandom(16).hex() for _ in range(3)]

    signature0 = emitter.sign([tickets[0]])
    signature1 = emitter.sign([tickets[1]])
    signature2 = emitter.sign([tickets[2]])
    signature  = emitter.sign(tickets)

    sg = SecretGenerator(key)

    pp = sg.get_partial('p')
    pq = sg.get_partial('q')
    pr = sg.get_partial('r')

    secret = sg.build_from_partial([_[0] for _ in [pp, pq, pr]], [_[1] for _ in [pp, pq, pr]])

    req_data = {
        'public': public.hex(),
        'secret': str(secret),
        'tickets': tickets,
        'sign0':  signature0,
        'sign1':  signature1,
        'sign2':  signature2,
        'sign': signature
        }
    requests.post(f'{dispatcher_url}/games/{play.id}', json=req_data).json()
    
    public = public.hex()

    for m in play.moves:
        r = game.play_move(m)
        if r is not None:
            if r[0] == 1:
                return {"public": public, "result": r[1]}

            partial_p = sg.get_partial('p')
            partial_q = sg.get_partial('q') # forwarding to gabibbo1...
            partial_r = sg.get_partial('r') # forwarding to gabibbo2...

            return {"public": public, "partial_p": [str(_) for _ in partial_p], "result": r[1]}
            
    return {"public": public, "partial": "", "result": game.lose()[1]}


@app.post("/games/merge")
def merge_partials(merge: MergeModel):

    loaded_game = storage.game_load(merge.id)

    if loaded_game[0] is None:
        return {"error": "no such game"}

    j = requests.get(f'{dispatcher_url}/{merge.id}/{merge.public}').json()
    if "error" in j:
        return j
    
    key = hashlib.sha256(loaded_game[0] + bytes.fromhex(merge.public)).digest()[:16]
    partial_p = [int(_) for _ in merge.partial_p]
    partial_q = SecretGenerator(key).get_partial('q') # reading from the gabibbo1...
    partial_r = SecretGenerator(key).get_partial('r') # reading from the gabibbo2...

    _s = [partial[0] for partial in (partial_p, partial_q, partial_r)]
    _p = [partial[1] for partial in (partial_p, partial_q, partial_r)]

    s = SecretGenerator(key).build_from_partial(_s, _p)

    requests.post(f'{dispatcher_url}/games/{merge.id}/{merge.public}/redeem', json={"secret": str(s), "amount": 1}) # gabibbo1 getting his tickets...
    requests.post(f'{dispatcher_url}/games/{merge.id}/{merge.public}/redeem', json={"secret": str(s), "amount": 1}) # gabibbo2 getting his tickets...

    return {"secret": str(s), "module": str(_p[0]*_p[1]*_p[2])}


@app.post("/games/redeem")
def redeem(tickets: TicketsModel):

    loaded_game = storage.game_load(tickets.id)

    if loaded_game[0] is None:
        return {"error": "no such game"}

    public = bytes.fromhex(tickets.public)
    key = hashlib.sha256(loaded_game[0] + public).digest()[:16]
    emitter = TokenEmitter(key)

    if emitter.verify(tickets.tickets, tickets.signature):
        if len(tickets.tickets) == 1:
            return {"prize": loaded_game[3]}
        elif len(tickets.tickets) == 3:
            return {"prize": loaded_game[4]}


    return {"prize": "what did you expect? you are so poor"}


@app.post("/register")
def register(user: UserModel):
    res = storage.user_create(user.username, user.password, user.info)
    if res:
        return {"result": "success"}
    else:
        return {"error": "user already exists"}

@app.post("/login")
def login(user: UserLogin):
    info = storage.user_auth(user.username, user.password)
    if info == None:
        raise InvalidCredentialsException
    access_token = manager.create_access_token(
    data={"sub":user.username}
    )
    resp = JSONResponse(content={"info": info, "username": user.username})
    manager.set_cookie(resp,access_token)
    return resp
