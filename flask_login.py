from flask import Flask, request
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import re 

import pymongo
from datetime import datetime, timedelta
from functools import wraps
import config

application = Flask(__name__)
conn = pymongo.MongoClient(config.MONGO_ADDR)
db = conn[config.MONGO_AUTH]


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return 'Unauthorized Access!', 401

        try:
            data = jwt.decode(token, config.SECRET_KEY)
            current_user = db['users'].find_one({'user_id': data['user_id']})
            if not current_user:
                return 'Unauthorized Access!', 401
        except:
            return 'Unauthorized Access!', 401
        return f(*args, **kwargs)

    return decorated


@application.route('/test', methods=['GET'])
@token_required
def test():
    return "Authorized"


@application.route('/login', methods=['POST'])
def login():
    response = {
        "success" : False,
        "message" : "Invalid parameters",
        "token" : ""
    }
    try:
        auth = request.form

        if not auth or not auth.get('email') or not auth.get('password'):
            response["message"] = 'Invalid data'
            return response, 422

        user = db['users'].find_one({'email': auth['email']})

        if not user:
            response["message"] = "Unauthorized Access!"
            return response, 401

        if check_password_hash(user['password'], auth['password']):
            token = jwt.encode({
                'user_id': user['user_id'],
                'exp': datetime.utcnow() + timedelta(minutes=30)
            }, config.SECRET_KEY)
            response["message"] = "token generated"
            response["token"] = token.decode('UTF-8')
            response["success"] = True
            return response, 200
        response["message"] = 'Invalid emailid or password'
        return response, 403
    except Exception as ex:
        print(str(ex))
        return response, 422

@application.route('/signup', methods=['POST'])
def signup():
    response = {
        "success" : False,
        "message" : "Invalid parameters"
    }
    try:
        data = request.form
        name, email = data.get('name'), data.get('email')
        password = data.get('password')
        if name == None or email == None  or password == None:
            return response, 202
        if check_email(email) == False:
            response["message"] = "Invalid email id"
            return response, 202
        if check_password(password) == False:
            response["message"] = "Password requirement not fullfilled"
            return response, 202
        user = db['users'].find_one({'email': email})
        if not user:
            db['users'].insert_one({'user_id': str(uuid.uuid4()), 'user_name': name,
                                    'email': email, 'password': generate_password_hash(password)})
            response["success"] = True
            response["message"] = 'Successfully registered'
            return response, 200
        else:
            response["message"] = 'User already exists. Please Log in'
            return response, 202
    except Exception as ex:
        print(str(ex))
        return response, 422



## Utils
def check_email(email):  
    if(re.search(config.EMAIL_REGEX,email)):  
        return True  
    else:  
        return False 

def check_password(password):
    if len(password) >= 6 and len(password) <= 20 and any(char.isdigit() for char in password) \
        and any(char.isupper() for char in password) and any(char.islower() for char in password):
        return True
    else:
        return False
        
if __name__ == "__main__":
    application.run(host='0.0.0.0', port=1234)