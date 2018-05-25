#!/usr/bin/env python
# -*- coding: utf-8 -*- 

from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
api = Api(app)
app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://ro:00Vesper!!@localhost/mantapp_db'
db = SQLAlchemy(app)

parser = reqparse.RequestParser()

# Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    admin = db.Column(db.Boolean)

class Machine(db.Model):
   id = db.Column('machine_id', db.Integer, primary_key = True)
   model = db.Column(db.String(100))
   brand = db.Column(db.String(50))
   year = db.Column(db.String(200))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
      token = None

      if 'x-access-token' in request.headers:
          token = request.headers['x-access-token']

      if not token:
          return jsonify({'message' : 'Token is missing!'})

      try: 
          data = jwt.decode(token, app.config['SECRET_KEY'])
          current_user = User.query.filter_by(public_id=data['public_id']).first()
      except:
          return jsonify({'message' : 'Token is invalid!'})

      return f(current_user, *args, **kwargs)

    return decorated 
 
# ------------------------
class Register(Resource):
  def post(self):
    parser.add_argument('name', required=True, help="Debes ingresar tu nombre.")
    parser.add_argument('email', required = True, help='Ingresar tu email es obligatorio.')
    parser.add_argument('password', required = True, help='Establecer tu contraseña es obligatorio.')
    parser.add_argument('admin', type=bool, default=False)
    data = parser.parse_args()
    hashed_password = generate_password_hash(data['password'], method='sha256')
    check_mail = User.query.filter_by(email=data['email']).first()

    if not check_mail:
      new_user = User(public_id=str(uuid.uuid4()), email=data['email'], name=data['name'], password=hashed_password, admin=data['admin'])
      db.session.add(new_user)
      db.session.commit()
      return jsonify({'message' : 'Bienvenid@ ' + data['name']})
    else:
      return jsonify({'message' : 'Ya existe usuario registrado. Haz Login.'})


class Login(Resource):
  def post(self):
    parser.add_argument('username')
    parser.add_argument('password')
    auth = parser.parse_args()

    if not auth.username or not auth.password:
      return make_response(jsonify({'Could not verify auth' : "Login required!" }),401)

    user = User.query.filter_by(email=auth.username).first()

    if not user:
      return make_response(jsonify({"message" : "Usuario no existe..."}),401)

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response(jsonify({'Could not verify user' : {'WWW-Authenticate' : 'Basic realm="Login required!"'}}),401)

class GetUsers(Resource):
    @token_required
    def get(self, current_user):
      print str(current_user.admin)
     
      users = User.query.all()

      output = []

      for user in users:
          user_data = {}
          user_data['public_id'] = user.public_id
          user_data['name'] = user.name
          user_data['email'] = user.email
          user_data['password'] = user.password
          user_data['admin'] = user.admin
          output.append(user_data)

      return jsonify({'users' : output})
          
    

class GetMachines(Resource):
    @token_required
    def get(self, current_user):
      machines = Machine.query.all()
      if len(machines) == 0:
          return jsonify({"message": "No hay ninguna máquina registrada"})

      output = []

      for machine in machines:
          machine_data = {}
          machine_data['id'] = machine.id
          machine_data['model'] = machine.model
          machine_data['brand'] = machine.brand
          machine_data['year'] = machine.year
          output.append(machine_data)

      return jsonify({'machines' : output})

    def post(self):
      parser.add_argument('model', required = True, help='Ingresa el modelo. Es obligatoria.')
      parser.add_argument('brand', required = True, help='Ingresa la marca. Es obligatoria.')
      parser.add_argument('year', required = True, type=int, help='El año debe de ser numérico, y es obligatorio.')
      data = parser.parse_args()

      new_machine = Machine(model=data['model'], brand=data['brand'], year=data['year'])
      db.session.add(new_machine)
      db.session.commit()
      return jsonify({'message' : 'Máquina agregada!'})


      
    
class GetMachine(Resource):
    @token_required
    def get(self,current_user,machine_id):
        machine = Machine.query.filter_by(id=machine_id).first()
        
        if machine:
          machine_data = {}
          machine_data['id'] = machine.id
          machine_data['model'] = machine.model
          machine_data['brand'] = machine.brand
          machine_data['year'] = machine.year
          return jsonify(machine_data)
        else:
          return jsonify({"message" : "No encontramos esa máquina!"})

    def put(self, machine_id):
      parser.add_argument('model', required = True, help='Ingresa el modelo. Es obligatoria.')
      parser.add_argument('brand', required = True, help='Ingresa la marca. Es obligatoria.')
      parser.add_argument('year', required = True, type=int, help='El año debe de ser numérico, y es obligatorio.')
      data = parser.parse_args()
      machine = Machine.query.filter_by(id=machine_id).first()
      
      if not machine:
        return jsonify({'message' : 'No encontramos esa máquina!'})
      else:
          machine.model = data['model']
          machine.brand = data['brand']
          machine.year = data['year']
          db.session.commit()
          return jsonify({"message" : "Máquina actualizada"})
      
    def delete(self, machine_id):
      data = request.get_json()
      machine = Machine.query.filter_by(id=machine_id).first()
      if not machine:
        return jsonify({'message' : 'No encontramos esa máquina!'})
      else:
        db.session.delete(machine)
        db.session.commit()
      return jsonify({'message' : 'Máquina borrada!'})


            



# ------------------------

# Endpoints
api.add_resource(Login, '/login')
api.add_resource(Register, '/register')
api.add_resource(GetUsers, '/users')
api.add_resource(GetMachines, '/')
api.add_resource(GetMachine, '/<string:machine_id>')
# ------------------------

if __name__ == "__main__":
    app.run(debug=True)



