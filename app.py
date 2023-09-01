# Importar las librerías necesarias
from functools import wraps
from flask import Flask, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_restx import Api, Resource, fields
from static import key
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from sqlalchemy.orm import Mapped
from sqlalchemy import Column, Integer, String, Float, BigInteger, Boolean, JSON
import json
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import string
from werkzeug.datastructures import FileStorage
import pandas as pd
from sqlalchemy import create_engine, text
import boto3
from botocore.exceptions import NoCredentialsError
from botocore.config import Config
import datetime
import pytz
import calendar
import time
import numpy as np
import uuid
import os
import requests
from datetime import date
import re

# Configurar el cliente de S3 para utilizar el esquema de autenticación AWS4-HMAC-SHA256
config = Config(signature_version='s3v4')

# Credenciales de AWS
aws_access_key_id = 'AKIA43VL5D2VLM52USWP'
aws_secret_access_key = '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'

# Conectarse a S3
session = boto3.Session(
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

s3 = session.client('s3', region_name='us-east-2', config=config)

# Nombre del bucket de S3
bucket_name = 'products-msl-nivea'


# Crear la aplicación Flask
app = Flask(__name__)
CORS(app)

# Configurar la URI de la base de datos PostgreSQL
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:postgres@food-chains.cvc6fic9cofz.us-east-1.rds.amazonaws.com:5432/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
engine = create_engine('postgresql://postgres:postgres@food-chains.cvc6fic9cofz.us-east-1.rds.amazonaws.com:5432/postgres')
connection = engine.connect()

# Configuracion Local
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:jacm1212@localhost:5432/foodChains'
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# engine = create_engine('postgresql://postgres:jacm1212@localhost:5432/foodChains')
# connection = engine.connect()


# Crear el objeto SQLAlchemy
db = SQLAlchemy(app)

# Crear el objeto Marshmallow
ma = Marshmallow(app)

# Configurar la clave secreta para la aplicación y el jwt
app.secret_key = key.SECRET_KEY
jwt_secret_key = key.SECRET_KEY

# Crear el gestor de login
login_manager = LoginManager()
login_manager.init_app(app)


# Crear una instancia de la clase Api
api = Api(app, version="1.0", title="API FOOD CHAINS", description="FOOD CHAINS API REST FOR APP ")

################
### MODELOS ###
###############

user_model_login_register = api.model("User ", {
    "username": fields.String(description="El nombre de usuario"),
    "name": fields.String(description="El nombre "),
    "profile": fields.String(description="Tipo de perfil de usuario "),
    "phone": fields.String(description="Telefono del usuario")
})

user_login = api.model("User login", {
    "username": fields.String(description="El nombre de usuario"),
    "password": fields.String(description="La contraseña del usuario")
})

user_model_update_password = api.model("User", {
    "id": fields.String(description="ID del usuarios a actualizar "),
})

token_model = api.model("Token", {
    "token": fields.String(description="El token generado para el usuario")
})

update_info_user = api.model("Personalizacion_de_usuarios", {
    "id": fields.String(description=""),
    "name": fields.String(description=""),
    "username": fields.String(description=""),
    "phome": fields.String(description=""),
})

update_password_user = api.model("Personalizacion_de_contrasenia_de_usuarios", {
    "id": fields.String(description=""),
    "oldPassword": fields.String(description=""),
    "newPassword": fields.String(description=""),
})

user_model_update = api.model("User update", {
    "id": fields.String(description="El id de usuario"),
    "name": fields.String(description="El nombre"),
    "username": fields.String(description="El nombre de usuario"),
    "profile": fields.String(description="Tipo de perfil de usuario "),
    "phone": fields.String(description="Telefono del usuario")
})

class PedidosTemp(db.Model):
    __tablename__ = "pedidos_temp"
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CNPJ_DISTRIBUIDOR = db.Column(db.String)
    DISTRIBUIOR = db.Column(db.String)
    CNPJ_CLIENTE = db.Column(db.String)
    CLIENTE = db.Column(db.String)
    PEDIDO = db.Column(db.String)
    STATUS_PEDIDO = db.Column(db.String)
    ENVIO = db.Column(db.String)
    CONFIRMACAO = db.Column(db.String)
    FINAL = db.Column(db.String)
    SKU = db.Column(db.String)
    QUANTIDADE = db.Column(db.String)
    NOME_PRODUTO = db.Column(db.String)
    PRECO_UNITARIO = db.Column(db.String)
    TOTAL = db.Column(db.String)
    FORMA_PAGAMENTO = db.Column(db.String)

    def __init__(self, ID, CNPJ_DISTRIBUIDOR, DISTRIBUIOR, CNPJ_CLIENTE, CLIENTE, PEDIDO,
                 STATUS_PEDIDO, ENVIO, CONFIRMACAO, FINAL, SKU, QUANTIDADE, NOME_PRODUTO,
                 PRECO_UNITARIO, TOTAL, FORMA_PAGAMENTO):
        self.ID = ID
        self.CNPJ_DISTRIBUIDOR = CNPJ_DISTRIBUIDOR
        self.DISTRIBUIOR = DISTRIBUIOR
        self.CNPJ_CLIENTE = CNPJ_CLIENTE
        self.CLIENTE = CLIENTE
        self.PEDIDO = PEDIDO
        self.STATUS_PEDIDO = STATUS_PEDIDO
        self.ENVIO = ENVIO
        self.CONFIRMACAO = CONFIRMACAO
        self.FINAL = FINAL
        self.SKU = SKU
        self.QUANTIDADE = QUANTIDADE
        self.NOME_PRODUTO = NOME_PRODUTO
        self.PRECO_UNITARIO = PRECO_UNITARIO,
        self.TOTAL = TOTAL
        self.FORMA_PAGAMENTO = FORMA_PAGAMENTO

class PedidosLog(db.Model):
    __tablename__ = "pedidos_log"
    ID = db.Column(db.Integer, primary_key=True, autoincrement=True)
    CNPJ_DISTRIBUIDOR = db.Column(db.String)
    DISTRIBUIOR = db.Column(db.String)
    CNPJ_CLIENTE = db.Column(db.String)
    CLIENTE = db.Column(db.String)
    PEDIDO = db.Column(db.String)
    STATUS_PEDIDO = db.Column(db.String)
    ENVIO = db.Column(db.String)
    CONFIRMACAO = db.Column(db.String)
    FINAL = db.Column(db.String)
    SKU = db.Column(db.String)
    QUANTIDADE = db.Column(db.String)
    NOME_PRODUTO = db.Column(db.String)
    PRECO_UNITARIO = db.Column(db.String)
    TOTAL = db.Column(db.String)
    FORMA_PAGAMENTO = db.Column(db.String)

    def __init__(self, ID, CNPJ_DISTRIBUIDOR, DISTRIBUIOR, CNPJ_CLIENTE, CLIENTE, PEDIDO,
                 STATUS_PEDIDO, ENVIO, CONFIRMACAO, FINAL, SKU, QUANTIDADE, NOME_PRODUTO,
                 PRECO_UNITARIO, TOTAL, FORMA_PAGAMENTO):
        self.ID = ID
        self.CNPJ_DISTRIBUIDOR = CNPJ_DISTRIBUIDOR
        self.DISTRIBUIOR = DISTRIBUIOR
        self.CNPJ_CLIENTE = CNPJ_CLIENTE
        self.CLIENTE = CLIENTE
        self.PEDIDO = PEDIDO
        self.STATUS_PEDIDO = STATUS_PEDIDO
        self.ENVIO = ENVIO
        self.CONFIRMACAO = CONFIRMACAO
        self.FINAL = FINAL
        self.SKU = SKU
        self.QUANTIDADE = QUANTIDADE
        self.NOME_PRODUTO = NOME_PRODUTO
        self.PRECO_UNITARIO = PRECO_UNITARIO,
        self.TOTAL = TOTAL
        self.FORMA_PAGAMENTO = FORMA_PAGAMENTO

# Crear una clase para representar a los usuarios
class Users(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True)
    name = db.Column(db.String)
    password = db.Column(db.String)
    profile = db.Column(db.String)
    phone = db.Column(db.String)

    def __init__(self, id, username, password, profile, phone, name):
        self.id = id
        self.username = username
        self.password = password
        self.profile = profile
        self.phone = phone
        self.name = name

    # Método para verificar la contraseña
    def check_password(self, password):
        return check_password_hash(self.password, password)

    # Método para generar un token
    def generate_token(self):
        payload = {
            "id": self.id,
            "username": self.username,
            "perfil": self.profile,
            "phone": self.phone,
            "name": self.name
        }
        token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
        return token

    def returnProfile(self):
        payload = {
            "id": self.id,
            "username": self.username,
            "perfil": self.profile,
            "phone": self.phone,
            "name": self.name
        }
        return payload

    def __repr__(self):
        return f'<User {self.username!r}>'

# Crear una función para obtener un usuario por su nombre de usuario
def get_user_by_username(username, password):
    user = Users.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        login_user(user)
        return user
    else:
        return


# Crear una ruta para registrar un usuario
@api.route("/api/user/register")
class Register(Resource):
    # Documentar los parámetros y el modelo esperado
    @api.expect(user_model_login_register)
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(201, "Usuario registrado con éxito", user_model_login_register)
    # Documentar la respuesta de error y el mensaje devuelto
    @api.response(400, "El nombre de usuario ya está en uso")
    def post(self):
        # Obtener los datos del usuario del cuerpo de la solicitud
        data = request.get_json()
        username = data.get("username")
        name = data.get("name")
        profile = data.get("profile")
        phone = data.get("phone")

        # Verificar si el usuario ya existe
        if checkUsername(username):
            return {"error": "El nombre de usuario ya está en uso"}, 400

        lenUser = Users.query.all()
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for i in range(20))  # for a 20-character password
        # Crear un nuevo usuario con un id generado y una contraseña hasheada
        saveUser(len(lenUser) + 1, username, generate_password_hash(password), profile, phone, name)

        mensaje = """ Mail: """ + username + """ \n Password: """ + password

        sendMailUser(username, mensaje, 'Criação de conta')

        # Retornar una respuesta exitosa con el usuario creado
        return {"message": "Usuario registrado con éxito"}, 201

# Crear una ruta para iniciar sesión con un usuario
@api.route("/api/login")
class Login(Resource):
    # Documentar los parámetros y el modelo esperado
    @api.expect(user_login)
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Usuario autenticado con éxito", token_model)
    # Documentar la respuesta de error y el mensaje devuelto
    @api.response(401, "Usuario o contraseña incorrectos")
    def post(self):
        # Obtener los datos del usuario del cuerpo de la solicitud
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        # Obtener el usuario por su nombre de usuario
        user = get_user_by_username(username, password)

        # Verificar si el usuario existe y si la contraseña es correcta
        if user and user.check_password(password):
            # Iniciar sesión con el usuario usando flask_login
            login_user(user)
            # Generar un token para el usuario usando jwt
            token = user.generate_token()
            payload = user.returnProfile()

            # Retornar una respuesta exitosa con el token generado
            return {"message": "Usuario autenticado con éxito", "token": token, "data": payload}, 200

        # Retornar una respuesta de error si el usuario o la contraseña son incorrectos
        return {"error": "Usuario o contraseña incorrectos"}, 401

# Crear una ruta para cerrar sesión con un usuario
@api.route("/api/logout")
class Logout(Resource):
    # Documentar que se requiere estar autenticado para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el mensaje devuelto
    @api.response(200, "Usuario desautenticado con éxito")
    # Usar el decorador de flask_login para requerir estar autenticado
    # @login_required
    def get(self):
        # Cerrar sesión con el usuario usando flask_login
        logout_user()

        # Retornar una respuesta exitosa con un mensaje
        return {"message": "Usuario desautenticado con éxito"}, 200

# Crear una ruta para obtener información del usuario autenticado
@api.route("/api/user/update")
class UserUpdate(Resource):
    # Documentar que se requiere estar autenticado y tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario a actualizar", user_model_update)
    # Usar el decorador de flask_login para requerir estar autenticado
    # @login_required
    def put(self):
        print("EJECUTANDO UPDATE DE USUARIOS")
        data = request.get_json()
        id = data.get("id")
        username = data.get("username")
        profile = data.get("profile")
        name = data.get("name")
        phone = data.get("phone")
        user_update = Users.query.filter_by(id=id).first()
        user_update.username = username
        user_update.name = name
        user_update.phone = phone
        user_update.profile = profile
        db.session.commit()
        # Retornar una respuesta exitosa con la información del usuario
        return {"message": "Usuario actualizado con éxito"}, 200

@api.route('/api/user/resendPassword')
class resendPassword(Resource):
    # Documentar que se requiere estar autenticado y tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Para actualizar y enviar una nueva contrasenia", user_model_update_password)
    # Usar el decorador de flask_login para requerir estar autenticado
    # @login_required
    def post(self):
        print("EJECUTANDO UPDATE DE PASSWORD")
        data = request.get_json()
        id = data.get("id")
        alphabet = string.ascii_letters + string.digits
        password = ''.join(secrets.choice(alphabet) for i in range(20))  # for a 20-character password
        user_update = Users.query.filter_by(id=id).first()
        print(password)
        mensaje = "Nova senha: " + password
        header = "Atualizar senha"
        sendMailUser(user_update.username, mensaje, header)
        user_update.password = generate_password_hash(password)
        db.session.commit()
        return {"message": "Contrasenia actualizada"}, 200

@api.route("/api/user/getAll")
class UserList(Resource):
    # Documentar que se requiere estar autenticado y tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información de los usuario", user_model_login_register)
    # Usar el decorador de flask_login para requerir estar autenticado
    # @login_required
    def get(self):
        list = Users.query.all()
        listUser = []
        for user in list:
            print(user.profile)
            listUser.append({
                "id": user.id,
                "name": user.name,
                "phone": user.phone,
                "username": user.username,
                "profile": user.profile,
            })
        return {"users": listUser}, 200

# Crear una función para verificar el token en las rutas protegidas
def verify_token(token):
    # Intentar decodificar el token usando la clave secreta del jwt
    try:
        payload = jwt.decode(token, jwt_secret_key, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        # Si el token está expirado, retornar falso
        return False
    except jwt.InvalidTokenError:
        # Si el token es inválido, retornar falso
        return False

    # Obtener el id del usuario del payload
    user_id = payload.get("id")

    # Obtener el usuario por su id
    user = get_user_by_id(user_id)

    # Si el usuario existe, retornar verdadero
    if user:
        return True

    # Si el usuario no existe, retornar falso
    return False

# Crear una función para manejar las autorizaciones en las rutas protegidas
@api.doc(security="apikey")
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Obtener el token de la cabecera de la solicitud
        token = request.headers.get("X-API-KEY")

        # Si no hay token, retornar un error 401
        if not token:
            return {"error": "Se requiere un token para acceder a esta ruta"}, 401

        # Si hay token, verificar si es válido
        if not verify_token(token):
            return {"error": "Token inválido o expirado"}, 401

        # Si el token es válido, continuar con la función original
        return f(*args, **kwargs)

    return decorated

# Crear una ruta para obtener información del usuario autenticado usando el token
@api.route("/api/user/token")
class UserToken(Resource):
    # Documentar que se requiere tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario", user_login)
    # Usar el decorador personalizado para requerir un token válido
    @token_required
    def get(self):
        # Obtener el token de la cabecera de la solicitud
        token = request.headers.get("X-API-KEY")

        # Decodificar el token para obtener el payload
        payload = jwt.decode(token, jwt_secret_key, algorithms=["HS256"])

        # Obtener el id del usuario del payload
        user_id = payload.get("id")

        # Obtener el usuario por su id
        user = get_user_by_id(user_id)

        # Retornar una respuesta exitosa con la información del usuario
        return {"user": {
            "id": user.id,
            "username": user.username,
            "password": user.password,
            "profile": user.profile
        }}, 200

# Crear una función para manejar los errores de la api
@api.errorhandler(Exception)
def handle_error(error):
    # Retornar una respuesta de error con el mensaje y el código correspondiente al error
    return {"error": str(error)}, getattr(error, "code", 500)

# Envio de emial a usuario
def sendMailUser(username, mensaje, header):
    print("EJECUTANDO ENVIO DE EMAIL")
    # Datos del servidor SMTP
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'niveabrproyect@gmail.com'
    smtp_password = 'xugxhfcgfeoiqmur'

    # Datos del mensaje
    from_addr = 'niveabrproyect@gmail.com'
    to_addr = username
    subject = header
    body = mensaje

    # Crear objeto mensaje
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Conectar al servidor SMTP
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_username, smtp_password)

    # Enviar mensaje
    text = msg.as_string()
    server.sendmail(from_addr, to_addr, text)

    # Cerrar conexión
    server.quit()

# Verifica existencia de usuario
def checkUsername(username):
    print('EJECUTANDO CHECKEO DE USUARIOS')
    users = Users.query.filter_by(username=username).first()
    if users:
        print(users, 'USUARIOS ENCONTRADOS')
        return True
    else:
        return False

# Para agregar usuario a la BD
def saveUser(id, username, password, profile, phone, name):
    user = Users(id=id,
                 username=username,
                 password=password,
                 profile=profile,
                 phone=phone,
                 name=name)
    db.session.add(user)
    db.session.commit()
    return

@api.route("/api/user/update/info")
class userUpdateInfo(Resource):
    @api.doc(security="apikey")
    @api.expect(update_info_user)
    @api.response(200, "Informacion para actualizar usuarios", update_info_user)
    def post(self):
        print("EJECUTANDO UPDATE DE USUARIOS PERSONALIZADO")
        data = request.get_json()
        id = data.get("id")
        username = data.get("username")
        name = data.get("name")
        phone = data.get("phone")
        user_update = Users.query.filter_by(id=id).first()
        user_update.username = username
        user_update.name = name
        user_update.phone = phone
        db.session.commit()
        # Retornar una respuesta exitosa con la información del usuario
        return {"message": "Usuario actualizado con éxito"}, 200

@api.route("/api/user/update/password")
class userUpdatePassword(Resource):
    @api.doc(security="apikey")
    @api.expect(update_password_user)
    @api.response(200, "Informacion para actualizar contraseña de usuarios", update_password_user)
    def post(self):
        print("EJECUTANDO UPDATE DE CONTRASEÑA DE USUARIOS PERSONALIZADO")
        data = request.get_json()
        id = data.get("id")
        oldPassword = data.get("oldPassword")
        newPassword = data.get("newPassword")
        username = data.get("username")
        user_update = Users.query.filter_by(id=id).first()

        # Obtener el usuario por su nombre de usuario
        user = get_user_by_username(username, oldPassword)
        print(user)
        print(oldPassword)
        print(newPassword)
        print(username)
        if user and user.check_password(oldPassword):
            user_update.password = generate_password_hash(newPassword)
            mensaje = """ Mail: """ + username + """ \n Password: """ + newPassword
            db.session.commit()
            sendMailUser(username, mensaje, 'Atualização de conta')
            # Retornar una respuesta exitosa con la información del usuario
            return {"message": "Usuario actualizado con éxito"}, 200
        else:
            return {"message": "A senha antiga não está correta"}, 401

@api.route("/api/omie/produtos/pedido/")
class getPedidosOmie(Resource):
    # Documentar que se requiere tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario", user_login)
    def get(self):
        url_omie = 'https://app.omie.com.br/api/v1/produtos/pedido/'
        headers = {'Content-type': 'application/json'}
        data = {
            "call": "ListarPedidos",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": 100,
                    "apenas_importado_api": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        response_data = response.json()
        data = {
            "call": "ListarPedidos",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": response_data['total_de_registros'],
                    "apenas_importado_api": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        response_data = response.json()
        return response_data, 200

@api.route("/api/omie/geral/clientes/")
class getClientesOmie(Resource):
    # Documentar que se requiere tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario", user_login)
    def get(self):
        url_ = 'https://app.omie.com.br/api/v1/geral/clientes/'
        headers = {'Content-type': 'application/json'}
        data = {
            "call": "ListarClientes",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": 100,
                    "apenas_importado_api": "N"
                }
            ]
        }
        response = requests.post(url_, headers=headers, data=json.dumps(data))
        response_data = response.json()
        data = {
            "call": "ListarClientes",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": response_data['total_de_registros'],
                    "apenas_importado_api": "N"
                }
            ]
        }
        response = requests.post(url_, headers=headers, data=json.dumps(data))

        # Crea el DataFrame
        response_data = response.json()
        df = pd.json_normalize(response_data['clientes_cadastro'])
        data = df.to_dict(orient='records')
        # Reemplazar NaN por None
        diccionario_reemplazado = reemplazar_nan_con_none(data)
        columns = df.columns.tolist()
        datasend = {
            "columns": columns,
            "clientes_cadastro": diccionario_reemplazado
        }

        return datasend, 200

def reemplazar_nan_con_none(objeto):
    if isinstance(objeto, dict):
        for clave, valor in objeto.items():
            objeto[clave] = reemplazar_nan_con_none(valor)
        return objeto
    elif isinstance(objeto, list):
        for i in range(len(objeto)):
            objeto[i] = reemplazar_nan_con_none(objeto[i])
        return objeto
    elif pd.isna(objeto):
        return None
    else:
        return objeto

@api.route("/api/omie/geral/produtos/")
class getPedidosOmie(Resource):
    # Documentar que se requiere tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario", user_login)
    def get(self):
        url_omie = 'https://app.omie.com.br/api/v1/geral/produtos/'
        headers = {'Content-type': 'application/json'}
        data = {
            "call": "ListarProdutos",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": 50,
                    "apenas_importado_api": "N",
                    "filtrar_apenas_omiepdv": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        response_data = response.json()

        data = {
            "call": "ListarProdutos",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": response_data['total_de_registros'],
                    "apenas_importado_api": "N",
                    "filtrar_apenas_omiepdv": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        # Crea el DataFrame
        response_data = response.json()
        df = pd.json_normalize(response_data['produto_servico_cadastro'])
        data = df.to_dict(orient='records')
        # Reemplazar NaN por None
        diccionario_reemplazado_all = reemplazar_nan_con_none(data)
        columns = df.columns.tolist()

        url_omie = 'https://app.omie.com.br/api/v1/geral/produtos/'
        headers = {'Content-type': 'application/json'}
        data = {
            "call": "ListarProdutosResumido",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": 50,
                    "apenas_importado_api": "N",
                    "filtrar_apenas_omiepdv": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        response_data = response.json()

        data = {
            "call": "ListarProdutosResumido",
            "app_key": "3458207541789",
            "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
            "param": [
                {
                    "pagina": 1,
                    "registros_por_pagina": response_data['total_de_registros'],
                    "apenas_importado_api": "N",
                    "filtrar_apenas_omiepdv": "N"
                }
            ]
        }
        response = requests.post(url_omie, headers=headers, data=json.dumps(data))
        # Crea el DataFrame
        response_data = response.json()
        df = pd.json_normalize(response_data['produto_servico_resumido'])
        data = df.to_dict(orient='records')
        # Reemplazar NaN por None
        diccionario_reemplazado_resume = reemplazar_nan_con_none(data)
        columns_resume = df.columns.tolist()

        datasend = {
            "columns": columns,
            "produto_servico_cadastro": diccionario_reemplazado_all,
            "resume": {
                "columns": columns_resume,
                "produto_servico_cadastro": diccionario_reemplazado_resume,
            }
        }

        return datasend, 200
        #
        # response_data = response.json()
        # return response_data, 200

@api.route("/api/omie/estoque/consulta/")
class getEstoqueConsulta(Resource):
    # Documentar que se requiere tener un token válido para acceder a esta ruta
    @api.doc(security="apikey")
    # Documentar la respuesta exitosa y el modelo devuelto
    @api.response(200, "Información del usuario", user_login)
    def get(self):
        # Obtener la fecha de hoy
        fecha_hoy = date.today()
        fecha_hoy_str = fecha_hoy.strftime("%d/%m/%Y")
        regPerPage = 50
        response_data = callToActionStockOmie(fecha_hoy_str, regPerPage)

        if response_data['nTotRegistros'] > regPerPage:
            response_data = callToActionStockOmie(fecha_hoy_str, response_data['nTotRegistros'])

        return response_data, 200

def callToActionStockOmie(fecha_hoy_str,regPerPage):
    url_omie = 'https://app.omie.com.br/api/v1/estoque/consulta/'
    headers = {'Content-type': 'application/json'}
    data = {
        "call": "ListarPosEstoque",
        "app_key": "3458207541789",
        "app_secret": "86976b5e3bdccbd7063e5c1666d6b039",
        "param": [
            {
                "nPagina": 1,
                "nRegPorPagina": regPerPage,
                "dDataPosicao": fecha_hoy_str,
                "cExibeTodos": "N",
                "codigo_local_estoque": 0
            }
        ]
    }
    response = requests.post(url_omie, headers=headers, data=json.dumps(data))
    return response.json()

@app.route('/api/pedidos', methods=['GET'])
def get_pedidos():
    pedidos = PedidosTemp.query.all()
    pedidos_data = []
    for pedido in pedidos:
        pedido_data = {
            'ID': pedido.ID,
            'CNPJ_DISTRIBUIDOR': pedido.CNPJ_DISTRIBUIDOR,
            'DISTRIBUIDOR': pedido.DISTRIBUIOR,
            'CNPJ_CLIENTE': pedido.CNPJ_CLIENTE,
            'CLIENTE': pedido.CLIENTE,
            'PEDIDO': pedido.PEDIDO,
            'STATUS_PEDIDO': pedido.STATUS_PEDIDO,
            'ENVIO': pedido.ENVIO,
            'CONFIRMACAO': pedido.CONFIRMACAO,
            'FINAL': pedido.FINAL,
            'SKU': pedido.SKU,
            'QUANTIDADE': pedido.QUANTIDADE,
            'NOME_PRODUTO': pedido.NOME_PRODUTO,
            'PRECO_UNITARIO': pedido.PRECO_UNITARIO,
            'TOTAL': pedido.TOTAL,
            'FORMA_PAGAMENTO': pedido.FORMA_PAGAMENTO
        }
        pedidos_data.append(pedido_data)

    return jsonify(pedidos_data), 200

@app.route('/api/pedidos/log', methods=['GET'])
def get_pedidos_log():
    pedidos = PedidosLog.query.all()
    pedidos_data = []
    for pedido in pedidos:
        pedido_data = {
            'ID': pedido.ID,
            'CNPJ_DISTRIBUIDOR': pedido.CNPJ_DISTRIBUIDOR,
            'DISTRIBUIDOR': pedido.DISTRIBUIOR,
            'CNPJ_CLIENTE': pedido.CNPJ_CLIENTE,
            'CLIENTE': pedido.CLIENTE,
            'PEDIDO': pedido.PEDIDO,
            'STATUS_PEDIDO': pedido.STATUS_PEDIDO,
            'ENVIO': pedido.ENVIO,
            'CONFIRMACAO': pedido.CONFIRMACAO,
            'FINAL': pedido.FINAL,
            'SKU': pedido.SKU,
            'QUANTIDADE': pedido.QUANTIDADE,
            'NOME_PRODUTO': pedido.NOME_PRODUTO,
            'PRECO_UNITARIO': pedido.PRECO_UNITARIO,
            'TOTAL': pedido.TOTAL,
            'FORMA_PAGAMENTO': pedido.FORMA_PAGAMENTO
        }
        pedidos_data.append(pedido_data)

    return jsonify(pedidos_data), 200

def validateHeader(headers):
    pass


def validate_header(header_row):
    expected_headers = [
        'CNPJ DISTRIBUIDOR',
        'DISTRIBUIOR',
        'CNPJ CLIENTE',
        'CLIENTE',
        'PEDIDO',
        'STATUS PEDIDO',
        'ENVIO',
        'CONFIRMAÇÃO',
        'FINAL',
        'SKU',
        'QUANTIDADE',
        'NOME PRODUTO',
        'PRECO UNITARIO',
        'TOTAL',
        'FORMA PAGAMENTO'
    ]

    cleaned_headers = [re.sub(r'\W+', '', header) for header in header_row]

    if len(cleaned_headers) != len(expected_headers):
        return False

    for header, expected_header in zip(cleaned_headers, expected_headers):
        if header != expected_header:
            return False

    return True


@api.route('/api/omie/cargar', methods=['POST'])
class UserUploadFile(Resource):
    @api.doc(security="apikey")
    @api.response(200, "Upload de archivos", update_password_user)
    def post(self):
        file = request.files['file']
        type = request.args.get('type')

        archivo = request.files['file']
        tipo_archivo = archivo.content_type
        nombre_archivo, extension = os.path.splitext(archivo.filename)

        if extension == '.csv':
            df = pd.read_csv(file, sep=',')
            print(df.columns)
        elif extension == '.xlsx':
            df = pd.read_excel(file)
            df.rename(columns=lambda x: x.replace(' ', ''), inplace=True)
            print(df.columns)
        else:
            return "Archivo no admitido", 400
        saveDataFromUpload(df)
        return "Archivo recibido con éxito", 200

def saveDataFromUpload(file):
    connection.execute(text('''DELETE from "pedidos_temp";'''))
    nombres_nuevos = {
        'CNPJ DISTRIBUIDOR': 'CNPJ_DISTRIBUIDOR',
        'DISTRIBUIOR': 'DISTRIBUIOR',
        'CNPJ CLIENTE': 'CNPJ_CLIENTE',
        'CLIENTE': 'CLIENTE',
        'PEDIDO': 'PEDIDO',
        'STATUS PEDIDO': 'STATUS_PEDIDO',
        'ENVIO': 'ENVIO',
        'CONFIRMAÇÃO': 'CONFIRMACAO',
        'FINAL': 'FINAL',
        'SKU': 'SKU',
        'QUANTIDADE': 'QUANTIDADE',
        'NOME PRODUTO': 'NOME_PRODUTO',
        'PRECO UNITARIO': 'PRECO_UNITARIO',
        'TOTAL': 'TOTAL',
        'FORMA PAGAMENTO': 'FORMA_PAGAMENTO',
    }

    # Cambia los nombres de las columnas utilizando el método rename()
    df = file.rename(columns=nombres_nuevos)
    # Itera sobre los registros del DataFrame y crea una instancia de la clase StoreTable para cada uno
    for index, row in df.iterrows():
        store_table = PedidosTemp(
            ID=index,
            CNPJ_DISTRIBUIDOR=row['CNPJ_DISTRIBUIDOR'],
            DISTRIBUIOR=row['DISTRIBUIOR'],
            CNPJ_CLIENTE=row['CNPJ_CLIENTE'],
            CLIENTE=row['CLIENTE'],
            PEDIDO=row['PEDIDO'],
            STATUS_PEDIDO=row['STATUS_PEDIDO'],
            ENVIO=row['ENVIO'],
            CONFIRMACAO=row['CONFIRMACAO'],
            FINAL=row['FINAL'],
            SKU=row['SKU'],
            QUANTIDADE=row['QUANTIDADE'],
            NOME_PRODUTO=row['NOME_PRODUTO'],
            PRECO_UNITARIO=row['PRECO_UNITARIO'],
            TOTAL=row['TOTAL'],
            FORMA_PAGAMENTO=row['FORMA_PAGAMENTO'],

        )
        db.session.add(store_table)

    # Confirma los cambios en la base de datos
    connection.commit()
    db.session.commit()


# # Crear un contexto de aplicación
with app.app_context():
    # Crear las tablas en la base de datos
    db.create_all()

# Ejecutar la aplicación si se ejecuta este archivo
if __name__ == "__main__":
    app.run(host="0.0.0.0")
