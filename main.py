import jwt
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.hash import bcrypt
from tortoise import fields
from tortoise.contrib.fastapi import register_tortoise
from tortoise.contrib.pydantic import pydantic_model_creator
from tortoise.models import Model

# Invoking FastAPI as app Variable
app = FastAPI()

# JWT Secret (It should be in .env or production variable environment)
JWT_SECRET = 'myjwtsecret'


# Creating a tortoise Model Schema
class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(50, unique=True)
    password_hash = fields.CharField(128)
    is_active = fields.BooleanField(default=False)

    # Creating user class method to verify password
    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)


# Creating a User Model with "pydantic_model_creator"
User_Pydantic = pydantic_model_creator(User, name='User')

# Creating a User Model with "pydantic_model_creator" (Excluding Readonly Fields)
UserIn_Pydantic = pydantic_model_creator(
    User, name='UserIn', exclude_readonly=True)

# Creating Auth2 Scheme with FastAPI "OAuth2PasswordBearer"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


# An Async method to Authenticate User & return User if Authenticated
async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


# A Route to Login & Generate Bearer Token
@app.post('/token')
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    # Getting user model from from tortoise_orm
    user_obj = await User_Pydantic.from_tortoise_orm(user)

    # Creating a Bearer token and Providing username & password
    token = jwt.encode({"username": user_obj.dict()[
                       'username'], "id": user_obj.dict()['id']}, JWT_SECRET)

    return {'access_token': token, 'token_type': 'bearer'}


# An Async method for Getting Current User based on Bearer Token (JWT)
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        user = await User.get(id=payload.get('id'))
    except:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid username or password'
        )

    return await User_Pydantic.from_tortoise_orm(user)


# A route for Creating a New User with username & password
@app.post('/create_user', response_model=User_Pydantic)
async def create_user(user: UserIn_Pydantic):
    user_obj = User(username=user.username,
                    password_hash=bcrypt.hash(user.password_hash))
    await user_obj.save()
    return await User_Pydantic.from_tortoise_orm(user_obj)


# A getting the current user based on the Bearer Token (JWT)
@app.get('/users/me', response_model=User_Pydantic)
async def get_user(user: User_Pydantic = Depends(get_current_user)):
    return user


# Configuring the tortoise orm
register_tortoise(
    app,
    db_url='sqlite://db.sqlite3',
    modules={'models': ['main']},
    generate_schemas=True,
    add_exception_handlers=True
)
