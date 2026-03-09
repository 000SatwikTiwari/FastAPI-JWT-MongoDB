# uvicorn prac3:app --reload

from fastapi import FastAPI, Depends, HTTPException
from pymongo import MongoClient
from pydantic import BaseModel
import random
import smtplib
import os
from jose import jwt, JWTError
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from email.message import EmailMessage
from datetime import datetime, timedelta
from dotenv import load_dotenv
from passlib.context import CryptContext
from bson import ObjectId

load_dotenv()

temp_users = {}
temp_forgot_users = {}
blacklisted_tokens = set()
blacklisted_access_tokens = set()

app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Environment variables
MONGO_URL = os.getenv("MONGO_URL")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SECRET_KEY = os.getenv("SECRET_KEY")

if not MONGO_URL or not SECRET_KEY:
    raise Exception("Missing environment variables")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# MongoDB
client = MongoClient(MONGO_URL)
db = client["prac3"]
collection = db["users"]
notes_collection = db["notes_prac3"]


# ================= MODELS =================

class Register(BaseModel):
    email: str
    password: str


class VerifyOTP(BaseModel):
    email: str
    otp: int


class Login(BaseModel):
    email: str
    password: str


class Note(BaseModel):
    title: str
    content: str


class Logout(BaseModel):
    access_token: str
    refresh_token: str


class ResetPassword(BaseModel):
    current_password: str
    new_password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetForgotPassword(BaseModel):
    email: str
    otp: int
    new_password: str


class DeleteNoteRequest(BaseModel):
    title: str


class RefreshToken(BaseModel):
    refresh_token: str


# ================= UTILITIES =================

def hash_password(password):
    return pwd_context.hash(password)


def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)


def generate_otp():
    return random.randint(100000, 999999)


def send_otp_email(receiver, otp):

    msg = EmailMessage()
    msg["Subject"] = "Your OTP Verification"
    msg["From"] = EMAIL_USER
    msg["To"] = receiver
    msg.set_content(f"Your OTP is {otp}")

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(EMAIL_USER, EMAIL_PASS)
        smtp.send_message(msg)


def create_access_token(data: dict):

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):

    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire})

    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# ================= AUTH DEPENDENCY =================

security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):

    token = credentials.credentials

    if token in blacklisted_access_tokens:
        raise HTTPException(status_code=401, detail="Token revoked")

    try:

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id = payload.get("user_id")

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = collection.find_one({"_id": ObjectId(user_id)})

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        return payload

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ================= AUTH APIs =================

@app.post("/register")
def register(data: Register):

    if collection.find_one({"email": data.email}):
        raise HTTPException(status_code=400, detail="Already registered")

    hashed_password = hash_password(data.password)
    otp = generate_otp()

    temp_users[data.email] = {
        "email": data.email,
        "password": hashed_password,
        "otp": otp,
        "created_at": datetime.utcnow()
    }

    send_otp_email(data.email, otp)

    return {"message": "OTP sent to email"}


@app.post("/verify-otp")
def verify_otp(data: VerifyOTP):

    user = temp_users.get(data.email)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if datetime.utcnow() > user["created_at"] + timedelta(minutes=5):
        raise HTTPException(status_code=400, detail="OTP expired")

    if user["otp"] != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    collection.insert_one({
        "email": user["email"],
        "password": user["password"],
        "verified": True
    })

    del temp_users[data.email]

    return {"message": "User verified"}


@app.post("/login")
def login(data: Login):

    user = collection.find_one({"email": data.email})

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(data.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid password")

    access_token = create_access_token({
        "user_id": str(user["_id"]),
        "email": user["email"]
    })

    refresh_token = create_refresh_token({
        "user_id": str(user["_id"])
    })

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }


# ================= NOTES =================

@app.post("/create-note")
def create_note(note: Note, user=Depends(get_current_user)):

    notes_collection.insert_one({
        "user_id": user["user_id"],
        "title": note.title,
        "content": note.content
    })

    return {"message": "Note created"}


@app.get("/my-notes")
def get_notes(user=Depends(get_current_user)):

    notes = list(notes_collection.find(
        {"user_id": user["user_id"]},
        {"_id": 0}
    ))

    return notes


@app.delete("/delete-note")
def delete_note(data: DeleteNoteRequest, user=Depends(get_current_user)):

    result = notes_collection.delete_one({
        "user_id": user["user_id"],
        "title": data.title
    })

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Note not found")

    return {"message": "Note deleted"}


# ================= TOKEN =================

@app.post("/refresh-token")
def refresh_token(data: RefreshToken):

    if data.refresh_token in blacklisted_tokens:
        raise HTTPException(status_code=401, detail="Token revoked")

    try:

        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        new_access = create_access_token({
            "user_id": payload["user_id"]
        })

        return {"access_token": new_access}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.post("/logout")
def logout(data: Logout):

    try:

        jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        blacklisted_tokens.add(data.refresh_token)
        blacklisted_access_tokens.add(data.access_token)

        return {"message": "Logged out"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ================= PASSWORD =================

@app.post("/reset-password")
def reset_password(data: ResetPassword, user=Depends(get_current_user)):

    db_user = collection.find_one({"_id": ObjectId(user["user_id"])})

    if not verify_password(data.current_password, db_user["password"]):
        raise HTTPException(status_code=401, detail="Wrong password")

    hashed_new = hash_password(data.new_password)

    collection.update_one(
        {"_id": db_user["_id"]},
        {"$set": {"password": hashed_new}}
    )

    return {"message": "Password updated"}


# ================= DELETE ACCOUNT =================

@app.delete("/delete-account")
def delete_account(credentials: HTTPAuthorizationCredentials = Depends(security)):

    token = credentials.credentials

    try:

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["user_id"]

        blacklisted_access_tokens.add(token)

        notes_collection.delete_many({"user_id": user_id})

        collection.delete_one({"_id": ObjectId(user_id)})

        return {"message": "Account deleted"}

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
