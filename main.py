from fastapi import FastAPI
from pymongo import MongoClient
from pydantic import BaseModel
import random
import smtplib
import os
from jose import jwt, JWTError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from email.message import EmailMessage
from datetime import datetime, timedelta
from dotenv import load_dotenv
from passlib.context import CryptContext
temp_users={}
load_dotenv()
blacklisted_tokens = set() ##
# NEW: logout ke time access token turant invalid karne ke liye
blacklisted_access_tokens = set()
temp_forgot_users = {}


app = FastAPI()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Environment variables
MONGO_URL = os.getenv("MONGO_URL")
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# MongoDB connection
client = MongoClient(MONGO_URL)
db1 = client["prac3"]
collection = db1["users"]

notes_collection = db1["notes_prac3"] ## for storing notes



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





def hash_password(password):
    return pwd_context.hash(password)
def generate_otp():
    return random.randint(100000, 999999)
def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)
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

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

def create_refresh_token(data: dict):

    to_encode = data.copy()

    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    return encoded_jwt

#### Token Verification Dependency This protects APIs.
security = HTTPBearer()
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    
    token = credentials.credentials

    # NEW: check if token is blacklisted (user logged out)
    if token in blacklisted_access_tokens:
        raise HTTPException(status_code=401, detail="Access token revoked (logged out)")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")

        # Optional: fetch user from DB
        user = collection.find_one({"_id": user_id})

        return payload

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")





@app.post("/register")
def user_reg(data: Register):
    if collection.find_one({"email":data.email}) :
        return{"message":"Already Registered"}
    hashed_password = hash_password(data.password)
    otp = generate_otp() ## ye lelia generate otp se
    # store temporarily
    temp_users[data.email] = {
        "email": data.email,
        "password": hashed_password,
        "otp": otp,
        "created_at": datetime.utcnow()
    }

    send_otp_email(data.email, otp) ##ye bhej dia send otp pe is mail pe ye otp

    return {"message": "OTP sent to your email"}
    
@app.post("/verify-otp")
def verify_email(data: VerifyOTP):

    user = temp_users.get(data.email)


    ##here it can be like user = temp_users[data.email]
    ## but If the email does not exist, it gives KeyError (program crash).
    ## so we use user = temp_users.get(data.email)
    ## If the email does not exist, it returns None (no error).



    if not user:
        return {"message": "User not found"}

    # OTP expiry check (5 minutes)
    if datetime.utcnow() > user["created_at"] + timedelta(minutes=5):
        return {"message": "OTP expired"}

    if user["otp"] != data.otp:
        return {"message": "Invalid OTP"}

    # Save to MongoDB after verification
    collection.insert_one({
        "email": user["email"],
        "password": user["password"],
        "verified": True
    })

    # remove temp user
    del temp_users[data.email]

    return {"message": "Email verified and user saved"}
@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordRequest):

    user = collection.find_one({"email": data.email})
    if not user:
        return {"message": "User not found"}

    # Generate OTP
    otp = generate_otp()

    # Store OTP temporarily
    temp_forgot_users[data.email] = {
        "otp": otp,
        "created_at": datetime.utcnow()
    }

    # Send OTP via email
    send_otp_email(data.email, otp)

    return {"message": "OTP sent to your email"}
@app.post("/reset-forgot-password")
def reset_forgot_password(data: ResetForgotPassword):

    temp_user = temp_forgot_users.get(data.email)
    if not temp_user:
        return {"message": "OTP request not found or expired"}

    # OTP expiry check (5 minutes)
    if datetime.utcnow() > temp_user["created_at"] + timedelta(minutes=5):
        del temp_forgot_users[data.email]
        return {"message": "OTP expired"}

    # OTP validation
    if temp_user["otp"] != data.otp:
        return {"message": "Invalid OTP"}

    # Hash new password and update DB
    hashed_password = hash_password(data.new_password)
    collection.update_one(
        {"email": data.email},
        {"$set": {"password": hashed_password}}
    )

    # Remove temporary OTP
    del temp_forgot_users[data.email]

    return {"message": "Password reset successfully"}

@app.post("/login")
def login(data: Login):

    user = collection.find_one({"email": data.email})

    if not user:
        return {"message": "User not found"}

    if not verify_password(data.password, user["password"]):
        return {"message": "Invalid password"}

    access_token = create_access_token(
        {"user_id": str(user["_id"]), "email": user["email"]}
    )

    refresh_token = create_refresh_token(
        {"user_id": str(user["_id"])}
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }
## main app
@app.post("/create-note")
def create_note(note: Note, user = Depends(get_current_user)):

    notes_collection.insert_one({
        "user_id": user["user_id"],
        "title": note.title,
        "content": note.content
    })

    return {"message": "Note created"}

@app.get("/my-notes")
def get_notes(user = Depends(get_current_user)):

    notes = list(notes_collection.find({"user_id": user["user_id"]}, {"_id":0}))

    return notes

class RefreshToken(BaseModel):
    refresh_token: str


@app.delete("/delete-note")
def delete_note(data: DeleteNoteRequest, user=Depends(get_current_user)):

    # Delete note where user_id matches and title matches
    result = notes_collection.delete_one({
        "user_id": user["user_id"],
        "title": data.title
    })

    if result.deleted_count == 0:
        return {"message": "Note not found or not yours"}

    return {"message": "Note deleted successfully"}


@app.post("/refresh-token")
def refresh_token(data: RefreshToken):

    # NEW: check if refresh token is blacklisted (user already logged out)
    if data.refresh_token in blacklisted_tokens:
        return {"message": "Refresh token invalid (user logged out)"}

    try:

        payload = jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])

        # SAME: new access token generate kar rahe hain
        new_access = create_access_token({
            "user_id": payload["user_id"]
        })

        return {"access_token": new_access}

    except JWTError:
        return {"message": "Invalid refresh token"}
    
    
@app.post("/logout")
def logout(data: Logout):

    try:
        # decode refresh token just to verify
        jwt.decode(data.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # NEW: add refresh token to blacklist
        blacklisted_tokens.add(data.refresh_token)

        # NEW: add access token to blacklist
        blacklisted_access_tokens.add(data.access_token)

        return {"message": "User logged out successfully"}

    except JWTError:
        return {"message": "Invalid refresh token"}
    

@app.post("/reset-password")
def reset_password(data: ResetPassword, user=Depends(get_current_user)):

    # 1️⃣ Get user from DB
    db_user = collection.find_one({"_id": user["user_id"]})

    if not db_user:
        return {"message": "User not found"}

    # 2️⃣ Verify current password
    if not pwd_context.verify(data.current_password, db_user["password"]):
        return {"message": "Current password incorrect"}

    # 3️⃣ Hash new password
    hashed_new = pwd_context.hash(data.new_password)

    # 4️⃣ Update in DB
    collection.update_one(
        {"_id": db_user["_id"]},
        {"$set": {"password": hashed_new}}
    )

    return {"message": "Password updated successfully"} 

from fastapi import Depends, HTTPException

@app.delete("/delete-account")
def delete_account(credentials: HTTPAuthorizationCredentials = Depends(security)):

    token = credentials.credentials

    # 1️⃣ Decode token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload["user_id"]

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    # 2️⃣ Blacklist access token immediately
    blacklisted_access_tokens.add(token)

    # 3️⃣ Delete all notes of the user
    notes_collection.delete_many({"user_id": user_id})

    # 4️⃣ Delete user record
    collection.delete_one({"_id": user_id})

    return {"message": "Account and all notes deleted successfully"}





