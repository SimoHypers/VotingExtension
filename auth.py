import firebase_admin
from firebase_admin import credentials, firestore
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from datetime import datetime, timedelta
import jwt

# Firebase Initialization
cred = credentials.Certificate("serviceAccount.json")  # Use your Firebase service account file
firebase_admin.initialize_app(cred)
db = firestore.client()

# FastAPI Router
router = APIRouter()

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# JWT settings
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# User registration route
@router.post("/signup", status_code=201)
def signup(username: str, email: str, password: str):
    user_ref = db.collection("users").document(username)
    if user_ref.get().exists:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = hash_password(password)
    user_ref.set({"email": email, "hashed_password": hashed_pw})

    return {"detail": "User created successfully"}

# User login route
@router.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_ref = db.collection("users").document(form_data.username)
    user_doc = user_ref.get()

    if not user_doc.exists or not verify_password(form_data.password, user_doc.to_dict()["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate a new token
    access_token = create_access_token({"sub": form_data.username}, timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    
    # Store the token in Firestore
    user_ref.update({"access_token": access_token})

    return {"access_token": access_token, "token_type": "bearer"}

# Get current user from token
def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        user_ref = db.collection("users").document(username)
        user_doc = user_ref.get()

        if not user_doc.exists:
            raise HTTPException(status_code=401, detail="User not found")

        user_data = user_doc.to_dict()
        return {"username": username, "email": user_data["email"]}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

@router.post("/validate-token")
def validate_token(client_token: str):
    try:
        # Decode the client's token
        payload = jwt.decode(client_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Retrieve the user's stored token (assuming Firestore stores it)
        user_ref = db.collection("users").document(username)
        user_doc = user_ref.get()

        if not user_doc.exists:
            raise HTTPException(status_code=401, detail="User not found")

        stored_token = user_doc.to_dict().get("access_token")

        if stored_token != client_token:
            raise HTTPException(status_code=401, detail="Token mismatch")

        return {"detail": "Token is valid"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")


# Protected route
@router.get("/profile")
def profile(user: dict = Depends(get_current_user)):
    return user
