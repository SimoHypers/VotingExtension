from fastapi import FastAPI
from app.routes import auth, posts, votes
from auth import router as auth_router  # Import the router from auth.py

app = FastAPI()

# Include authentication routes
app.include_router(auth_router, prefix="/auth")

@app.get("/")
def home():
    return {"message": "Voting API is running"}