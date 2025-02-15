from fastapi import FastAPI
from app.routes import auth, posts, votes

app = FastAPI()

@app.get("/")
def home():
    return {"message": "Voting API is running"}