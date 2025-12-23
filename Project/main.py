from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional

import uvicorn
from fastapi import FastAPI, Form, Request, Depends, status
from fastapi.responses import RedirectResponse, HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jinja2 import TemplateNotFound

from passlib.context import CryptContext
from jose import jwt, JWTError

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"
print("PROJECT DIR:", BASE_DIR)
print("DATABASE FILE:", DB_PATH)
SECRET_KEY = "replace_this_with_a_long_random_secret_in_prod"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

pwd_ctx = CryptContext(schemes=["argon2"], deprecated="auto")
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False)
    email = Column(String(200), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


app = FastAPI()
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def get_password_hash(password: str) -> str:
    return pwd_ctx.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


@app.get("/", response_class=HTMLResponse)
def root():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))

@app.get("/register", response_class=HTMLResponse)
def get_register():
    return FileResponse(str(BASE_DIR / "static" / "register.html"))

@app.get("/login", response_class=HTMLResponse)
def get_login():
    return FileResponse(str(BASE_DIR / "static" / "login.html"))

@app.get("/debug/users")
def get_all_users(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [
        {"id": u.id, "username": u.username, "email": u.email, "created_at": u.created_at.isoformat() if u.created_at else None}
        for u in users
    ]

@app.get("/debug/users/html", response_class=HTMLResponse)
def get_all_users_html(db: Session = Depends(get_db)):
    users = db.query(User).all()
    rows = "".join(
        f"<tr><td>{u.id}</td><td>{u.username}</td><td>{u.email}</td><td>{u.created_at}</td></tr>"
        for u in users
    )
    html = f"""
    <html><head><meta charset="utf-8"><title>Users</title></head>
    <body style="font-family:Inter,Arial,Helvetica,sans-serif;padding:20px">
      <h2>Users</h2>
      <table border="1" cellpadding="6" cellspacing="0">
        <thead><tr><th>id</th><th>username</th><th>email</th><th>created_at</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p><a href="/">Главная</a></p>
    </body></html>
    """
    return HTMLResponse(content=html)


@app.get("/discussions", response_class=HTMLResponse)
def discussions(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    user_obj = None
    if token:
        data = decode_token(token)
        if data and "sub" in data:
            try:
                uid = int(data["sub"])
                user_obj = db.query(User).filter(User.id == uid).first()
            except Exception:
                user_obj = None

    users_list = db.query(User).order_by(User.id.asc()).all()

    context = {"request": request, "user": user_obj, "users_list": users_list}

    try:
        return templates.TemplateResponse("discussions/discussions.html", context)
    except TemplateNotFound:
        html = "<html><body><h2>Страница обсуждений временно недоступна</h2></body></html>"
        return HTMLResponse(content=html)
    






    
@app.post("/register")
def post_register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    password_confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    print("POST /register:", username, email)
    if password != password_confirm:
        return HTMLResponse(
            "<h3>Пароли не совпадают.</h3><p><a href='/register'>Назад</a></p>",
            status_code=400
        )

    hashed = get_password_hash(password)
    user = User(username=username.strip(), email=email.strip().lower(), hashed_password=hashed)
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as e:
        db.rollback()
        print("DB IntegrityError:", e)
        return HTMLResponse(
            "<h3>Пользователь с таким email уже существует.</h3><p><a href='/register'>Назад</a></p>",
            status_code=400
        )

    access_token = create_access_token({"sub": str(user.id)})
    redirect_resp = RedirectResponse("/discussions", status_code=status.HTTP_303_SEE_OTHER)
    redirect_resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    print(f"Created user id={user.id} email={user.email} -> DB: {DB_PATH}")
    return redirect_resp

@app.post("/login")
def post_login(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    print("POST /login:", email)
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user:
        return HTMLResponse("<h3>Пользователь не найден.</h3><p><a href='/login'>Назад</a></p>", status_code=401)

    if not verify_password(password, user.hashed_password):
        return HTMLResponse("<h3>Неверный пароль.</h3><p><a href='/login'>Назад</a></p>", status_code=401)

    access_token = create_access_token({"sub": str(user.id)})
    redirect_resp = RedirectResponse("/discussions", status_code=status.HTTP_303_SEE_OTHER)
    redirect_resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        samesite="lax",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    print(f"User logged in id={user.id} email={user.email}")
    return redirect_resp

@app.get("/logout")
def logout():
    resp = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    resp.delete_cookie("access_token")
    return resp
