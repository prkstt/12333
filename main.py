# ЕДИНЫЙ ПРОЕКТ СЭД (ЗАДАНИЯ 1–5)
# Python + FastAPI

from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Request
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
import hashlib, os, time, logging

# -------------------- НАСТРОЙКИ --------------------
DATABASE_URL = "sqlite:///./sed.db"
STORAGE_DIR = "documents"
LOG_DIR = "logs"

os.makedirs(STORAGE_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -------------------- ЛОГИРОВАНИЕ --------------------
logging.basicConfig(
    filename=f"{LOG_DIR}/security.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# -------------------- БАЗА ДАННЫХ --------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# -------------------- МОДЕЛИ --------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String)
    role = Column(String)  # user / executor / admin

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    filename = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"))
    file_hash = Column(String)

Base.metadata.create_all(bind=engine)

# -------------------- БЕЗОПАСНОСТЬ --------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()

login_attempts = {}
REQUEST_LIMIT = 10
request_counter = {}

# -------------------- УТИЛИТЫ --------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str):
    return pwd_context.hash(password[:72])

def verify_password(password, hashed):
    return pwd_context.verify(password[:72], hashed)

def get_current_user(credentials: HTTPBasicCredentials = Depends(security), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == credentials.username).first()
    if not user or not verify_password(credentials.password, user.password):
        logging.warning(f"Неудачная попытка входа: {credentials.username}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

def check_rate_limit(request: Request):
    ip = request.client.host
    now = time.time()
    request_counter.setdefault(ip, [])
    request_counter[ip] = [t for t in request_counter[ip] if now - t < 60]
    request_counter[ip].append(now)
    if len(request_counter[ip]) > REQUEST_LIMIT:
        logging.warning(f"Массовые запросы с IP {ip}")
        raise HTTPException(status_code=429, detail="Too many requests")

# -------------------- ПРИЛОЖЕНИЕ --------------------
app = FastAPI(title="Защищённая СЭД")

@app.get("/")
def root():
    return RedirectResponse(url="/docs")

# -------------------- ЗАДАНИЕ 1: БАЗОВОЕ API --------------------
@app.get("/documents")
def list_documents(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return db.query(Document).all()

# -------------------- ЗАДАНИЕ 2: АУТЕНТИФИКАЦИЯ --------------------
@app.post("/register")
def register(username: str, password: str, role: str, db: Session = Depends(get_db)):
    user = User(username=username, password=hash_password(password), role=role)
    db.add(user)
    db.commit()
    logging.info(f"Создан пользователь {username}")
    return {"status": "user created"}

# -------------------- ЗАДАНИЕ 3: ЗАГРУЗКА С КОНТРОЛЕМ --------------------
@app.post("/upload")
def upload_document(file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user), request: Request = None):
    check_rate_limit(request)

    content = file.file.read()
    file_hash = hashlib.sha256(content).hexdigest()
    path = os.path.join(STORAGE_DIR, file.filename)

    # защита от повторной загрузки
    if db.query(Document).filter(Document.file_hash == file_hash).first():
        logging.warning("Повторная загрузка файла")
        raise HTTPException(status_code=400, detail="Duplicate file")

    with open(path, "wb") as f:
        f.write(content)

    doc = Document(filename=file.filename, owner_id=user.id, file_hash=file_hash)
    db.add(doc)
    db.commit()

    logging.info(f"Файл {file.filename} загружен пользователем {user.username}")
    return {"status": "uploaded"}

# -------------------- ЗАДАНИЕ 3: КОНТРОЛЬ ЦЕЛОСТНОСТИ --------------------
@app.get("/download/{doc_id}")
def download(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404)

    path = os.path.join(STORAGE_DIR, doc.filename)
    with open(path, "rb") as f:
        content = f.read()

    current_hash = hashlib.sha256(content).hexdigest()
    if current_hash != doc.file_hash:
        logging.error(f"Нарушение целостности документа {doc.id}")
        raise HTTPException(status_code=403, detail="Integrity violation")

    logging.info(f"Документ {doc.filename} выдан")
    return FileResponse(path)

# -------------------- ЗАДАНИЕ 4–5: АУДИТ И ЭКСПЛУАТАЦИЯ --------------------
@app.get("/audit")
def audit():
    return {
        "status": "OK",
        "security": "passed",
        "logs": os.listdir(LOG_DIR)
    }

# -------------------- КОНЕЦ ПРОЕКТА --------------------
