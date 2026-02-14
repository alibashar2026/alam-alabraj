[zodiac-app-for-github.zip](https://github.com/user-attachments/files/25314537/zodiac-app-for-github.zip)
[server.py](https://github.com/user-attachments/files/25314557/server.py)
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict
import uuid
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import JWTError, jwt
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configure logging FIRST before any usage
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# MongoDB connection - supports both local and Atlas
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
db_name = os.environ.get('DB_NAME', 'zodiac_app')

# Parse MongoDB URL to handle Atlas connections with authentication
try:
    client = AsyncIOMotorClient(
        mongo_url,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
        maxPoolSize=50,
        minPoolSize=10
    )
    db = client[db_name]
    logger.info(f"MongoDB connected to database: {db_name}")
except Exception as e:
    logger.error(f"MongoDB connection failed: {str(e)}")
    raise

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = os.environ.get('JWT_SECRET', 'your-secret-key-change-in-production-' + str(uuid.uuid4()))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_DAYS = 30

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# ==================== MODELS ====================

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    birthdate: str  # Format: "YYYY-MM-DD"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    birthdate: str
    zodiac_sign: str
    role: str = "user"
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse

class ZodiacSign(BaseModel):
    name_ar: str
    name_en: str
    symbol: str
    date_range: str
    element: str
    color: str
    description: str
    traits: List[str]

class DailyReading(BaseModel):
    sign: str
    date: str
    reading: str
    lucky_number: int
    lucky_color: str

class PersonalityAnalysisRequest(BaseModel):
    name: str
    birthdate: str
    zodiac_sign: str

class PersonalityAnalysisResponse(BaseModel):
    analysis: str
    created_at: datetime

class AdminContentUpdate(BaseModel):
    sign: str
    daily_reading: str

# ==================== HELPER FUNCTIONS ====================

def get_zodiac_sign(birthdate: str) -> str:
    """Determine zodiac sign from birthdate (YYYY-MM-DD)"""
    try:
        month, day = int(birthdate[5:7]), int(birthdate[8:10])
        
        if (month == 3 and day >= 21) or (month == 4 and day <= 19):
            return "aries"
        elif (month == 4 and day >= 20) or (month == 5 and day <= 20):
            return "taurus"
        elif (month == 5 and day >= 21) or (month == 6 and day <= 20):
            return "gemini"
        elif (month == 6 and day >= 21) or (month == 7 and day <= 22):
            return "cancer"
        elif (month == 7 and day >= 23) or (month == 8 and day <= 22):
            return "leo"
        elif (month == 8 and day >= 23) or (month == 9 and day <= 22):
            return "virgo"
        elif (month == 9 and day >= 23) or (month == 10 and day <= 22):
            return "libra"
        elif (month == 10 and day >= 23) or (month == 11 and day <= 21):
            return "scorpio"
        elif (month == 11 and day >= 22) or (month == 12 and day <= 21):
            return "sagittarius"
        elif (month == 12 and day >= 22) or (month == 1 and day <= 19):
            return "capricorn"
        elif (month == 1 and day >= 20) or (month == 2 and day <= 18):
            return "aquarius"
        else:  # (month == 2 and day >= 19) or (month == 3 and day <= 20)
            return "pisces"
    except:
        return "unknown"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=ACCESS_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    # Fetch user without password field for security
    user = await db.users.find_one({"id": user_id}, {"password": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def get_admin_user(user: dict = Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user

# ==================== ZODIAC DATA ====================

ZODIAC_SIGNS = {
    "aries": {
        "name_ar": "الحمل",
        "name_en": "Aries",
        "symbol": "♈",
        "date_range": "21 مارس - 19 أبريل",
        "element": "نار",
        "color": "#E74C3C",
        "description": "برج الحمل هو أول الأبراج في دائرة الأبراج، يتميز أصحابه بالشجاعة والقيادة والحماس",
        "traits": ["شجاع", "قيادي", "متحمس", "مستقل", "صريح"]
    },
    "taurus": {
        "name_ar": "الثور",
        "name_en": "Taurus",
        "symbol": "♉",
        "date_range": "20 أبريل - 20 مايو",
        "element": "تراب",
        "color": "#27AE60",
        "description": "برج الثور يتميز بالصبر والاستقرار وحب الجمال والفن",
        "traits": ["صبور", "مخلص", "عملي", "مسؤول", "محب للجمال"]
    },
    "gemini": {
        "name_ar": "الجوزاء",
        "name_en": "Gemini",
        "symbol": "♊",
        "date_range": "21 مايو - 20 يونيو",
        "element": "هواء",
        "color": "#F39C12",
        "description": "برج الجوزاء يتميز بالذكاء والتواصل والقدرة على التكيف",
        "traits": ["ذكي", "اجتماعي", "فضولي", "متعدد المواهب", "مرن"]
    },
    "cancer": {
        "name_ar": "السرطان",
        "name_en": "Cancer",
        "symbol": "♋",
        "date_range": "21 يونيو - 22 يوليو",
        "element": "ماء",
        "color": "#BDC3C7",
        "description": "برج السرطان يتميز بالحساسية والعاطفة والحدس القوي",
        "traits": ["عاطفي", "حساس", "مخلص", "حدسي", "حنون"]
    },
    "leo": {
        "name_ar": "الأسد",
        "name_en": "Leo",
        "symbol": "♌",
        "date_range": "23 يوليو - 22 أغسطس",
        "element": "نار",
        "color": "#F4D03F",
        "description": "برج الأسد يتميز بالثقة والكرم والقيادة الطبيعية",
        "traits": ["واثق", "كريم", "قيادي", "إبداعي", "دراماتيكي"]
    },
    "virgo": {
        "name_ar": "العذراء",
        "name_en": "Virgo",
        "symbol": "♍",
        "date_range": "23 أغسطس - 22 سبتمبر",
        "element": "تراب",
        "color": "#A3CB38",
        "description": "برج العذراء يتميز بالدقة والتنظيم والتحليل",
        "traits": ["دقيق", "منظم", "تحليلي", "مجتهد", "متواضع"]
    },
    "libra": {
        "name_ar": "الميزان",
        "name_en": "Libra",
        "symbol": "♎",
        "date_range": "23 سبتمبر - 22 أكتوبر",
        "element": "هواء",
        "color": "#EC7063",
        "description": "برج الميزان يتميز بالعدل والتوازن وحب السلام",
        "traits": ["عادل", "دبلوماسي", "اجتماعي", "رومانسي", "متوازن"]
    },
    "scorpio": {
        "name_ar": "العقرب",
        "name_en": "Scorpio",
        "symbol": "♏",
        "date_range": "23 أكتوبر - 21 نوفمبر",
        "element": "ماء",
        "color": "#8E44AD",
        "description": "برج العقرب يتميز بالقوة والشغف والغموض",
        "traits": ["قوي", "شغوف", "غامض", "إستراتيجي", "مخلص"]
    },
    "sagittarius": {
        "name_ar": "القوس",
        "name_en": "Sagittarius",
        "symbol": "♐",
        "date_range": "22 نوفمبر - 21 ديسمبر",
        "element": "نار",
        "color": "#9B59B6",
        "description": "برج القوس يتميز بحب المغامرة والتفاؤل والفلسفة",
        "traits": ["متفائل", "مغامر", "فيلسوف", "صريح", "حر"]
    },
    "capricorn": {
        "name_ar": "الجدي",
        "name_en": "Capricorn",
        "symbol": "♑",
        "date_range": "22 ديسمبر - 19 يناير",
        "element": "تراب",
        "color": "#34495E",
        "description": "برج الجدي يتميز بالطموح والانضباط والمسؤولية",
        "traits": ["طموح", "منضبط", "مسؤول", "صبور", "عملي"]
    },
    "aquarius": {
        "name_ar": "الدلو",
        "name_en": "Aquarius",
        "symbol": "♒",
        "date_range": "20 يناير - 18 فبراير",
        "element": "هواء",
        "color": "#3498DB",
        "description": "برج الدلو يتميز بالإبداع والاستقلالية والإنسانية",
        "traits": ["مبدع", "مستقل", "إنساني", "ذكي", "فريد"]
    },
    "pisces": {
        "name_ar": "الحوت",
        "name_en": "Pisces",
        "symbol": "♓",
        "date_range": "19 فبراير - 20 مارس",
        "element": "ماء",
        "color": "#1ABC9C",
        "description": "برج الحوت يتميز بالخيال والحساسية والتعاطف",
        "traits": ["خيالي", "حساس", "متعاطف", "روحاني", "فني"]
    }
}

# ==================== AUTH ROUTES ====================

@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    zodiac_sign = get_zodiac_sign(user_data.birthdate)
    
    user_dict = {
        "id": user_id,
        "name": user_data.name,
        "email": user_data.email,
        "password": hash_password(user_data.password),
        "birthdate": user_data.birthdate,
        "zodiac_sign": zodiac_sign,
        "role": "user",
        "created_at": datetime.utcnow()
    }
    
    await db.users.insert_one(user_dict)
    
    # Create token
    access_token = create_access_token(data={"sub": user_id})
    
    user_response = UserResponse(
        id=user_id,
        name=user_data.name,
        email=user_data.email,
        birthdate=user_data.birthdate,
        zodiac_sign=zodiac_sign,
        role="user",
        created_at=user_dict["created_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@api_router.post("/auth/login", response_model=Token)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email})
    if not user or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    access_token = create_access_token(data={"sub": user["id"]})
    
    user_response = UserResponse(
        id=user["id"],
        name=user["name"],
        email=user["email"],
        birthdate=user["birthdate"],
        zodiac_sign=user["zodiac_sign"],
        role=user.get("role", "user"),
        created_at=user["created_at"]
    )
    
    return Token(access_token=access_token, token_type="bearer", user=user_response)

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    return UserResponse(
        id=current_user["id"],
        name=current_user["name"],
        email=current_user["email"],
        birthdate=current_user["birthdate"],
        zodiac_sign=current_user["zodiac_sign"],
        role=current_user.get("role", "user"),
        created_at=current_user["created_at"]
    )

# ==================== ZODIAC ROUTES ====================

@api_router.get("/zodiac/signs")
async def get_all_zodiac_signs():
    return {"signs": ZODIAC_SIGNS}

@api_router.get("/zodiac/sign/{sign}")
async def get_zodiac_sign_info(sign: str):
    if sign not in ZODIAC_SIGNS:
        raise HTTPException(status_code=404, detail="Zodiac sign not found")
    return ZODIAC_SIGNS[sign]

@api_router.get("/zodiac/daily/{sign}")
async def get_daily_reading(sign: str):
    if sign not in ZODIAC_SIGNS:
        raise HTTPException(status_code=404, detail="Zodiac sign not found")
    
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Check if we have a reading for today
    reading = await db.daily_readings.find_one({"sign": sign, "date": today})
    
    if not reading:
        # Generate new reading with AI
        try:
            llm_key = os.environ.get('EMERGENT_LLM_KEY')
            chat = LlmChat(
                api_key=llm_key,
                session_id=f"daily-{sign}-{today}",
                system_message="أنت خبير في قراءة الأبراج. قدم قراءات يومية إيجابية ومحفزة باللغة العربية."
            )
            chat.with_model("openai", "gpt-5.2")
            
            prompt = f"اكتب قراءة برج {ZODIAC_SIGNS[sign]['name_ar']} لهذا اليوم. يجب أن تكون القراءة إيجابية ومحفزة، وتتحدث عن الحظ والعمل والحب والصحة. اكتب فقرة واحدة من 4-5 جمل."
            
            user_message = UserMessage(text=prompt)
            response = await chat.send_message(user_message)
            
            import random
            reading = {
                "sign": sign,
                "date": today,
                "reading": response,
                "lucky_number": random.randint(1, 99),
                "lucky_color": ZODIAC_SIGNS[sign]["color"]
            }
            
            await db.daily_readings.insert_one(reading)
        except Exception as e:
            logger.error(f"Error generating daily reading: {str(e)}")
            # Fallback reading
            reading = {
                "sign": sign,
                "date": today,
                "reading": f"يوم رائع ينتظر مولود برج {ZODIAC_SIGNS[sign]['name_ar']}! استعد لفرص جديدة وطاقة إيجابية.",
                "lucky_number": 7,
                "lucky_color": ZODIAC_SIGNS[sign]["color"]
            }
    
    # Remove MongoDB ObjectId before returning
    if "_id" in reading:
        del reading["_id"]
    return reading

# ==================== AI ANALYSIS ROUTES ====================

@api_router.post("/analysis/personality", response_model=PersonalityAnalysisResponse)
async def analyze_personality(
    request: PersonalityAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    try:
        llm_key = os.environ.get('EMERGENT_LLM_KEY')
        
        zodiac_info = ZODIAC_SIGNS.get(request.zodiac_sign, {})
        zodiac_name = zodiac_info.get("name_ar", request.zodiac_sign)
        
        chat = LlmChat(
            api_key=llm_key,
            session_id=f"analysis-{current_user['id']}-{datetime.now().timestamp()}",
            system_message="أنت خبير في علم الأبراج وتحليل الشخصية. قدم تحليلات شخصية عميقة ومفصلة باللغة العربية."
        )
        chat.with_model("openai", "gpt-5.2")
        
        prompt = f"""قم بتحليل شخصية شامل ومفصل للشخص التالي:
الاسم: {request.name}
تاريخ الميلاد: {request.birthdate}
البرج: {zodiac_name}

يرجى تقديم تحليل شامل يتضمن:
1. تحليل معنى الاسم وتأثيره على الشخصية
2. تحليل البرج وصفاته الأساسية
3. نقاط القوة والضعف
4. التوافق مع الآخرين
5. النصائح المهنية والعاطفية
6. الأرقام المحظوظة والألوان المناسبة

اكتب التحليل بأسلوب احترافي وإيجابي، بحوالي 300-400 كلمة."""

        user_message = UserMessage(text=prompt)
        analysis_text = await chat.send_message(user_message)
        
        # Save analysis
        analysis_doc = {
            "user_id": current_user["id"],
            "name": request.name,
            "birthdate": request.birthdate,
            "zodiac_sign": request.zodiac_sign,
            "analysis": analysis_text,
            "created_at": datetime.utcnow()
        }
        
        await db.personality_analyses.insert_one(analysis_doc)
        
        return PersonalityAnalysisResponse(
            analysis=analysis_text,
            created_at=analysis_doc["created_at"]
        )
        
    except Exception as e:
        logger.error(f"Error in personality analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error generating analysis: {str(e)}")

@api_router.get("/analysis/history")
async def get_analysis_history(current_user: dict = Depends(get_current_user)):
    analyses = await db.personality_analyses.find(
        {"user_id": current_user["id"]}
    ).sort("created_at", -1).limit(10).to_list(10)
    
    return {"analyses": analyses}

# ==================== ADMIN ROUTES ====================

@api_router.get("/admin/users")
async def get_all_users(admin_user: dict = Depends(get_admin_user), skip: int = 0, limit: int = 100):
    # Optimized: only fetch required fields, exclude password, with pagination
    users = await db.users.find(
        {},
        {"_id": 0, "id": 1, "name": 1, "email": 1, "zodiac_sign": 1, "role": 1, "created_at": 1}
    ).skip(skip).limit(limit).to_list(limit)
    total = await db.users.count_documents({})
    return {"users": users, "total": total, "skip": skip, "limit": limit}

@api_router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, admin_user: dict = Depends(get_admin_user)):
    result = await db.users.delete_one({"id": user_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}

@api_router.post("/admin/content/daily")
async def update_daily_content(
    content: AdminContentUpdate,
    admin_user: dict = Depends(get_admin_user)
):
    today = datetime.now().strftime("%Y-%m-%d")
    
    reading_doc = {
        "sign": content.sign,
        "date": today,
        "reading": content.daily_reading,
        "lucky_number": 7,
        "lucky_color": ZODIAC_SIGNS.get(content.sign, {}).get("color", "#000000"),
        "updated_by": admin_user["id"],
        "updated_at": datetime.utcnow()
    }
    
    await db.daily_readings.update_one(
        {"sign": content.sign, "date": today},
        {"$set": reading_doc},
        upsert=True
    )
    
    return {"message": "Daily reading updated successfully"}

@api_router.get("/admin/stats")
async def get_admin_stats(admin_user: dict = Depends(get_admin_user)):
    total_users = await db.users.count_documents({})
    total_analyses = await db.personality_analyses.count_documents({})
    
    # Count users by zodiac sign
    pipeline = [
        {"$group": {"_id": "$zodiac_sign", "count": {"$sum": 1}}}
    ]
    zodiac_distribution = await db.users.aggregate(pipeline).to_list(12)
    
    return {
        "total_users": total_users,
        "total_analyses": total_analyses,
        "zodiac_distribution": zodiac_distribution
    }

# ==================== SETUP ====================

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_db():
    # Create admin user if not exists
    admin = await db.users.find_one({"email": "admin@zodiac.com"})
    if not admin:
        admin_user = {
            "id": str(uuid.uuid4()),
            "name": "Admin",
            "email": "admin@zodiac.com",
            "password": hash_password("admin123"),
            "birthdate": "1990-01-01",
            "zodiac_sign": "capricorn",
            "role": "admin",
            "created_at": datetime.utcnow()
        }
        await db.users.insert_one(admin_user)
        logger.info("Admin user created: admin@zodiac.com / admin123")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
