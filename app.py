from fastapi import FastAPI, HTTPException, Depends, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
import bcrypt
from pydantic import BaseModel
from datetime import datetime, timedelta
app = FastAPI(title="Hospital Management",
            description="To make appointment slots")

def hash_password(plain_password):
    passwd_bytes = plain_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_value = bcrypt.hashpw(passwd_bytes, salt)
    return hashed_value.decode('utf-8')

def verify_password(plain_password, hashed_password):
    plain_bytes = plain_password.encode('utf-8')
    hasehed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(plain_bytes, hasehed_bytes)

class PatientDetails(BaseModel):
    name : str
    email : str
    phone : str


class BookSlot(BaseModel):
    appointment_type : str
    date : str
    start_time : str
    end_time : str
    patient : PatientDetails
    reason : str



faker_db = {
    "meena":{
        "username": "meena",
        "password": hash_password("Think@123")
    }
}

SECRET_KEY = 'Welcome@123'
ALGORITHM = "HS256"
oauth_scheme = OAuth2PasswordBearer(tokenUrl = '/login')

calendly_data = {
    '2025-11-11':[
        {"start_time" : "9.00", "end_time" : "9.30", "available" : True},
        {"start_time" : "9.30", "end_time" : "10.00", "available" : True}
    ]
}
def get_current_user(token : str = Depends(oauth_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        print(f"{payload}------------------>")        
        if not payload.get('sub'):
            raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "No username")
        return payload.get('sub')
    except JWTError:
        raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Invalid or Expired token")


@app.post('/login')
def login(data: OAuth2PasswordRequestForm = Depends()):
    # copied_data = data.copy()
    username = data.username
    password = data.password
    if not username in faker_db.keys() or not verify_password(password, faker_db[username]['password']):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail = "INVALID USERNAME and PASSWORD")
    exp = datetime.utcnow() + timedelta(minutes = 30)
    
    token = jwt.encode({'sub': username, 'exp': exp}, SECRET_KEY, ALGORITHM)
    return {"access_token" : token, "type": "Bearer", "expired at": exp, "current time": datetime.utcnow()}


@app.get('/get_users')
def get_users(user: str = Depends(get_current_user)):
    return list(faker_db.keys())

@app.get('/api/calendly/availablity')
def get_available_slots(user : str = Depends(get_current_user), date : str = Query(..., description="YYYY-MM-DD")):
    if calendly_data.get(date):
        return calendly_data[date]
    return "Slots are Empty"

@app.post('/api/calendly/book')
def book_slot(request : BookSlot, user : str = Depends(get_current_user)):
    date = request.date
    slot_list = []
    slot_dict = {}
    if date:
        if date not in calendly_data.keys(): 
            calendly_data[date] = slot_list

        slot_list = calendly_data[date]
        for slot in slot_list:
            if not slot.get('available'):
                return f"{request.start_time} to {request.end_time} already booked on {date}"
            
        slot_dict = {
            'start_time' : request.start_time,
            'end_time' : request.end_time,
            'available' : False
        }
        slot_list.append(slot_dict)
        return 'slot booked successfully'



