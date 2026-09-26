from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
import uvicorn, os, bcrypt, jwt, datetime, json, secrets
import psycopg as psycopg2

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL","ridhimaverma2307@gmail.com")
ADMIN_HASH  = os.getenv("ADMIN_PASSWORD_HASH","")
JWT_SECRET  = os.getenv("JWT_SECRET","fallback_secret_123")
ADMIN_JWT   = os.getenv("ADMIN_JWT_SECRET","fallback_admin_456")
DB_URL      = os.getenv("DATABASE_URL","")

def get_db():
    return psycopg2.connect(DB_URL)

def init_db():
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(255),
                plan VARCHAR(50) DEFAULT 'free',
                webhook_url VARCHAR(500),
                license_key VARCHAR(100),
                created_at TIMESTAMP DEFAULT NOW(),
                is_active BOOLEAN DEFAULT TRUE
            );
            CREATE TABLE IF NOT EXISTS signals (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                broker VARCHAR(100),
                symbol VARCHAR(50),
                action VARCHAR(20),
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS license_keys (
                license_key VARCHAR(50) PRIMARY KEY,
                product VARCHAR(50) DEFAULT 'AG_TRADE_RECEIVER',
                max_members INT DEFAULT 1,
                buyer_name VARCHAR(255),
                buyer_email VARCHAR(255),
                plan_name VARCHAR(100),
                active BOOLEAN DEFAULT TRUE,
                expiry_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS license_members (
                id SERIAL PRIMARY KEY,
                license_key VARCHAR(50) REFERENCES license_keys(license_key) ON DELETE CASCADE,
                member_name VARCHAR(255),
                account_number VARCHAR(50),
                added_at TIMESTAMP DEFAULT NOW()
            );
        """)
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        print("DB init error:", e)

init_db()

def make_token(data, secret, hours=24):
    data["exp"] = datetime.datetime.utcnow() + datetime.timedelta(hours=hours)
    return jwt.encode(data, secret, algorithm="HS256")

def verify_token(token, secret):
    try: return jwt.decode(token, secret, algorithms=["HS256"])
    except: return None

@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    email = body.get("email","").lower().strip()
    password = body.get("password","")
    if email == ADMIN_EMAIL.lower() or email == "":
        # password-only admin login (email optional)
        if ADMIN_HASH and bcrypt.checkpw(password.encode(), ADMIN_HASH.encode()):
            token = make_token({"email":ADMIN_EMAIL,"role":"admin"}, ADMIN_JWT, hours=12)
            return JSONResponse({"token":token,"role":"admin","name":"AG Admin"})
        raise HTTPException(401, "Wrong password")
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT id,password_hash,name,plan FROM users WHERE email=%s AND is_active=TRUE",(email,))
        row=cur.fetchone(); cur.close(); conn.close()
        if not row: raise HTTPException(401,"User not found")
        if not bcrypt.checkpw(password.encode(),row[1].encode()): raise HTTPException(401,"Wrong password")
        token=make_token({"user_id":row[0],"email":email,"role":"user"},JWT_SECRET)
        return JSONResponse({"token":token,"role":"user","name":row[2] or email,"plan":row[3]})
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/auth/signup")
async def signup(request: Request):
    body = await request.json()
    email=body.get("email","").lower().strip()
    password=body.get("password","")
    name=body.get("name","")
    if not email or not password or len(password)<6:
        raise HTTPException(400,"Email and password (min 6 chars) required")
    hashed=bcrypt.hashpw(password.encode(),bcrypt.gensalt(10)).decode()
    lic="AGTB-"+secrets.token_hex(6).upper()
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("INSERT INTO users (email,password_hash,name,license_key) VALUES (%s,%s,%s,%s) RETURNING id",
                    (email,hashed,name,lic))
        uid=cur.fetchone()[0]; conn.commit(); cur.close(); conn.close()
        token=make_token({"user_id":uid,"email":email,"role":"user"},JWT_SECRET)
        return JSONResponse({"token":token,"role":"user","name":name or email,"plan":"free"})
    except Exception as e:
        if "unique" in str(e).lower(): raise HTTPException(409,"Email already registered")
        raise HTTPException(500,str(e))

@app.get("/api/user/me")
async def get_me(request: Request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,JWT_SECRET)
    if not data: raise HTTPException(401,"Unauthorized")
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT id,email,name,plan,webhook_url,license_key,created_at FROM users WHERE id=%s",(data["user_id"],))
        row=cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM signals WHERE user_id=%s",(data["user_id"],))
        sig=cur.fetchone()[0]; cur.close(); conn.close()
        return JSONResponse({"id":row[0],"email":row[1],"name":row[2],"plan":row[3],
                             "webhook_url":row[4],"license_key":row[5],"created_at":str(row[6]),"signal_count":sig})
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,str(e))

def admin_check(request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,ADMIN_JWT)
    if not data or data.get("role")!="admin": raise HTTPException(403,"Admin only")


@app.post("/api/admin/forgot-password")
async def forgot_password():
    # In production: send email. For now return the hint.
    import hashlib, time
    reset_code = hashlib.sha256((ADMIN_EMAIL + str(int(time.time()//3600))).encode()).hexdigest()[:8].upper()
    # Store in env or memory (simple: just return to admin email)
    # For now: log it (Render logs only admin can see)
    print(f"ADMIN RESET CODE: {reset_code}")
    return JSONResponse({"ok": True, "msg": "Reset code sent to admin email (check Render logs)"})


# ── LICENSE ROUTES ──

@app.post("/api/license/verify")
async def verify_license(request: Request):
    body = await request.json()
    key = body.get("license_key","").strip()
    account = body.get("account_number","").strip()
    product = body.get("product","AG_TRADE_RECEIVER")
    if not key:
        return JSONResponse({"status":"error","reason":"MISSING_KEY"},status_code=400)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT active,expiry_date FROM license_keys WHERE license_key=%s",(key,))
        row=cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return JSONResponse({"status":"error","reason":"INVALID_KEY"},status_code=403)
        active,expiry=row
        if not active:
            cur.close(); conn.close()
            return JSONResponse({"status":"error","reason":"KEY_DISABLED"},status_code=403)
        if expiry and datetime.datetime.utcnow() > expiry:
            cur.close(); conn.close()
            return JSONResponse({"status":"error","reason":"EXPIRED"},status_code=403)
        if product == "AG_TRADE_SENDER":
            cur.close(); conn.close()
            return JSONResponse({"status":"ok"})
        cur.execute("SELECT id FROM license_members WHERE license_key=%s AND account_number=%s",(key,account))
        member=cur.fetchone()
        cur.close(); conn.close()
        if member:
            return JSONResponse({"status":"ok"})
        return JSONResponse({"status":"error","reason":"NOT_REGISTERED"},status_code=403)
    except Exception as e:
        return JSONResponse({"status":"error","reason":str(e)},status_code=500)

@app.post("/api/license/create")
async def create_license(request: Request):
    admin_check(request)
    body = await request.json()
    key = "AGR-" + secrets.token_hex(4).upper() + "-" + secrets.token_hex(4).upper()
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("INSERT INTO license_keys (license_key,product,max_members,buyer_name,buyer_email,plan_name) VALUES (%s,%s,%s,%s,%s,%s)",
                    (key,body.get("product","AG_TRADE_RECEIVER"),int(body.get("max_members",1)),
                     body.get("buyer_name",""),body.get("buyer_email",""),body.get("plan_name","Standard")))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"key":key})
    except Exception as e: raise HTTPException(500,str(e))

@app.get("/api/license/list")
async def list_licenses(request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("""SELECT lk.license_key,lk.product,lk.max_members,lk.buyer_name,
                   lk.buyer_email,lk.plan_name,lk.active,lk.created_at,
                   COUNT(lm.id) as mc
            FROM license_keys lk LEFT JOIN license_members lm ON lk.license_key=lm.license_key
            GROUP BY lk.license_key ORDER BY lk.created_at DESC""")
        rows=cur.fetchall(); cur.close(); conn.close()
        return JSONResponse([{"key":r[0],"product":r[1],"max_members":r[2],"buyer_name":r[3],
            "buyer_email":r[4],"plan_name":r[5],"active":r[6],"created":str(r[7]),"member_count":r[8]} for r in rows])
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/license/{key}/add-member")
async def add_member(key: str, request: Request):
    admin_check(request)
    body = await request.json()
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT max_members FROM license_keys WHERE license_key=%s",(key,))
        row=cur.fetchone()
        if not row: raise HTTPException(404,"Key not found")
        cur.execute("SELECT COUNT(*) FROM license_members WHERE license_key=%s",(key,))
        if cur.fetchone()[0] >= row[0]: raise HTTPException(400,"Member limit reached")
        cur.execute("INSERT INTO license_members (license_key,member_name,account_number) VALUES (%s,%s,%s)",
                    (key,body.get("member_name",""),body.get("account_number","")))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True})
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,str(e))

@app.get("/api/license/{key}/members")
async def get_members(key: str, request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT id,member_name,account_number,added_at FROM license_members WHERE license_key=%s ORDER BY added_at",(key,))
        rows=cur.fetchall(); cur.close(); conn.close()
        return JSONResponse([{"id":r[0],"name":r[1],"account":r[2],"added":str(r[3])} for r in rows])
    except Exception as e: raise HTTPException(500,str(e))

@app.delete("/api/license/{key}/member/{mid}")
async def remove_member(key: str, mid: int, request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("DELETE FROM license_members WHERE id=%s AND license_key=%s",(mid,key))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True})
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/license/{key}/toggle")
async def toggle_license(key: str, request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE license_keys SET active=NOT active WHERE license_key=%s RETURNING active",(key,))
        result=cur.fetchone(); conn.commit(); cur.close(); conn.close()
        return JSONResponse({"active":result[0]})
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/license/register")
async def register_members(request: Request):
    body = await request.json()
    key = body.get("license_key","").strip()
    members = body.get("members",[])
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT max_members,active FROM license_keys WHERE license_key=%s",(key,))
        row=cur.fetchone()
        if not row or not row[1]: raise HTTPException(403,"Invalid or inactive license key")
        if len(members) > row[0]: raise HTTPException(400,f"Max {row[0]} members allowed")
        cur.execute("SELECT COUNT(*) FROM license_members WHERE license_key=%s",(key,))
        if cur.fetchone()[0] > 0: raise HTTPException(409,"Already registered")
        for m in members:
            cur.execute("INSERT INTO license_members (license_key,member_name,account_number) VALUES (%s,%s,%s)",
                        (key,m.get("name",""),m.get("account","")))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True})
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,str(e))


# ── USER SELF-SERVICE LICENSE ROUTES ──

@app.post("/api/user/get-license")
async def user_get_license(request: Request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,JWT_SECRET)
    if not data: raise HTTPException(401,"Unauthorized")
    uid=data["user_id"]
    body=await request.json()
    max_members=int(body.get("max_members",1))
    if max_members not in [1,5,10]: max_members=1
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT license_key FROM users WHERE id=%s",(uid,))
        row=cur.fetchone()
        if row and row[0]:
            cur.execute("UPDATE license_keys SET max_members=%s WHERE license_key=%s",(max_members,row[0]))
            conn.commit(); cur.close(); conn.close()
            return JSONResponse({"license_key":row[0],"max_members":max_members,"existing":True})
        key="AGTB-"+secrets.token_hex(3).upper()+"-"+secrets.token_hex(3).upper()+"-"+secrets.token_hex(3).upper()
        cur.execute("SELECT email,name FROM users WHERE id=%s",(uid,))
        urow=cur.fetchone()
        cur.execute("INSERT INTO license_keys (license_key,product,max_members,buyer_email,buyer_name,plan_name) VALUES (%s,%s,%s,%s,%s,%s)",
                    (key,"AG_TRADE_RECEIVER",max_members,urow[0],urow[1],f"MT5-MT5-{max_members}"))
        cur.execute("UPDATE users SET license_key=%s WHERE id=%s",(key,uid))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"license_key":key,"max_members":max_members,"existing":False})
    except Exception as e: raise HTTPException(500,str(e))

@app.get("/api/user/my-license")
async def user_my_license(request: Request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,JWT_SECRET)
    if not data: raise HTTPException(401,"Unauthorized")
    uid=data["user_id"]
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT license_key FROM users WHERE id=%s",(uid,))
        row=cur.fetchone()
        if not row or not row[0]:
            cur.close(); conn.close()
            return JSONResponse({"license_key":None,"members":[],"max_members":0})
        key=row[0]
        cur.execute("SELECT max_members,active FROM license_keys WHERE license_key=%s",(key,))
        lrow=cur.fetchone()
        cur.execute("SELECT id,member_name,account_number,added_at FROM license_members WHERE license_key=%s ORDER BY added_at",(key,))
        members=[{"id":r[0],"name":r[1],"account":r[2],"added":str(r[3])} for r in cur.fetchall()]
        cur.close(); conn.close()
        return JSONResponse({"license_key":key,"max_members":lrow[0] if lrow else 1,"active":lrow[1] if lrow else True,"members":members})
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/user/add-member")
async def user_add_member(request: Request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,JWT_SECRET)
    if not data: raise HTTPException(401,"Unauthorized")
    uid=data["user_id"]
    body=await request.json()
    name=body.get("member_name","").strip()
    account=body.get("account_number","").strip()
    if not account: raise HTTPException(400,"Account number required")
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT license_key FROM users WHERE id=%s",(uid,))
        row=cur.fetchone()
        if not row or not row[0]: raise HTTPException(400,"Get a license first")
        key=row[0]
        cur.execute("SELECT max_members FROM license_keys WHERE license_key=%s",(key,))
        lrow=cur.fetchone()
        cur.execute("SELECT COUNT(*) FROM license_members WHERE license_key=%s",(key,))
        cnt=cur.fetchone()[0]
        if cnt >= lrow[0]: raise HTTPException(400,f"Max {lrow[0]} members reached")
        cur.execute("SELECT id FROM license_members WHERE license_key=%s AND account_number=%s",(key,account))
        if cur.fetchone(): raise HTTPException(409,"Account already registered")
        cur.execute("INSERT INTO license_members (license_key,member_name,account_number) VALUES (%s,%s,%s) RETURNING id",
                    (key,name or "MT5 Account",account))
        new_id=cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True,"id":new_id})
    except HTTPException: raise
    except Exception as e: raise HTTPException(500,str(e))

@app.delete("/api/user/remove-member/{mid}")
async def user_remove_member(mid: int, request: Request):
    token=request.headers.get("Authorization","").replace("Bearer ","")
    data=verify_token(token,JWT_SECRET)
    if not data: raise HTTPException(401,"Unauthorized")
    uid=data["user_id"]
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT license_key FROM users WHERE id=%s",(uid,))
        row=cur.fetchone()
        if not row or not row[0]: raise HTTPException(400,"No license")
        key=row[0]
        cur.execute("DELETE FROM license_members WHERE id=%s AND license_key=%s",(mid,key))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True})
    except Exception as e: raise HTTPException(500,str(e))

@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users"); total=cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE is_active=TRUE"); active=cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users WHERE plan!='free'"); paid=cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM signals"); sigs=cur.fetchone()[0]
        cur.close(); conn.close()
        return JSONResponse({"total_users":total,"active_users":active,"paid_users":paid,"total_signals":sigs})
    except Exception as e: raise HTTPException(500,str(e))

@app.get("/api/admin/users")
async def admin_users(request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT id,email,name,plan,is_active,created_at,license_key FROM users ORDER BY created_at DESC")
        rows=cur.fetchall(); cur.close(); conn.close()
        return JSONResponse([{"id":r[0],"email":r[1],"name":r[2],"plan":r[3],"active":r[4],"created":str(r[5]),"license":r[6]} for r in rows])
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/admin/user/{user_id}/toggle")
async def toggle_user(user_id: int, request: Request):
    admin_check(request)
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE users SET is_active=NOT is_active WHERE id=%s RETURNING is_active",(user_id,))
        result=cur.fetchone(); conn.commit(); cur.close(); conn.close()
        return JSONResponse({"active":result[0]})
    except Exception as e: raise HTTPException(500,str(e))

@app.post("/api/admin/user/{user_id}/plan")
async def change_plan(user_id: int, request: Request):
    admin_check(request)
    body=await request.json()
    plan=body.get("plan","free")
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("UPDATE users SET plan=%s WHERE id=%s",(plan,user_id))
        conn.commit(); cur.close(); conn.close()
        return JSONResponse({"ok":True})
    except Exception as e: raise HTTPException(500,str(e))


LOGO_B64 = "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"

@app.get("/logo.jpg")
async def serve_logo():
    import base64
    data = base64.b64decode(LOGO_B64)
    return Response(content=data, media_type="image/jpeg")

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AG TradeBridge</title>
<link rel="icon" type="image/jpeg" href="/logo.jpg">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
  *,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
  :root{
    --bg:#08070a;--panel:#100f15;--panel2:#1a1825;
    --gold:#f7c04a;--gold-deep:#d98e2b;
    --violet:#38bdf8;--violet-dim:#0284c7;
    --green:#4ade80;--red:#f26d6d;
    --text:#f4efe6;--muted:#9d95a6;--border:#2a2536;
  }
  html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;overflow:hidden;cursor:none;}

  /* CURSOR */
  #cursor{position:fixed;width:14px;height:14px;background:var(--violet);border-radius:50%;pointer-events:none;z-index:9999;transform:translate(-50%,-50%);mix-blend-mode:screen;transition:width .15s,height .15s,background .2s;}
  #cursor-ring{position:fixed;width:44px;height:44px;border:1.5px solid rgba(56,189,248,0.6);border-radius:50%;pointer-events:none;z-index:9998;transform:translate(-50%,-50%);transition:width .2s,height .2s,border-color .2s;}
  body.hov #cursor{width:22px;height:22px;background:var(--gold);}
  body.hov #cursor-ring{width:58px;height:58px;border-color:rgba(247,192,74,0.7);}

  /* BIG PURPLE MOUSE GLOW */
  #mglow{position:fixed;pointer-events:none;z-index:0;width:1400px;height:1400px;transform:translate(-50%,-50%);background:radial-gradient(circle,rgba(14,165,233,0.32) 0%,rgba(56,189,248,0.14) 35%,rgba(14,165,233,0.05) 60%,transparent 72%);border-radius:50%;transition:left .04s,top .04s;}

  /* AMBIENT ORBS */
  .orb{position:fixed;border-radius:50%;pointer-events:none;z-index:0;filter:blur(90px);}
  .orb1{width:600px;height:600px;top:-150px;left:20%;background:rgba(80,40,200,0.14);animation:od1 20s ease-in-out infinite;}
  .orb2{width:450px;height:450px;bottom:-120px;right:5%;background:rgba(247,192,74,0.09);animation:od2 25s ease-in-out infinite;}
  .orb3{width:380px;height:380px;top:35%;left:-100px;background:rgba(70,30,180,0.11);animation:od3 18s ease-in-out infinite;}
  @keyframes od1{0%,100%{transform:translate(0,0)}50%{transform:translate(50px,35px)}}
  @keyframes od2{0%,100%{transform:translate(0,0)}50%{transform:translate(-35px,-25px)}}
  @keyframes od3{0%,100%{transform:translate(0,0)}50%{transform:translate(25px,45px)}}

  #bg-canvas{position:fixed;inset:0;z-index:0;pointer-events:none;}
  .shell{position:relative;z-index:1;display:flex;height:100vh;width:100vw;}

  /* SIDEBAR */
  .sidebar{width:244px;min-width:244px;background:linear-gradient(180deg,rgba(14,13,20,0.98),rgba(8,7,10,0.98));border-right:1px solid var(--border);display:flex;flex-direction:column;position:relative;z-index:2;overflow:hidden;backdrop-filter:blur(24px);}
  .sb-inner{display:flex;flex-direction:column;height:100%;}
  .brand{padding:24px 20px 20px;border-bottom:1px solid var(--border);flex-shrink:0;}
  .brand-logo{display:flex;align-items:center;gap:10px;margin-bottom:4px;}
  .brand-icon{width:32px;height:32px;border-radius:9px;background:linear-gradient(135deg,var(--violet-dim),var(--violet));display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0;box-shadow:0 0 18px rgba(56,189,248,0.5);}
  .brand-name{font-size:16px;font-weight:700;color:var(--text);letter-spacing:-0.3px;}
  .brand-sub{font-size:9px;color:var(--gold);font-family:'Space Mono',monospace;letter-spacing:2px;margin-top:4px;padding-left:42px;}
  .user-btn{margin:14px 10px 4px;display:flex;align-items:center;gap:10px;padding:10px 12px;border-radius:10px;background:linear-gradient(135deg,rgba(56,189,248,0.1),rgba(26,24,37,0.8));border:1px solid rgba(56,189,248,0.22);cursor:none;transition:all 0.2s;font-size:12px;font-family:'Space Grotesk',sans-serif;flex-shrink:0;}
  .user-btn:hover{border-color:rgba(56,189,248,0.5);}
  .user-avatar{width:30px;height:30px;border-radius:50%;background:linear-gradient(135deg,var(--violet-dim),var(--gold-deep));display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;color:#fff;flex-shrink:0;box-shadow:0 0 14px rgba(56,189,248,0.45);}
  .user-info{flex:1;}
  .user-name{font-size:12px;font-weight:600;color:var(--text);}
  .user-plan{font-size:10px;color:var(--muted);}
  .nav-label{font-size:9px;letter-spacing:2px;color:var(--muted);padding:16px 20px 8px;font-family:'Space Mono',monospace;opacity:0.5;flex-shrink:0;}
  .nav-btn{display:flex;align-items:center;gap:12px;padding:12px 14px;margin:2px 10px;border-radius:10px;cursor:none;border:1px solid transparent;background:transparent;color:var(--muted);font-size:12.5px;font-family:'Space Grotesk',sans-serif;font-weight:500;transition:all 0.18s;text-align:left;width:calc(100% - 20px);flex-shrink:0;position:relative;overflow:hidden;}
  .nav-btn::after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,rgba(56,189,248,0.1),transparent);opacity:0;transition:opacity 0.18s;border-radius:10px;}
  .nav-btn:hover::after,.nav-btn.active::after{opacity:1;}
  .nav-btn:hover,.nav-btn.active{color:var(--text);border-color:rgba(56,189,248,0.28);}
  .nav-btn.active{background:rgba(56,189,248,0.07);border-color:rgba(56,189,248,0.4);}
  .nav-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;flex-shrink:0;background:var(--panel2);border:1px solid var(--border);transition:all 0.18s;position:relative;z-index:1;}
  .nav-btn:hover .nav-icon,.nav-btn.active .nav-icon{background:rgba(56,189,248,0.22);border-color:rgba(56,189,248,0.45);}
  .nav-text{flex:1;position:relative;z-index:1;line-height:1.3;}
  .arr{font-size:15px;color:var(--muted);flex-shrink:0;position:relative;z-index:1;transition:transform 0.18s,color 0.18s;}
  .nav-btn:hover .arr,.nav-btn.active .arr{transform:translateX(3px);color:var(--violet);}
  .sb-footer{margin-top:auto;padding:14px 20px;border-top:1px solid var(--border);flex-shrink:0;}
  .status-dot{display:flex;align-items:center;gap:8px;font-size:11px;color:var(--muted);}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 10px var(--green);animation:pulse 2s infinite;}
  @keyframes pulse{0%,100%{opacity:1;box-shadow:0 0 10px var(--green)}50%{opacity:0.5;box-shadow:0 0 4px var(--green)}}

  /* MAIN */
  .main{flex:1;display:flex;flex-direction:column;overflow:hidden;min-width:0;position:relative;}
  .page{position:absolute;inset:0;overflow-y:auto;opacity:0;pointer-events:none;transition:opacity 0.22s;}
  .page.active{opacity:1;pointer-events:all;}
  .page::-webkit-scrollbar{width:4px;}
  .page::-webkit-scrollbar-thumb{background:var(--border);border-radius:2px;}

  /* HOME */
  .hero{display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100%;padding:44px 40px;text-align:center;}
  .hero-badge{display:inline-flex;align-items:center;gap:8px;font-family:'Space Mono',monospace;font-size:10px;letter-spacing:1.5px;color:var(--violet);border:1px solid rgba(56,189,248,0.32);background:rgba(56,189,248,0.08);border-radius:20px;padding:6px 18px;margin-bottom:28px;}
  .badge-dot{width:6px;height:6px;border-radius:50%;background:var(--violet);animation:pulse 2s infinite;}
  .hero-title{font-size:clamp(36px,4.5vw,62px);font-weight:700;line-height:1.08;letter-spacing:-1.5px;margin-bottom:20px;max-width:640px;}
  .grad{display:block;background:linear-gradient(90deg,var(--violet) 0%,var(--gold) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .hero-desc{font-size:15px;color:var(--muted);max-width:420px;line-height:1.75;margin-bottom:40px;}

  .ticker-wrap{width:100%;max-width:680px;overflow:hidden;margin-bottom:40px;border:1px solid var(--border);border-radius:10px;background:var(--panel);position:relative;}
  .ticker-wrap::before,.ticker-wrap::after{content:'';position:absolute;top:0;bottom:0;width:60px;z-index:2;pointer-events:none;}
  .ticker-wrap::before{left:0;background:linear-gradient(90deg,var(--panel),transparent);}
  .ticker-wrap::after{right:0;background:linear-gradient(-90deg,var(--panel),transparent);}
  .ticker{display:flex;animation:tick 32s linear infinite;width:max-content;padding:10px 0;}
  @keyframes tick{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
  .ticker-item{display:flex;align-items:center;gap:10px;padding:4px 18px;border-right:1px solid var(--border);white-space:nowrap;flex-shrink:0;}
  .ticker-sym{font-family:'Space Mono',monospace;font-size:11px;font-weight:700;color:var(--text);}
  .ticker-price{font-family:'Space Mono',monospace;font-size:11px;color:var(--muted);}
  .ticker-chg{font-size:10px;font-weight:700;font-family:'Space Mono',monospace;padding:2px 6px;border-radius:4px;}
  .up{color:var(--green);background:rgba(74,222,128,0.1);}
  .dn{color:var(--red);background:rgba(242,109,109,0.1);}

  .stats-row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-bottom:36px;}
  .stat-card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:20px 28px;text-align:center;min-width:110px;position:relative;overflow:hidden;transition:border-color 0.2s,transform 0.2s;}
  .stat-card:hover{border-color:rgba(56,189,248,0.4);transform:translateY(-2px);}
  .stat-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(56,189,248,0.07),transparent 60%);}
  .stat-num{font-size:28px;font-weight:700;font-family:'Space Mono',monospace;background:linear-gradient(135deg,var(--gold),var(--gold-deep));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;position:relative;}
  .stat-label{font-size:11px;color:var(--muted);margin-top:4px;position:relative;}

  .cta-row{display:flex;gap:12px;flex-wrap:wrap;justify-content:center;}
  .cta-btn{padding:13px 30px;border-radius:9px;font-size:13px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;border:none;}
  .cta-primary{background:linear-gradient(135deg,var(--violet),var(--violet-dim));color:#fff;box-shadow:0 4px 24px rgba(56,189,248,0.3);}
  .cta-primary:hover{box-shadow:0 4px 36px rgba(56,189,248,0.55);transform:translateY(-2px);}
  .cta-outline{background:transparent;border:1px solid var(--border)!important;color:var(--muted);}
  .cta-outline:hover{border-color:var(--violet)!important;color:var(--text);}

  /* BROKER PAGE */

  /* ── DASHBOARD ── */
  .dash-wrap{padding:32px 36px;overflow-y:auto;height:100%;}
  .dash-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;}
  .dash-title{font-size:26px;font-weight:700;letter-spacing:-0.5px;}
  .dash-sub{font-size:13px;color:var(--muted);margin-top:4px;}
  .dash-status{font-size:12px;color:#4ade80;display:flex;align-items:center;font-family:'Space Mono',monospace;}
  .dash-stats{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:16px;margin-bottom:20px;}
  .ds-card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px 20px;display:flex;flex-direction:column;gap:8px;transition:border-color 0.2s,transform 0.2s;}
  .ds-card:hover{border-color:rgba(56,189,248,0.3);transform:translateY(-2px);}
  .ds-icon{width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:4px;}
  .ds-num{font-size:26px;font-weight:700;letter-spacing:-0.5px;}
  .ds-label{font-size:12px;color:var(--muted);}
  .ds-badge{font-size:10px;font-family:'Space Mono',monospace;padding:3px 10px;border-radius:20px;border:1px solid rgba(255,255,255,0.08);width:fit-content;margin-top:2px;}
  .dash-grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px;}
  .dash-panel{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;}
  .dash-panel-head{display:flex;align-items:center;justify-content:space-between;font-size:14px;font-weight:600;margin-bottom:18px;}
  .dash-pill{font-size:10px;font-family:'Space Mono',monospace;padding:3px 10px;border-radius:20px;background:rgba(74,222,128,0.1);color:#4ade80;border:1px solid rgba(74,222,128,0.2);}
  .dash-empty{text-align:center;padding:28px 0;color:var(--muted);}
  .dash-cta{margin-top:16px;padding:9px 20px;border-radius:9px;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.28);color:var(--violet);cursor:none;font-family:'Space Grotesk',sans-serif;font-size:12px;font-weight:600;transition:all 0.2s;}
  .dash-cta:hover{background:rgba(56,189,248,0.2);}
  .dash-conn-list{display:flex;flex-direction:column;gap:12px;}
  .dash-conn-item{display:flex;align-items:center;gap:12px;padding:10px 14px;border-radius:10px;background:rgba(255,255,255,0.02);border:1px solid var(--border);}
  .dash-conn-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0;}
  .dash-conn-info{flex:1;}
  .dash-conn-name{font-size:13px;font-weight:600;}
  .dash-conn-sub{font-size:11px;color:var(--muted);margin-top:2px;}
  .dash-conn-tag{font-size:10px;font-family:'Space Mono',monospace;letter-spacing:0.5px;}
  .dash-actions{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
  .dash-action-btn{background:rgba(255,255,255,0.02);border:1px solid var(--border);border-radius:12px;padding:18px 12px;display:flex;flex-direction:column;align-items:center;gap:10px;font-size:12px;font-weight:600;color:var(--text);cursor:none;transition:all 0.2s;font-family:'Space Grotesk',sans-serif;}
  .dash-action-btn:hover{background:rgba(56,189,248,0.08);border-color:rgba(56,189,248,0.3);color:var(--violet);transform:translateY(-2px);}

  /* ── AUTH / LOGIN ── */
  .auth-wrap{display:flex;align-items:center;justify-content:center;height:100%;padding:20px;}
  .auth-box{background:var(--panel);border:1px solid rgba(56,189,248,0.25);border-radius:20px;padding:40px 36px;width:100%;max-width:400px;box-shadow:0 24px 80px rgba(0,0,0,0.5);}
  .auth-logo{text-align:center;margin-bottom:28px;}
  .auth-logo .brand-icon{width:48px;height:48px;border-radius:14px;background:linear-gradient(135deg,var(--violet-dim),var(--violet));display:flex;align-items:center;justify-content:center;font-size:22px;margin:0 auto 12px;box-shadow:0 0 24px rgba(56,189,248,0.5);}
  .auth-logo h2{font-size:20px;font-weight:700;margin-bottom:4px;}
  .auth-logo p{font-size:12px;color:var(--muted);}
  .auth-tabs{display:flex;gap:0;margin-bottom:24px;background:rgba(255,255,255,0.03);border-radius:10px;padding:4px;}
  .auth-tab{flex:1;padding:8px;border-radius:8px;border:none;background:none;color:var(--muted);font-size:13px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.2s;}
  .auth-tab.active{background:rgba(56,189,248,0.15);color:var(--violet);}
  .auth-field{margin-bottom:16px;}
  .auth-field label{display:block;font-size:11px;color:var(--muted);margin-bottom:6px;font-family:'Space Mono',monospace;letter-spacing:0.5px;}
  .auth-field input{width:100%;padding:11px 14px;border-radius:9px;background:rgba(255,255,255,0.04);border:1px solid var(--border);color:var(--text);font-size:14px;font-family:'Space Grotesk',sans-serif;outline:none;transition:border-color 0.2s;}
  .auth-field input:focus{border-color:rgba(56,189,248,0.5);}
  .auth-btn{width:100%;padding:12px;border-radius:10px;background:linear-gradient(135deg,var(--violet-dim),var(--violet));border:none;color:#fff;font-size:14px;font-weight:700;font-family:'Space Grotesk',sans-serif;cursor:none;margin-top:8px;transition:opacity 0.2s;}
  .auth-btn:hover{opacity:0.88;}
  .auth-err{font-size:12px;color:#f26d6d;margin-top:10px;text-align:center;min-height:18px;}

  /* ── USER DASHBOARD ── */
  .udash-wrap{padding:32px 36px;overflow-y:auto;height:100%;}
  .udash-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;}
  .udash-greet{font-size:22px;font-weight:700;}
  .udash-plan{font-family:'Space Mono',monospace;font-size:10px;padding:5px 14px;border-radius:20px;border:1px solid rgba(247,192,74,0.3);color:#f7c04a;background:rgba(247,192,74,0.08);}
  .udash-logout{font-size:12px;color:var(--muted);cursor:none;background:none;border:1px solid var(--border);border-radius:8px;padding:6px 14px;font-family:'Space Grotesk',sans-serif;transition:all 0.2s;}
  .udash-logout:hover{color:var(--red);border-color:var(--red);}
  .udash-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;}
  .ucard{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;}
  .ucard-label{font-size:11px;color:var(--muted);margin-bottom:8px;font-family:'Space Mono',monospace;}
  .ucard-val{font-size:22px;font-weight:700;}
  .ucard-sub{font-size:11px;color:var(--muted);margin-top:4px;}
  .uwebhook{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;margin-bottom:16px;}
  .uwebhook-title{font-size:14px;font-weight:600;margin-bottom:12px;}
  .uwebhook-url{background:rgba(255,255,255,0.03);border:1px solid var(--border);border-radius:8px;padding:10px 14px;font-family:'Space Mono',monospace;font-size:11px;color:var(--violet);word-break:break-all;}
  .ulicense{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:22px;}
  .ulicense-key{font-family:'Space Mono',monospace;font-size:15px;font-weight:700;color:var(--gold);letter-spacing:2px;margin-top:8px;}

  /* ── ADMIN PANEL ── */
  .admin-wrap{padding:32px 36px;overflow-y:auto;height:100%;}
  .admin-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;}
  .admin-title{font-size:24px;font-weight:700;}
  .admin-badge{font-family:'Space Mono',monospace;font-size:10px;padding:5px 14px;border-radius:20px;border:1px solid rgba(242,109,109,0.3);color:#f26d6d;background:rgba(242,109,109,0.08);}
  .admin-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px;}
  .astat{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;}
  .astat-num{font-size:28px;font-weight:700;}
  .astat-label{font-size:11px;color:var(--muted);margin-top:4px;}
  .admin-table-wrap{background:var(--panel);border:1px solid var(--border);border-radius:16px;overflow:hidden;}
  .admin-table-head{padding:16px 20px;border-bottom:1px solid var(--border);font-size:13px;font-weight:600;display:flex;align-items:center;justify-content:space-between;}
  .admin-table{width:100%;border-collapse:collapse;}
  .admin-table th{padding:10px 16px;text-align:left;font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;border-bottom:1px solid var(--border);}
  .admin-table td{padding:12px 16px;font-size:13px;border-bottom:1px solid rgba(42,37,54,0.5);}
  .admin-table tr:last-child td{border-bottom:none;}
  .admin-table tr:hover td{background:rgba(255,255,255,0.02);}
  .plan-badge{font-size:10px;font-family:'Space Mono',monospace;padding:3px 10px;border-radius:20px;}
  .plan-free{background:rgba(157,149,166,0.1);color:var(--muted);border:1px solid rgba(157,149,166,0.2);}
  .plan-pro{background:rgba(56,189,248,0.1);color:var(--violet);border:1px solid rgba(56,189,248,0.2);}
  .plan-enterprise{background:rgba(247,192,74,0.1);color:var(--gold);border:1px solid rgba(247,192,74,0.2);}
  .atoggle{font-size:11px;padding:4px 12px;border-radius:6px;cursor:none;font-family:'Space Grotesk',sans-serif;font-weight:600;border:1px solid;transition:all 0.2s;}
  .atoggle-on{color:#f26d6d;border-color:rgba(242,109,109,0.3);background:rgba(242,109,109,0.08);}
  .atoggle-off{color:#4ade80;border-color:rgba(74,222,128,0.3);background:rgba(74,222,128,0.08);}
  .aplan-sel{background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:11px;padding:4px 8px;font-family:'Space Grotesk',sans-serif;cursor:none;}
  .broker-page{padding:32px 36px;}
  .bp-back{display:inline-flex;align-items:center;gap:7px;font-size:12px;color:var(--muted);cursor:none;transition:color 0.15s;margin-bottom:20px;background:none;border:none;font-family:'Space Grotesk',sans-serif;padding:0;}
  .bp-back:hover{color:var(--text);}
  .bp-title{font-size:26px;font-weight:700;margin-bottom:6px;letter-spacing:-0.5px;}
  .bp-sub{font-size:13px;color:var(--muted);margin-bottom:28px;}
  .bp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:20px;}

  @keyframes cardIn{from{opacity:0;transform:translateY(28px) scale(0.96)}to{opacity:1;transform:translateY(0) scale(1)}}
  @keyframes logoPulse{0%,100%{box-shadow:0 0 0 0 var(--pulse-col,rgba(56,189,248,0.5)),0 4px 16px rgba(0,0,0,0.4)}60%{box-shadow:0 0 0 8px rgba(0,0,0,0),0 4px 16px rgba(0,0,0,0.4)}}

  .bp-card{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:28px 24px 22px;display:flex;flex-direction:column;gap:18px;transition:border-color 0.3s,box-shadow 0.35s,transform 0.25s;cursor:none;position:relative;overflow:hidden;animation:cardIn 0.45s cubic-bezier(.22,.68,0,1.2) both;will-change:transform;}
  .bp-card::before{content:'';position:absolute;inset:0;opacity:0;transition:opacity 0.3s;border-radius:18px;pointer-events:none;}
  .bp-card::after{content:'';position:absolute;top:0;left:-120%;width:55%;height:100%;background:linear-gradient(105deg,transparent 15%,rgba(255,255,255,0.09) 50%,transparent 85%);transform:skewX(-15deg);transition:left 0.6s cubic-bezier(.25,.46,.45,.94);pointer-events:none;}
  .bp-card:hover::before{opacity:1;}
  .bp-card:hover::after{left:165%;}

  /* LOGO BOX */
  .bp-logo{width:80px;height:80px;border-radius:18px;display:flex;align-items:center;justify-content:center;flex-shrink:0;border:1px solid rgba(255,255,255,0.08);overflow:hidden;position:relative;animation:logoPulse 2.4s ease-in-out infinite;}
  .logo-svg{width:38px;height:38px;flex-shrink:0;}

  .bp-name{font-size:17px;font-weight:700;margin-bottom:5px;}
  .bp-type{font-size:11px;color:var(--muted);}
  .bp-connect{padding:10px 0;border-radius:8px;font-size:11px;font-family:'Space Mono',monospace;border:1px solid var(--border);color:var(--muted);background:rgba(255,255,255,0.02);cursor:none;letter-spacing:0.5px;text-align:center;transition:all 0.18s;}
  .bp-card:hover .bp-connect{color:var(--violet);}

  @keyframes glow-slide{0%{transform:translateX(-20%);opacity:0}8%{opacity:1}92%{opacity:1}100%{transform:translateX(120vw);opacity:0}}
  .gline{position:fixed;height:1px;width:250px;animation:glow-slide linear infinite;pointer-events:none;z-index:0;}

  .modal-ov{display:none;position:fixed;inset:0;z-index:200;background:rgba(8,7,10,0.88);backdrop-filter:blur(8px);align-items:center;justify-content:center;}
  .modal-ov.open{display:flex;}
  .modal-box{background:linear-gradient(135deg,#1a1825,#141119);border:1px solid rgba(56,189,248,0.2);border-radius:16px;padding:40px 36px;max-width:360px;width:90%;text-align:center;box-shadow:0 24px 80px rgba(0,0,0,0.6);}

  /* ── UD TABS ── */
  .ud-tab{background:none;border:none;border-bottom:2px solid transparent;padding:10px 18px;font-family:'Space Grotesk',sans-serif;font-size:13px;font-weight:600;color:var(--muted);cursor:pointer;transition:all 0.2s;margin-bottom:-1px;}
  .ud-tab:hover{color:var(--text);}
  .ud-tab.active{color:var(--violet);border-bottom-color:var(--violet);}
  .plan-card{background:var(--panel);border:2px solid var(--border);border-radius:16px;padding:22px 16px;text-align:center;cursor:pointer;transition:all 0.2s;}
  .plan-card:hover{border-color:rgba(56,189,248,0.4);background:rgba(56,189,248,0.04);}
  .plan-card.selected{border-color:var(--violet);background:rgba(56,189,248,0.08);}
  .plan-card-icon{font-size:28px;margin-bottom:10px;}
  .plan-card-name{font-size:15px;font-weight:700;margin-bottom:4px;}
  .plan-card-sub{font-size:11px;color:var(--muted);margin-bottom:12px;}
  .plan-card-price{font-family:'Space Mono',monospace;font-size:12px;color:#4ade80;background:rgba(74,222,128,0.08);border:1px solid rgba(74,222,128,0.2);border-radius:20px;padding:4px 12px;display:inline-block;}
  .wiz-btn{width:100%;padding:12px;border-radius:10px;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);color:var(--violet);font-family:'Space Grotesk',sans-serif;font-size:14px;font-weight:600;cursor:pointer;transition:all 0.2s;}
  .wiz-btn:hover{background:rgba(56,189,248,0.18);}
  .wiz-btn:disabled{opacity:0.4;cursor:not-allowed;}
  .mem-row{display:flex;align-items:center;gap:12px;padding:10px 14px;background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-bottom:8px;}
  .mem-role-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
  .mem-info{flex:1;}
  .mem-name{font-size:13px;font-weight:600;}
  .mem-acc{font-size:11px;font-family:'Space Mono',monospace;color:var(--muted);margin-top:2px;}
  .mem-del{font-size:12px;color:var(--red);background:none;border:none;cursor:pointer;padding:4px 8px;border-radius:6px;opacity:0.6;transition:opacity 0.2s;}
  .mem-del:hover{opacity:1;}
  .guide-step{display:flex;gap:16px;margin-bottom:14px;padding:16px;background:var(--panel);border:1px solid var(--border);border-radius:14px;}
  .guide-num{width:32px;height:32px;border-radius:50%;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:var(--violet);flex-shrink:0;}
  .guide-body{flex:1;}
  .guide-title{font-size:14px;font-weight:700;margin-bottom:6px;}
  .guide-desc{font-size:12px;color:var(--muted);line-height:1.7;}

  .mt5-strip-wrap{overflow:hidden;width:100%;margin:16px 0 22px;mask-image:linear-gradient(to right,transparent,black 8%,black 92%,transparent);}
  .mt5-strip{display:flex;gap:28px;animation:strip-scroll 28s linear infinite;width:max-content;}
  .mt5-strip:hover{animation-play-state:paused;}
  @keyframes strip-scroll{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
  .strip-logo{display:flex;flex-direction:column;align-items:center;gap:8px;flex-shrink:0;}
  .strip-logo img{width:72px;height:72px;border-radius:16px;border:1px solid var(--border);background:var(--panel);object-fit:contain;}
  .strip-logo span{font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;}
  .mt5-form-card{background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:24px;max-width:480px;margin:0 auto;}
  .role-card{background:var(--bg);border:2px solid var(--border);border-radius:14px;padding:18px 12px;text-align:center;cursor:pointer;transition:all 0.2s;}
  .role-card:hover{border-color:rgba(56,189,248,0.35);}
  .role-card.active{border-color:var(--violet);background:rgba(56,189,248,0.07);}
</style>
</head>
<body>

<div id="cursor"></div>
<div id="cursor-ring"></div>
<div id="mglow"></div>
<div class="orb orb1"></div>
<div class="orb orb2"></div>
<div class="orb orb3"></div>
<canvas id="bg-canvas"></canvas>

<div class="gline" style="top:14%;animation-duration:10s;background:linear-gradient(90deg,transparent,rgba(56,189,248,0.7),transparent);"></div>
<div class="gline" style="top:42%;animation-duration:16s;animation-delay:5s;background:linear-gradient(90deg,transparent,rgba(247,192,74,0.55),transparent);"></div>
<div class="gline" style="top:70%;animation-duration:12s;animation-delay:9s;background:linear-gradient(90deg,transparent,rgba(56,189,248,0.5),transparent);"></div>
<div class="gline" style="top:88%;animation-duration:14s;animation-delay:3s;background:linear-gradient(90deg,transparent,rgba(247,192,74,0.35),transparent);"></div>

<div class="shell">
  <aside class="sidebar">
    <div class="sb-inner">
      <div class="brand">
        <div class="brand-logo">
          <img src="/logo.jpg" alt="AG Technicals" style="width:44px;height:44px;border-radius:50%;object-fit:contain;background:#000;border:2px solid rgba(247,192,74,0.5);flex-shrink:0;">
          <div class="brand-name">AG TradeBridge</div>
        </div>
        <div class="brand-sub">SIGNAL AUTOMATION</div>
      </div>
      <button class="user-btn" onclick="SESSION?((SESSION.role==='admin'?openPage('admin',null):openPage('udashboard',null))&&(SESSION.role==='admin'?loadAdminData():loadUserData())):openPage('login',null)">
        <div class="user-avatar">AG</div>
        <div class="user-info"><div class="user-name">Dashboard</div><div class="user-plan">View account →</div></div>
      </button>
      <div class="nav-label">Connect</div>
      <button class="nav-btn" id="nav-tv-mt5" onclick="openPage('tv-mt5',this)">
        <span class="nav-icon">📡</span><span class="nav-text">TradingView → MT5</span><span class="arr">›</span>
      </button>
      <button class="nav-btn" id="nav-mt5-mt5" onclick="openPage('mt5-mt5',this);onMt5PageOpen()">
        <span class="nav-icon">🔁</span><span class="nav-text">MT5 → MT5</span><span class="arr">›</span>
      </button>
      <button class="nav-btn" id="nav-tv-crypto" onclick="openPage('tv-crypto',this)">
        <span class="nav-icon">₿</span><span class="nav-text">TradingView → Crypto</span><span class="arr">›</span>
      </button>
      <button class="nav-btn" id="nav-tv-indices" onclick="openPage('tv-indices',this)">
        <span class="nav-icon">📊</span><span class="nav-text">TradingView → Indices</span><span class="arr">›</span>
      </button>
      <div class="sb-footer"><div class="status-dot"><div class="dot"></div><span>All systems live</span></div></div>
    </div>
  </aside>

  <main class="main">
    <!-- PUBLIC LANDING PAGE (shown when NOT logged in) -->
    <div class="page" id="page-landing">
      <div style="height:100%;overflow-y:auto;">
        <!-- TOPBAR -->
        <div style="position:sticky;top:0;z-index:50;background:rgba(8,7,10,0.85);backdrop-filter:blur(20px);border-bottom:1px solid var(--border);padding:14px 40px;display:flex;align-items:center;justify-content:space-between;">
          <div style="display:flex;align-items:center;gap:10px;">
            <img src="/logo.jpg" style="width:36px;height:36px;border-radius:50%;object-fit:contain;background:#000;border:1.5px solid rgba(247,192,74,0.4);">
            <span style="font-size:16px;font-weight:700;letter-spacing:-0.3px;">AG TradeBridge</span>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <button onclick="openPage('login',null)" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:8px 20px;border-radius:8px;font-size:12px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;" onmouseenter="this.style.borderColor='rgba(56,189,248,0.5)';this.style.color='#f4efe6'" onmouseleave="this.style.borderColor='var(--border)';this.style.color='var(--muted)'">Login</button>
            <button onclick="openPage('login',null);setTimeout(()=>switchAuthTab('signup'),100)" style="background:linear-gradient(135deg,#0284c7,#38bdf8);border:none;color:#fff;padding:8px 20px;border-radius:8px;font-size:12px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;box-shadow:0 4px 18px rgba(56,189,248,0.3);transition:all 0.18s;" onmouseenter="this.style.boxShadow='0 4px 28px rgba(56,189,248,0.55)'" onmouseleave="this.style.boxShadow='0 4px 18px rgba(56,189,248,0.3)'">Get Started Free</button>
          </div>
        </div>

        <!-- HERO -->
        <div style="text-align:center;padding:80px 40px 60px;max-width:900px;margin:0 auto;">
          <div style="display:inline-flex;align-items:center;gap:8px;font-family:'Space Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--violet);border:1px solid rgba(56,189,248,0.3);background:rgba(56,189,248,0.07);border-radius:20px;padding:6px 18px;margin-bottom:32px;">
            <span style="width:6px;height:6px;border-radius:50%;background:var(--violet);display:inline-block;animation:pulse 2s infinite;"></span>
            LIVE SIGNAL AUTOMATION · INDIA'S FIRST MT5 BRIDGE
          </div>
          <h1 style="font-size:clamp(38px,5.5vw,72px);font-weight:700;line-height:1.06;letter-spacing:-2px;margin-bottom:24px;">
            Route your trades<br>
            <span style="background:linear-gradient(90deg,#38bdf8,#f7c04a);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">to any broker. Instantly.</span>
          </h1>
          <p style="font-size:16px;color:var(--muted);max-width:520px;margin:0 auto 44px;line-height:1.8;">
            Connect TradingView signals to MT5, crypto exchanges &amp; Indian brokers with zero coding. Automate your entire trading workflow in minutes.
          </p>
          <div style="display:flex;gap:14px;justify-content:center;flex-wrap:wrap;margin-bottom:60px;">
            <button onclick="openPage('login',null);setTimeout(()=>switchAuthTab('signup'),100)" style="background:linear-gradient(135deg,#0284c7,#38bdf8);border:none;color:#fff;padding:15px 36px;border-radius:10px;font-size:14px;font-weight:700;cursor:none;font-family:'Space Grotesk',sans-serif;box-shadow:0 4px 28px rgba(56,189,248,0.35);letter-spacing:0.3px;">🚀 Start Free — No Credit Card</button>
            <button onclick="openPage('mt5-mt5',document.getElementById('nav-mt5-mt5'))" style="background:transparent;border:1px solid var(--border);color:var(--text);padding:15px 36px;border-radius:10px;font-size:14px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;">See How It Works →</button>
          </div>
          <!-- TICKER -->
          <div style="width:100%;max-width:700px;margin:0 auto;overflow:hidden;border:1px solid var(--border);border-radius:12px;background:var(--panel);position:relative;">
            <div style="position:absolute;top:0;bottom:0;left:0;width:60px;background:linear-gradient(90deg,var(--panel),transparent);z-index:2;pointer-events:none;"></div>
            <div style="position:absolute;top:0;bottom:0;right:0;width:60px;background:linear-gradient(-90deg,var(--panel),transparent);z-index:2;pointer-events:none;"></div>
            <div class="ticker" id="ticker" style="padding:10px 0;"></div>
          </div>
        </div>

        <!-- STATS BAR -->
        <div style="border-top:1px solid var(--border);border-bottom:1px solid var(--border);background:var(--panel);padding:28px 40px;display:grid;grid-template-columns:repeat(4,1fr);gap:20px;text-align:center;max-width:900px;margin:0 auto;">
          <div><div style="font-size:30px;font-weight:700;font-family:'Space Mono',monospace;background:linear-gradient(135deg,var(--gold),#d98e2b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">12+</div><div style="font-size:11px;color:var(--muted);margin-top:4px;">Brokers Supported</div></div>
          <div><div style="font-size:30px;font-weight:700;font-family:'Space Mono',monospace;background:linear-gradient(135deg,var(--gold),#d98e2b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">&lt;50ms</div><div style="font-size:11px;color:var(--muted);margin-top:4px;">Signal Latency</div></div>
          <div><div style="font-size:30px;font-weight:700;font-family:'Space Mono',monospace;background:linear-gradient(135deg,var(--gold),#d98e2b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">99.9%</div><div style="font-size:11px;color:var(--muted);margin-top:4px;">Uptime SLA</div></div>
          <div><div style="font-size:30px;font-weight:700;font-family:'Space Mono',monospace;background:linear-gradient(135deg,var(--gold),#d98e2b);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">4</div><div style="font-size:11px;color:var(--muted);margin-top:4px;">Bridge Types</div></div>
        </div>

        <!-- FEATURES GRID -->
        <div style="padding:70px 40px;max-width:900px;margin:0 auto;">
          <div style="text-align:center;margin-bottom:50px;">
            <div style="font-family:'Space Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--gold);margin-bottom:14px;">WHAT YOU GET</div>
            <h2 style="font-size:32px;font-weight:700;letter-spacing:-0.8px;">Everything to automate your trading</h2>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;">
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;position:relative;overflow:hidden;" onmouseenter="this.style.borderColor='rgba(56,189,248,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">📡</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">TradingView → MT5</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Send TradingView webhook alerts directly to your MT5 broker. Supports all major forex brokers.</div>
            </div>
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;position:relative;" onmouseenter="this.style.borderColor='rgba(247,192,74,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">🔁</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">MT5 → MT5 Copy</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Copy trades from a Master account to multiple Receiver accounts in real time with our EA.</div>
            </div>
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;" onmouseenter="this.style.borderColor='rgba(74,222,128,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">₿</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">TradingView → Crypto</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Route signals to Binance, Bybit, OKX and other top crypto exchanges via API.</div>
            </div>
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;" onmouseenter="this.style.borderColor='rgba(56,189,248,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">📊</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">TradingView → Indices</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Connect to Zerodha, Fyers, Angel One and other Indian brokers for Nifty &amp; BankNifty.</div>
            </div>
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;" onmouseenter="this.style.borderColor='rgba(247,192,74,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">🔐</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">License System</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Secure license keys to protect your EA files. Manage Master &amp; Receiver seats per license.</div>
            </div>
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:28px;transition:all 0.2s;" onmouseenter="this.style.borderColor='rgba(74,222,128,0.4)'" onmouseleave="this.style.borderColor='var(--border)'">
              <div style="font-size:28px;margin-bottom:14px;">⚡</div>
              <div style="font-size:14px;font-weight:700;margin-bottom:8px;">Ultra Low Latency</div>
              <div style="font-size:12px;color:var(--muted);line-height:1.7;">Sub-50ms signal routing on dedicated cloud infrastructure. No delays, no missed trades.</div>
            </div>
          </div>
        </div>

        <!-- PRICING -->
        <div style="padding:60px 40px 80px;max-width:900px;margin:0 auto;text-align:center;">
          <div style="font-family:'Space Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--gold);margin-bottom:14px;">PRICING</div>
          <h2 style="font-size:32px;font-weight:700;letter-spacing:-0.8px;margin-bottom:12px;">Simple, transparent pricing</h2>
          <p style="color:var(--muted);font-size:14px;margin-bottom:44px;">Start free. Upgrade when you need more.</p>
          <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px;text-align:left;">
            <!-- Free -->
            <div style="background:var(--panel);border:1px solid var(--border);border-radius:20px;padding:32px;">
              <div style="font-size:12px;font-weight:700;color:var(--muted);letter-spacing:1.5px;font-family:'Space Mono',monospace;margin-bottom:16px;">FREE</div>
              <div style="font-size:40px;font-weight:700;font-family:'Space Mono',monospace;margin-bottom:4px;">₹0</div>
              <div style="font-size:12px;color:var(--muted);margin-bottom:24px;">Forever free</div>
              <div style="border-top:1px solid var(--border);padding-top:20px;display:flex;flex-direction:column;gap:12px;">
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> 1 Bridge Connection</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> TradingView → MT5</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> 100 signals/day</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:var(--muted)">✗</span> <span style="color:var(--muted)">MT5 Copy Trading</span></div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:var(--muted)">✗</span> <span style="color:var(--muted)">Priority Support</span></div>
              </div>
              <button onclick="openPage('login',null);setTimeout(()=>switchAuthTab('signup'),100)" style="margin-top:28px;width:100%;background:transparent;border:1px solid var(--border);color:var(--text);padding:12px;border-radius:9px;font-size:13px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;" onmouseenter="this.style.borderColor='rgba(56,189,248,0.5)'" onmouseleave="this.style.borderColor='var(--border)'">Get Started Free</button>
            </div>
            <!-- Pro -->
            <div style="background:linear-gradient(135deg,rgba(2,132,199,0.15),rgba(8,7,10,1));border:1px solid rgba(56,189,248,0.45);border-radius:20px;padding:32px;position:relative;overflow:hidden;">
              <div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#0284c7,#38bdf8,#f7c04a);"></div>
              <div style="font-size:12px;font-weight:700;color:var(--violet);letter-spacing:1.5px;font-family:'Space Mono',monospace;margin-bottom:16px;">PRO</div>
              <div style="font-size:40px;font-weight:700;font-family:'Space Mono',monospace;margin-bottom:4px;">₹999<span style="font-size:16px;color:var(--muted);font-weight:400;">/mo</span></div>
              <div style="font-size:12px;color:var(--muted);margin-bottom:24px;">Billed monthly</div>
              <div style="border-top:1px solid rgba(56,189,248,0.2);padding-top:20px;display:flex;flex-direction:column;gap:12px;">
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> All 4 Bridge Types</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> MT5 → MT5 Copy Trading</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Unlimited signals</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> License Key (2 seats)</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Priority WhatsApp Support</div>
              </div>
              <button onclick="openPage('login',null);setTimeout(()=>switchAuthTab('signup'),100)" style="margin-top:28px;width:100%;background:linear-gradient(135deg,#0284c7,#38bdf8);border:none;color:#fff;padding:12px;border-radius:9px;font-size:13px;font-weight:700;cursor:none;font-family:'Space Grotesk',sans-serif;box-shadow:0 4px 18px rgba(56,189,248,0.3);transition:all 0.18s;" onmouseenter="this.style.boxShadow='0 4px 28px rgba(56,189,248,0.55)'" onmouseleave="this.style.boxShadow='0 4px 18px rgba(56,189,248,0.3)'">Start Pro Trial</button>
            </div>
            <!-- Enterprise -->
            <div style="background:linear-gradient(135deg,rgba(247,192,74,0.08),rgba(8,7,10,1));border:1px solid rgba(247,192,74,0.35);border-radius:20px;padding:32px;">
              <div style="font-size:12px;font-weight:700;color:var(--gold);letter-spacing:1.5px;font-family:'Space Mono',monospace;margin-bottom:16px;">ENTERPRISE</div>
              <div style="font-size:40px;font-weight:700;font-family:'Space Mono',monospace;margin-bottom:4px;">Custom</div>
              <div style="font-size:12px;color:var(--muted);margin-bottom:24px;">Contact us</div>
              <div style="border-top:1px solid rgba(247,192,74,0.15);padding-top:20px;display:flex;flex-direction:column;gap:12px;">
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Everything in Pro</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Unlimited seats</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> White-label option</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Dedicated support</div>
                <div style="font-size:12px;display:flex;align-items:center;gap:10px;"><span style="color:#4ade80">✓</span> Custom integrations</div>
              </div>
              <button style="margin-top:28px;width:100%;background:rgba(247,192,74,0.1);border:1px solid rgba(247,192,74,0.3);color:var(--gold);padding:12px;border-radius:9px;font-size:13px;font-weight:600;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;" onmouseenter="this.style.background='rgba(247,192,74,0.2)'" onmouseleave="this.style.background='rgba(247,192,74,0.1)'">Contact AG Technicals</button>
            </div>
          </div>
        </div>

        <!-- FOOTER -->
        <div style="border-top:1px solid var(--border);padding:28px 40px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;">
          <div style="display:flex;align-items:center;gap:10px;">
            <img src="/logo.jpg" style="width:28px;height:28px;border-radius:50%;object-fit:contain;background:#000;border:1px solid rgba(247,192,74,0.3);">
            <span style="font-size:13px;font-weight:600;">AG TradeBridge</span>
            <span style="font-size:11px;color:var(--muted);">by AG Technicals, Ajmer</span>
          </div>
          <div style="font-size:11px;color:var(--muted);">© 2025 AG Technicals · agtradebridge.com</div>
        </div>
      </div>
    </div>

    <!-- HOME (for logged-in users coming back to home) -->
    <div class="page" id="page-home">
      <div class="hero">
        <div class="hero-badge"><span class="badge-dot"></span>LIVE SIGNAL ROUTING</div>
        <h1 class="hero-title">Your signals.<br><span class="grad">Any broker. Instantly.</span></h1>
        <p class="hero-desc">Connect TradingView alerts to MT5, crypto exchanges, or Indian brokers — automated, reliable, live in minutes.</p>
        <div class="ticker-wrap"><div class="ticker" id="ticker2"></div></div>
        <div class="stats-row">
          <div class="stat-card"><div class="stat-num">12+</div><div class="stat-label">Brokers</div></div>
          <div class="stat-card"><div class="stat-num">&lt;50ms</div><div class="stat-label">Latency</div></div>
          <div class="stat-card"><div class="stat-num">99.9%</div><div class="stat-label">Uptime</div></div>
          <div class="stat-card"><div class="stat-num">4</div><div class="stat-label">Bridge Types</div></div>
        </div>
        <div class="cta-row">
          <button class="cta-btn cta-primary" onclick="openPage('tv-mt5',document.getElementById('nav-tv-mt5'))">Start Connecting</button>
          <button class="cta-btn cta-outline" onclick="openPage('mt5-mt5',document.getElementById('nav-mt5-mt5'))">MT5 Copy Trading</button>
        </div>
      </div>
    </div>

    <div class="page" id="page-tv-mt5"><div class="broker-page">
      <button class="bp-back" onclick="goHome()">‹ &nbsp;Back</button>
      <div class="bp-title">TradingView → MT5</div><div class="bp-sub">Select your forex broker to connect</div>
      <div class="bp-grid" id="grid-tv-mt5"></div>
    </div></div>

    <div class="page" id="page-mt5-mt5"><div class="broker-page" style="max-width:820px;margin:0 auto;padding:32px 20px;">
      <button class="bp-back" onclick="goHome()">‹ &nbsp;Back</button>
      <div class="bp-title">MT5 → MT5 Copy Trading</div>
      <div class="bp-sub">Register your Master and Receiver accounts, then download your personalized EA files</div>
      <div class="mt5-strip-wrap"><div class="mt5-strip" id="mt5-strip-inner"></div></div>

      <!-- 2 CARDS SIDE BY SIDE -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-top:24px;">

        <!-- MASTER CARD -->
        <div style="background:var(--panel);border:1px solid rgba(247,192,74,0.35);border-radius:18px;padding:26px;position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#d98e2b,#f7c04a);"></div>
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:18px;">
            <div style="width:40px;height:40px;border-radius:10px;background:rgba(247,192,74,0.12);border:1px solid rgba(247,192,74,0.3);display:flex;align-items:center;justify-content:center;font-size:20px;">📤</div>
            <div>
              <div style="font-size:15px;font-weight:700;color:#f7c04a;">Master Account</div>
              <div style="font-size:11px;color:var(--muted);">Sends trades to receivers</div>
            </div>
          </div>

          <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:6px;">MT5 ACCOUNT NUMBER</div>
          <input id="master-account-inp" type="text" placeholder="e.g. 12345678"
            style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:10px 13px;font-family:'Space Mono',monospace;font-size:13px;margin-bottom:12px;outline:none;"
            onfocus="this.style.borderColor='rgba(247,192,74,0.6)'" onblur="this.style.borderColor='var(--border)'">

          <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:6px;">LICENSE KEY</div>
          <input id="master-lic-inp" type="text" placeholder="AGTB-XXXXXX-XXXXXX-XXXXXX"
            style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:10px 13px;font-family:'Space Mono',monospace;font-size:13px;margin-bottom:14px;outline:none;"
            onfocus="this.style.borderColor='rgba(247,192,74,0.6)'" onblur="this.style.borderColor='var(--border)'">

          <!-- TICK OPTION -->
          <label style="display:flex;align-items:flex-start;gap:10px;padding:12px;background:rgba(74,222,128,0.05);border:1px solid rgba(74,222,128,0.2);border-radius:9px;cursor:pointer;margin-bottom:14px;">
            <input type="checkbox" id="master-include-receiver" style="width:16px;height:16px;margin-top:1px;accent-color:#4ade80;cursor:pointer;flex-shrink:0;">
            <div>
              <div style="font-size:12px;font-weight:600;color:#4ade80;">Also include Receiver EA</div>
              <div style="font-size:11px;color:var(--muted);margin-top:2px;">Tick karo agar aapke paas receiver account bhi hai — dono files milein gi</div>
            </div>
          </label>

          <div id="master-form-msg" style="font-size:11px;margin-bottom:10px;min-height:16px;"></div>
          <button onclick="submitMasterForm()" style="width:100%;background:linear-gradient(135deg,#d98e2b,#f7c04a);border:none;color:#000;padding:11px;border-radius:9px;font-size:13px;font-weight:700;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;">
            Register &amp; Get EA Files →
          </button>

          <!-- MASTER DOWNLOAD (hidden until registered) -->
          <div id="master-dl-section" style="display:none;margin-top:14px;padding:12px;background:rgba(247,192,74,0.04);border:1px solid rgba(247,192,74,0.2);border-radius:10px;">
            <div style="font-size:11px;color:var(--gold);font-weight:700;margin-bottom:10px;">⬇ YOUR EA FILES</div>
            <div id="master-dl-links" style="display:flex;flex-direction:column;gap:8px;"></div>
          </div>
        </div>

        <!-- RECEIVER CARD -->
        <div style="background:var(--panel);border:1px solid rgba(56,189,248,0.35);border-radius:18px;padding:26px;position:relative;overflow:hidden;">
          <div style="position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#0284c7,#38bdf8);"></div>
          <div style="display:flex;align-items:center;gap:10px;margin-bottom:18px;">
            <div style="width:40px;height:40px;border-radius:10px;background:rgba(56,189,248,0.12);border:1px solid rgba(56,189,248,0.3);display:flex;align-items:center;justify-content:center;font-size:20px;">📥</div>
            <div>
              <div style="font-size:15px;font-weight:700;color:#38bdf8;">Receiver Account</div>
              <div style="font-size:11px;color:var(--muted);">Copies trades from master</div>
            </div>
          </div>

          <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:6px;">MT5 ACCOUNT NUMBER</div>
          <input id="receiver-account-inp" type="text" placeholder="e.g. 87654321"
            style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:10px 13px;font-family:'Space Mono',monospace;font-size:13px;margin-bottom:12px;outline:none;"
            onfocus="this.style.borderColor='rgba(56,189,248,0.6)'" onblur="this.style.borderColor='var(--border)'">

          <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:6px;">LICENSE KEY</div>
          <input id="receiver-lic-inp" type="text" placeholder="AGTB-XXXXXX-XXXXXX-XXXXXX"
            style="width:100%;box-sizing:border-box;background:var(--bg);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:10px 13px;font-family:'Space Mono',monospace;font-size:13px;margin-bottom:14px;outline:none;"
            onfocus="this.style.borderColor='rgba(56,189,248,0.6)'" onblur="this.style.borderColor='var(--border)'">

          <!-- HOW MANY RECEIVERS -->
          <div style="margin-bottom:14px;">
            <div style="font-size:11px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:6px;">KITNE RECEIVER ACCOUNTS? (1–10)</div>
            <div style="display:flex;align-items:center;gap:10px;">
              <button onclick="changeReceiverCount(-1)" style="width:32px;height:32px;border-radius:7px;background:var(--panel2);border:1px solid var(--border);color:var(--text);font-size:18px;cursor:none;font-family:'Space Grotesk',sans-serif;display:flex;align-items:center;justify-content:center;">−</button>
              <span id="receiver-count-display" style="font-size:18px;font-weight:700;font-family:'Space Mono',monospace;min-width:24px;text-align:center;">1</span>
              <button onclick="changeReceiverCount(1)" style="width:32px;height:32px;border-radius:7px;background:var(--panel2);border:1px solid var(--border);color:var(--text);font-size:18px;cursor:none;font-family:'Space Grotesk',sans-serif;display:flex;align-items:center;justify-content:center;">+</button>
              <span style="font-size:11px;color:var(--muted);">numbered EA files milenge</span>
            </div>
          </div>

          <div id="receiver-form-msg" style="font-size:11px;margin-bottom:10px;min-height:16px;"></div>
          <button onclick="submitReceiverForm()" style="width:100%;background:linear-gradient(135deg,#0284c7,#38bdf8);border:none;color:#fff;padding:11px;border-radius:9px;font-size:13px;font-weight:700;cursor:none;font-family:'Space Grotesk',sans-serif;transition:all 0.18s;">
            Register &amp; Get Receiver Files →
          </button>

          <!-- RECEIVER DOWNLOAD (hidden until registered) -->
          <div id="receiver-dl-section" style="display:none;margin-top:14px;padding:12px;background:rgba(56,189,248,0.04);border:1px solid rgba(56,189,248,0.2);border-radius:10px;">
            <div style="font-size:11px;color:var(--violet);font-weight:700;margin-bottom:10px;">⬇ YOUR RECEIVER EA FILES</div>
            <div id="receiver-dl-links" style="display:flex;flex-direction:column;gap:8px;"></div>
          </div>
        </div>

      </div><!-- end grid -->

      <!-- INFO BOX -->
      <div style="margin-top:20px;padding:16px 20px;background:rgba(56,189,248,0.04);border:1px solid rgba(56,189,248,0.15);border-radius:12px;display:flex;gap:14px;align-items:flex-start;">
        <span style="font-size:20px;flex-shrink:0;">ℹ️</span>
        <div style="font-size:12px;color:var(--muted);line-height:1.7;">
          <b style="color:var(--text);">Kaise kaam karta hai:</b> Master account register karo → Sender EA download karo → MT5 mein daalo. Receiver accounts register karo → numbered Receiver EA files milenge — har account ke liye alag file. License key admin panel se milegi.
        </div>
      </div>

    </div></div>

    <div class="page" id="page-tv-crypto"><div class="broker-page">
      <button class="bp-back" onclick="goHome()">‹ &nbsp;Back</button>
      <div class="bp-title">TradingView → Crypto</div><div class="bp-sub">Connect to your crypto exchange</div>
      <div class="bp-grid" id="grid-tv-crypto"></div>
    </div></div>

    <div class="page" id="page-tv-indices"><div class="broker-page">
      <button class="bp-back" onclick="goHome()">‹ &nbsp;Back</button>
      <div class="bp-title">TradingView → Indices</div><div class="bp-sub">Connect to your Indian broker</div>
      <div class="bp-grid" id="grid-tv-indices"></div>
    </div></div>

    <!-- DASHBOARD PAGE -->
    <div class="page" id="page-dashboard">
      <div class="dash-wrap">
        <div class="dash-header">
          <div>
            <div class="dash-title">Dashboard</div>
            <div class="dash-sub">AG TradeBridge — Signal Automation Hub</div>
          </div>
          <div class="dash-status"><span class="dot" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#4ade80;margin-right:7px;box-shadow:0 0 8px #4ade80;"></span>All systems live</div>
        </div>

        <!-- STAT CARDS -->
        <div class="dash-stats">
          <div class="ds-card">
            <div class="ds-icon" style="background:rgba(56,189,248,0.15);color:#38bdf8;">📡</div>
            <div class="ds-num">0</div>
            <div class="ds-label">Active Signals</div>
            <div class="ds-badge" style="color:#9d95a6;background:rgba(255,255,255,0.04);">Waiting for connection</div>
          </div>
          <div class="ds-card">
            <div class="ds-icon" style="background:rgba(74,222,128,0.12);color:#4ade80;">🔗</div>
            <div class="ds-num">0</div>
            <div class="ds-label">Connected Brokers</div>
            <div class="ds-badge" style="color:#9d95a6;background:rgba(255,255,255,0.04);">No brokers linked yet</div>
          </div>
          <div class="ds-card">
            <div class="ds-icon" style="background:rgba(247,192,74,0.12);color:#f7c04a;">⚡</div>
            <div class="ds-num">&lt;50ms</div>
            <div class="ds-label">Signal Latency</div>
            <div class="ds-badge" style="color:#4ade80;background:rgba(74,222,128,0.08);">Optimal</div>
          </div>
          <div class="ds-card">
            <div class="ds-icon" style="background:rgba(242,109,109,0.12);color:#f26d6d;">📊</div>
            <div class="ds-num">—</div>
            <div class="ds-label">P&amp;L Today</div>
            <div class="ds-badge" style="color:#9d95a6;background:rgba(255,255,255,0.04);">No trades yet</div>
          </div>
        </div>

        <div class="dash-grid2">
          <!-- RECENT SIGNALS -->
          <div class="dash-panel">
            <div class="dash-panel-head">
              <span>Recent Signals</span>
              <span class="dash-pill">Live</span>
            </div>
            <div class="dash-empty">
              <div style="font-size:36px;margin-bottom:12px">📭</div>
              <div style="font-size:14px;font-weight:600;margin-bottom:6px">No signals yet</div>
              <div style="font-size:12px;color:var(--muted)">Connect a broker to start receiving TradingView alerts</div>
              <button class="dash-cta" onclick="openPage('tv-mt5',document.getElementById('nav-tv-mt5'))">Connect Broker →</button>
            </div>
          </div>

          <!-- ACTIVE CONNECTIONS -->
          <div class="dash-panel">
            <div class="dash-panel-head">
              <span>Active Connections</span>
              <span class="dash-pill" style="background:rgba(247,192,74,0.1);color:#f7c04a;border-color:rgba(247,192,74,0.2);">Coming Soon</span>
            </div>
            <div class="dash-conn-list">
              <div class="dash-conn-item">
                <div class="dash-conn-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div>
                <div class="dash-conn-info"><div class="dash-conn-name">TradeBridge Engine</div><div class="dash-conn-sub">v2.1 · Running</div></div>
                <div class="dash-conn-tag" style="color:#4ade80">LIVE</div>
              </div>
              <div class="dash-conn-item">
                <div class="dash-conn-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div>
                <div class="dash-conn-info"><div class="dash-conn-name">Signal Queue</div><div class="dash-conn-sub">0 pending · 0 processed</div></div>
                <div class="dash-conn-tag" style="color:#4ade80">LIVE</div>
              </div>
              <div class="dash-conn-item">
                <div class="dash-conn-dot" style="background:#f7c04a;box-shadow:0 0 8px #f7c04a88"></div>
                <div class="dash-conn-info"><div class="dash-conn-name">Broker API</div><div class="dash-conn-sub">Not configured</div></div>
                <div class="dash-conn-tag" style="color:#f7c04a">IDLE</div>
              </div>
              <div class="dash-conn-item">
                <div class="dash-conn-dot" style="background:#38bdf8;box-shadow:0 0 8px #38bdf888"></div>
                <div class="dash-conn-info"><div class="dash-conn-name">Neon Database</div><div class="dash-conn-sub">Connected · PostgreSQL</div></div>
                <div class="dash-conn-tag" style="color:#38bdf8">OK</div>
              </div>
            </div>
          </div>
        </div>

        <!-- QUICK ACTIONS -->
        <div class="dash-panel" style="margin-top:20px;">
          <div class="dash-panel-head"><span>Quick Actions</span></div>
          <div class="dash-actions">
            <button class="dash-action-btn" onclick="openPage('tv-mt5',document.getElementById('nav-tv-mt5'))">
              <span style="font-size:22px">📡</span>
              <span>TradingView → MT5</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('mt5-mt5',document.getElementById('nav-mt5-mt5'))">
              <span style="font-size:22px">🔁</span>
              <span>MT5 → MT5</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('tv-crypto',document.getElementById('nav-tv-crypto'))">
              <span style="font-size:22px">₿</span>
              <span>TradingView → Crypto</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('tv-indices',document.getElementById('nav-tv-indices'))">
              <span style="font-size:22px">📊</span>
              <span>TradingView → Indices</span>
            </button>
          </div>
        </div>

      </div>
    </div>

    <!-- LOGIN PAGE -->
    <div class="page" id="page-login">
      <div class="auth-wrap">
        <div class="auth-box">
          <div class="auth-logo">
            <div class="brand-icon">⚡</div>
            <h2>AG TradeBridge</h2>
            <p>Signal Automation Platform</p>
          </div>
          <div class="auth-tabs">
            <button class="auth-tab active" id="tab-login" onclick="switchAuthTab('login')">Login</button>
            <button class="auth-tab" id="tab-signup" onclick="switchAuthTab('signup')">Sign Up</button>
          </div>
          <div id="auth-login-form">
            <div class="auth-field"><label>EMAIL</label><input type="email" id="login-email" placeholder="you@example.com"></div>
            <div class="auth-field"><label>PASSWORD</label><input type="password" id="login-pass" placeholder="••••••••"></div>
            <button class="auth-btn" onclick="doLogin()">Login →</button>
          </div>
          <div id="auth-signup-form" style="display:none">
            <div class="auth-field"><label>NAME</label><input type="text" id="signup-name" placeholder="Your name"></div>
            <div class="auth-field"><label>EMAIL</label><input type="email" id="signup-email" placeholder="you@example.com"></div>
            <div class="auth-field"><label>PASSWORD</label><input type="password" id="signup-pass" placeholder="Min 6 characters"></div>
            <button class="auth-btn" onclick="doSignup()">Create Account →</button>
          </div>
          <div class="auth-err" id="auth-err"></div>
        </div>
      </div>
    </div>

    <!-- USER DASHBOARD PAGE -->
    <div class="page" id="page-udashboard">
      <div class="udash-wrap">
        <div class="udash-top">
          <div>
            <div class="udash-greet" id="ud-greet">Welcome back 👋</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px" id="ud-email"></div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <div class="udash-plan" id="ud-plan">FREE</div>
            <button class="udash-logout" onclick="doLogout()">Logout</button>
          </div>
        </div>
        <!-- Overview -->
        <div id="utab-overview">
          <div class="udash-grid">
            <div class="ucard">
              <div class="ucard-label">ACTIVE SIGNALS</div>
              <div class="ucard-val" id="ud-signals">0</div>
              <div class="ucard-sub">Total processed</div>
            </div>
            <div class="ucard">
              <div class="ucard-label">PLAN</div>
              <div class="ucard-val" id="ud-plan2" style="color:var(--violet)">Free</div>
              <div class="ucard-sub">Active subscription</div>
            </div>
          </div>
          <div class="uwebhook">
            <div class="uwebhook-title">📡 Your Webhook URL</div>
            <div class="uwebhook-url" id="ud-webhook">Loading...</div>
            <div style="font-size:11px;color:var(--muted);margin-top:8px">Paste in TradingView alert → Webhook URL</div>
          </div>
          <div class="ulicense" style="cursor:pointer" onclick="switchUTab('mt5')">
            <div class="ucard-label">LICENSE KEY</div>
            <div class="ulicense-key" id="ud-license">—</div>
            <div style="font-size:11px;color:var(--muted);margin-top:8px">Click to manage MT5→MT5 copier</div>
          </div>
          <div style="margin-top:16px;display:flex;gap:12px;flex-wrap:wrap;">
            <button class="dash-action-btn" onclick="switchUTab('mt5')">
              <span style="font-size:20px">🔁</span><span>MT5 → MT5</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('tv-mt5',document.getElementById('nav-tv-mt5'))">
              <span style="font-size:20px">📡</span><span>Forex Broker</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('tv-crypto',document.getElementById('nav-tv-crypto'))">
              <span style="font-size:20px">₿</span><span>Crypto</span>
            </button>
            <button class="dash-action-btn" onclick="openPage('tv-indices',document.getElementById('nav-tv-indices'))">
              <span style="font-size:20px">📊</span><span>Indian Broker</span>
            </button>
          </div>
        </div>


      </div>
    </div>

    <!-- ADMIN PANEL PAGE -->
    <div class="page" id="page-admin">
      <div class="admin-wrap">
        <div class="admin-header">
          <div>
            <div class="admin-title">Admin Panel</div>
            <div style="font-size:12px;color:var(--muted);margin-top:4px">AG TradeBridge Control Center</div>
          </div>
          <div style="display:flex;gap:10px;align-items:center;">
            <div class="admin-badge">🔐 ADMIN</div>
            <button class="udash-logout" onclick="doLogout()">Logout</button>
          </div>
        </div>
        <div class="admin-stats" id="admin-stats">
          <div class="astat"><div class="astat-num" id="as-total">—</div><div class="astat-label">Total Users</div></div>
          <div class="astat"><div class="astat-num" id="as-active">—</div><div class="astat-label">Active Users</div></div>
          <div class="astat"><div class="astat-num" id="as-paid">—</div><div class="astat-label">Paid Users</div></div>
          <div class="astat"><div class="astat-num" id="as-signals">—</div><div class="astat-label">Total Signals</div></div>
        </div>
        <div class="admin-table-wrap">
          <div class="admin-table-head">
            <span>All Users</span>
            <button class="dash-cta" onclick="loadAdminData()" style="margin-top:0;padding:6px 16px;">↻ Refresh</button>
          </div>
          <table class="admin-table">
            <thead><tr>
              <th>#</th><th>Name / Email</th><th>Plan</th><th>License</th><th>Joined</th><th>Status</th><th>Actions</th>
            </tr></thead>
            <tbody id="admin-users-tbody">
              <tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">Loading...</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>
</div>

<div class="modal-ov" id="dash-modal" onclick="if(event.target.id==='dash-modal')closeDash()">
  <div class="modal-box">
    <div style="font-size:44px;margin-bottom:16px">🚀</div>
    <div style="font-size:20px;font-weight:700;margin-bottom:10px">Dashboard</div>
    <div style="display:inline-block;font-family:'Space Mono',monospace;font-size:10px;letter-spacing:1px;color:#f7c04a;background:rgba(247,192,74,0.1);border:1px solid rgba(247,192,74,0.25);border-radius:20px;padding:5px 16px;margin-bottom:18px">Coming Soon</div>
    <div style="font-size:13px;color:#9d95a6;line-height:1.7;margin-bottom:28px">Active signals, connected brokers, P&L tracking — all in one place. Launching soon.</div>
    <button onclick="closeDash()" style="padding:11px 30px;border-radius:9px;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.28);color:var(--violet);cursor:none;font-family:'Space Grotesk',sans-serif;font-size:13px;font-weight:600">Got it</button>
  </div>
</div>

<script>
// ── BROKERS with inline SVG logos ──
const BROKERS = {
  'tv-mt5': [
    { name:'Exness',      type:'Forex · MT5',       fg:'#2ecc71', bg:'#0d3d29',
      svg:`<img src="https://img.logo.dev/exness.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'IC Markets',  type:'Forex · MT5',       fg:'#4fa3e0', bg:'#0a2540',
      svg:`<img src="https://img.logo.dev/icmarkets.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Pepperstone', type:'Forex · MT5',       fg:'#00c87a', bg:'#0a2e1f',
      svg:`<img src="https://img.logo.dev/pepperstone.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'XM',          type:'Forex · MT5',       fg:'#e63946', bg:'#3a0a0e',
      svg:`<img src="https://img.logo.dev/xm.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'FP Markets',  type:'Forex · MT5',       fg:'#f7c04a', bg:'#2a1e00',
      svg:`<img src="https://img.logo.dev/fpmarkets.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'AvaTrade',    type:'Forex · MT5',       fg:'#38bdf8', bg:'#1e1440',
      svg:`<img src="https://img.logo.dev/avatrade.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Tickmill',    type:'Forex · MT5',       fg:'#2a9d8f', bg:'#082b28',
      svg:`<img src="https://img.logo.dev/tickmill.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'HFM',         type:'Forex · MT5',       fg:'#e76f51', bg:'#2e1108',
      svg:`<img src="https://img.logo.dev/hfm.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
  ],
  'mt5-mt5': [
    { name:'Exness',      type:'Master → Follower', fg:'#2ecc71', bg:'#0d3d29', svg:`<img src="https://img.logo.dev/exness.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'IC Markets',  type:'Master → Follower', fg:'#4fa3e0', bg:'#0a2540', svg:`<img src="https://img.logo.dev/icmarkets.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Pepperstone', type:'Master → Follower', fg:'#00c87a', bg:'#0a2e1f', svg:`<img src="https://img.logo.dev/pepperstone.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'XM',          type:'Master → Follower', fg:'#e63946', bg:'#3a0a0e', svg:`<img src="https://img.logo.dev/xm.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'FP Markets',  type:'Master → Follower', fg:'#f7c04a', bg:'#2a1e00', svg:`<img src="https://img.logo.dev/fpmarkets.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'AvaTrade',    type:'Master → Follower', fg:'#38bdf8', bg:'#1e1440', svg:`<img src="https://img.logo.dev/avatrade.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Tickmill',    type:'Master → Follower', fg:'#2a9d8f', bg:'#082b28', svg:`<img src="https://img.logo.dev/tickmill.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'HFM',         type:'Master → Follower', fg:'#e76f51', bg:'#2e1108', svg:`<img src="https://img.logo.dev/hfm.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
  ],
  'tv-crypto': [
    { name:'Binance',  type:'Spot & Futures', fg:'#f0b90b', bg:'#2e2000',
      svg:`<img src="https://img.logo.dev/binance.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Bybit',    type:'Derivatives',    fg:'#f7a600', bg:'#2e1f00',
      svg:`<img src="https://img.logo.dev/bybit.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'OKX',      type:'Spot & Futures', fg:'#ffffff', bg:'#111019',
      svg:`<img src="https://img.logo.dev/okx.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Bitget',   type:'Copy Trade',     fg:'#00c0cb', bg:'#002a2c',
      svg:`<img src="https://img.logo.dev/bitget.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'MEXC',     type:'Spot & Futures', fg:'#4fa3e0', bg:'#001830',
      svg:`<img src="https://img.logo.dev/mexc.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'KuCoin',   type:'Spot & Futures', fg:'#23af92', bg:'#002820',
      svg:`<img src="https://img.logo.dev/kucoin.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Gate.io',  type:'Spot & Futures', fg:'#4470e6', bg:'#00102e',
      svg:`<img src="https://img.logo.dev/gate.io?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Phemex',   type:'Derivatives',    fg:'#7b6de0', bg:'#160e38',
      svg:`<img src="https://img.logo.dev/phemex.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
  ],
  'tv-indices': [
    { name:'Zerodha',      type:'Kite API',    fg:'#387ed1', bg:'#0a1e36',
      svg:`<img src="https://img.logo.dev/zerodha.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Angel One',    type:'SmartAPI',    fg:'#e63946', bg:'#3a0a0e',
      svg:`<img src="https://img.logo.dev/angelone.in?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Upstox',       type:'Upstox API',  fg:'#9b6be0', bg:'#1a0830',
      svg:`<img src="https://img.logo.dev/upstox.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Fyers',        type:'Fyers API',   fg:'#2ecc71', bg:'#0d3d29',
      svg:`<img src="https://img.logo.dev/fyers.in?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Dhan',         type:'Dhan API',    fg:'#f7c04a', bg:'#2a1e00',
      svg:`<img src="https://img.logo.dev/dhan.co?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'ICICI Direct', type:'iDirect API', fg:'#ff7b2e', bg:'#2e1400',
      svg:`<img src="https://img.logo.dev/icicidirect.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'5paisa',       type:'5paisa API',  fg:'#2a9d8f', bg:'#082b28',
      svg:`<img src="https://img.logo.dev/5paisa.com?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
    { name:'Groww',        type:'Groww API',   fg:'#00b386', bg:'#002820',
      svg:`<img src="https://img.logo.dev/groww.in?token=pk_dGHiURxISBalsYUwRrykOA&size=80&format=png" style="width:64px;height:64px;border-radius:10px;object-fit:contain;" onerror="this.style.display='none'">` },
  ]
};

Object.entries(BROKERS).forEach(([key,list])=>{
  const grid=document.getElementById('grid-'+key);
  if(!grid)return;
  list.forEach((b,i)=>{
    const uid='c'+Math.random().toString(36).slice(2,7);
    const s=document.createElement('style');
    s.textContent=`.${uid}::before{background:radial-gradient(ellipse at top left,${b.fg}22 0%,transparent 60%);}
    .${uid}:hover{border-color:${b.fg}99;box-shadow:0 0 0 1px ${b.fg}55,0 0 28px 4px ${b.fg}33,0 22px 52px rgba(0,0,0,0.65);}
    .${uid}:hover .bp-connect{border-color:${b.fg}66;color:${b.fg};}
    .${uid} .bp-logo{--pulse-col:${b.fg}66;}`;
    document.head.appendChild(s);
    const card=document.createElement('div');
    card.className='bp-card '+uid;
    card.style.animationDelay=(i*0.07)+'s';
    card.innerHTML=`
      <div class="bp-logo" style="background:${b.bg};">${b.svg}</div>
      <div><div class="bp-name">${b.name}</div><div class="bp-type">${b.type}</div></div>
      <div class="bp-connect">Coming Soon</div>`;
    grid.appendChild(card);

    // 3D tilt on mousemove
    card.addEventListener('mousemove',e=>{
      const r=card.getBoundingClientRect();
      const x=(e.clientX-r.left)/r.width-0.5;
      const y=(e.clientY-r.top)/r.height-0.5;
      card.style.transform=`perspective(700px) rotateY(${x*14}deg) rotateX(${-y*10}deg) translateY(-5px) scale(1.02)`;
    });
    card.addEventListener('mouseleave',()=>{
      card.style.transform='';
    });
  });
});

// MT5→MT5 strip + form
let MT5_ROLE='';
function buildMt5Strip(){
  const brokers=BROKERS['mt5-mt5']||[];
  const doubled=[...brokers,...brokers];
  const strip=document.getElementById('mt5-strip-inner');
  if(!strip)return;
  strip.innerHTML=doubled.map(b=>`<div class="strip-logo">${b.svg}<span>${b.name}</span></div>`).join('');
}
buildMt5Strip();

function selectRole(role){ MT5_ROLE=role; } // kept for compat

// Auto-fill license key in mt5 page inputs
function autoFillLicense(){
  if(!SESSION||!SESSION.token)return;
  fetch('/api/user/my-license',{headers:{'Authorization':'Bearer '+SESSION.token}})
    .then(r=>r.json()).then(d=>{
      if(d.license_key){
        const mi=document.getElementById('master-lic-inp');if(mi&&!mi.value)mi.value=d.license_key;
        const ri=document.getElementById('receiver-lic-inp');if(ri&&!ri.value)ri.value=d.license_key;
      }
    }).catch(()=>{});
}

// Called when user opens mt5-mt5 page
function onMt5PageOpen(){ buildMt5Strip(); autoFillLicense(); }

// Receiver count
let RECV_COUNT=1;
function changeReceiverCount(delta){
  RECV_COUNT=Math.max(1,Math.min(10,RECV_COUNT+delta));
  const el=document.getElementById('receiver-count-display');
  if(el)el.textContent=RECV_COUNT;
}

// EA download link builder — uses GitHub raw URL with account in filename
function eaDownloadLink(role, account, num){
  // filename pattern: AG_Master_<account>.mq5 or AG_Receiver_<account>_<num>.mq5
  const base='https://raw.githubusercontent.com/ridhi-trader/tradebridge/main/';
  if(role==='master') return {url: base+'AG_Trade_Sender.mq5', name:'AG_Master_'+account+'.mq5', label:'📤 Master EA — '+account};
  return {url: base+'AG_Trade_Receiver.mq5', name:'AG_Receiver_'+account+'_'+num+'.mq5', label:'📥 Receiver EA #'+num+' — '+account};
}

async function submitMasterForm(){
  const account=document.getElementById('master-account-inp').value.trim();
  const lic=document.getElementById('master-lic-inp').value.trim();
  const includeReceiver=document.getElementById('master-include-receiver').checked;
  const msg=document.getElementById('master-form-msg');
  if(!account){msg.textContent='❌ MT5 account number daalo';msg.style.color='var(--red)';return;}
  if(!lic){msg.textContent='❌ License key daalo';msg.style.color='var(--red)';return;}
  if(!SESSION){msg.textContent='❌ Pehle login karo';msg.style.color='var(--red)';return;}
  msg.textContent='Registering...';msg.style.color='var(--muted)';
  try{
    const r=await fetch('/api/user/add-member',{method:'POST',
      headers:{'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'},
      body:JSON.stringify({member_name:'Master Account',account_number:account,role:'master'})});
    const d=await r.json();
    if(!r.ok){msg.textContent='❌ '+(d.detail||'Error');msg.style.color='var(--red)';return;}
    msg.textContent='✅ Master registered!';msg.style.color='#4ade80';
    // Show download links
    const sec=document.getElementById('master-dl-section');
    const links=document.getElementById('master-dl-links');
    const files=[];
    files.push(eaDownloadLink('master',account,1));
    if(includeReceiver) files.push(eaDownloadLink('receiver',account,1));
    links.innerHTML=files.map(f=>`
      <a href="${f.url}" download="${f.name}"
        style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text);text-decoration:none;background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;transition:border-color 0.18s;"
        onmouseenter="this.style.borderColor='rgba(247,192,74,0.5)'" onmouseleave="this.style.borderColor='var(--border)'">
        <span style="font-size:16px;">${f.label.slice(0,2)}</span>
        <div>
          <div style="font-weight:600;">${f.label.slice(3)}</div>
          <div style="font-size:10px;color:var(--muted);">${f.name}</div>
        </div>
        <span style="margin-left:auto;font-size:10px;color:var(--gold);">⬇ Download</span>
      </a>`).join('');
    sec.style.display='block';
  }catch(e){msg.textContent='Network error';msg.style.color='var(--red)';}
}

async function submitReceiverForm(){
  const account=document.getElementById('receiver-account-inp').value.trim();
  const lic=document.getElementById('receiver-lic-inp').value.trim();
  const msg=document.getElementById('receiver-form-msg');
  if(!account){msg.textContent='❌ MT5 account number daalo';msg.style.color='var(--red)';return;}
  if(!lic){msg.textContent='❌ License key daalo';msg.style.color='var(--red)';return;}
  if(!SESSION){msg.textContent='❌ Pehle login karo';msg.style.color='var(--red)';return;}
  msg.textContent='Registering...';msg.style.color='var(--muted)';
  try{
    const r=await fetch('/api/user/add-member',{method:'POST',
      headers:{'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'},
      body:JSON.stringify({member_name:'Receiver Account',account_number:account,role:'receiver'})});
    const d=await r.json();
    if(!r.ok){msg.textContent='❌ '+(d.detail||'Error');msg.style.color='var(--red)';return;}
    msg.textContent=`✅ Registered! ${RECV_COUNT} EA file${RECV_COUNT>1?'s':''} ready.`;msg.style.color='#4ade80';
    // Show numbered download links
    const sec=document.getElementById('receiver-dl-section');
    const links=document.getElementById('receiver-dl-links');
    const files=[];
    for(let i=1;i<=RECV_COUNT;i++) files.push(eaDownloadLink('receiver',account,i));
    links.innerHTML=files.map(f=>`
      <a href="${f.url}" download="${f.name}"
        style="display:flex;align-items:center;gap:8px;font-size:12px;color:var(--text);text-decoration:none;background:var(--panel2);border:1px solid var(--border);border-radius:8px;padding:8px 12px;transition:border-color 0.18s;"
        onmouseenter="this.style.borderColor='rgba(56,189,248,0.5)'" onmouseleave="this.style.borderColor='var(--border)'">
        <span style="font-size:16px;">📥</span>
        <div>
          <div style="font-weight:600;">${f.label.slice(3)}</div>
          <div style="font-size:10px;color:var(--muted);">${f.name}</div>
        </div>
        <span style="margin-left:auto;font-size:10px;color:var(--violet);">⬇ Download</span>
      </a>`).join('');
    sec.style.display='block';
  }catch(e){msg.textContent='Network error';msg.style.color='var(--red)';}
}

async function submitMt5Form(){ /* legacy — not used */ }

// PAGE ROUTING
function openPage(key,btn){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  document.getElementById('page-'+key).classList.add('active');
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  if(btn)btn.classList.add('active');
  history.replaceState(null,'','/');
}
function goHome(){
  document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
  if(SESSION&&SESSION.role==='admin'){document.getElementById('page-admin').classList.add('active');}
  else if(SESSION&&SESSION.role==='user'){document.getElementById('page-udashboard').classList.add('active');}
  else{document.getElementById('page-landing').classList.add('active');}
  document.querySelectorAll('.nav-btn').forEach(b=>b.classList.remove('active'));
  history.replaceState(null,'','/');
}


// ── AUTH SYSTEM ──
let SESSION = JSON.parse(localStorage.getItem('agtb_session') || 'null');

function saveSession(data){ SESSION=data; localStorage.setItem('agtb_session',JSON.stringify(data)); }
function clearSession(){ SESSION=null; localStorage.removeItem('agtb_session'); }

function switchAuthTab(tab){
  document.getElementById('auth-login-form').style.display = tab==='login'?'block':'none';
  document.getElementById('auth-signup-form').style.display = tab==='signup'?'block':'none';
  document.getElementById('tab-login').classList.toggle('active', tab==='login');
  document.getElementById('tab-signup').classList.toggle('active', tab==='signup');
  document.getElementById('auth-err').textContent='';
}

async function doLogin(){
  const email=document.getElementById('login-email').value;
  const pass=document.getElementById('login-pass').value;
  document.getElementById('auth-err').textContent='';
  try{
    const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pass})});
    const d=await r.json();
    if(!r.ok){document.getElementById('auth-err').textContent=d.detail||'Login failed';return;}
    saveSession(d);
    if(d.role==='admin'){openPage('admin',null);loadAdminData();}
    else{openPage('udashboard',null);loadUserData();}
  }catch(e){document.getElementById('auth-err').textContent='Network error';}
}

async function doSignup(){
  const name=document.getElementById('signup-name').value;
  const email=document.getElementById('signup-email').value;
  const pass=document.getElementById('signup-pass').value;
  document.getElementById('auth-err').textContent='';
  try{
    const r=await fetch('/api/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email,password:pass,name})});
    const d=await r.json();
    if(!r.ok){document.getElementById('auth-err').textContent=d.detail||'Signup failed';return;}
    saveSession(d);
    openPage('udashboard',null); loadUserData();
  }catch(e){document.getElementById('auth-err').textContent='Network error';}
}

function doLogout(){clearSession();openPage('login',null);}

let WIZ_PLAN=0,WIZ_KEY='',WIZ_MAX=1;
async function loadUserData(){
  if(!SESSION||SESSION.role!=='user')return;
  document.getElementById('ud-greet').textContent='Welcome back, '+(SESSION.name||'Trader')+' 👋';
  document.getElementById('ud-email').textContent=SESSION.email||'';
  document.getElementById('ud-plan').textContent=(SESSION.plan||'free').toUpperCase();
  document.getElementById('ud-plan2').textContent=SESSION.plan||'free';
  try{
    const r=await fetch('/api/user/me',{headers:{'Authorization':'Bearer '+SESSION.token}});
    const d=await r.json();
    if(r.ok){
      document.getElementById('ud-signals').textContent=d.signal_count||0;
      document.getElementById('ud-license').textContent=d.license_key||'—';
      const wh=`${location.origin}/master/${d.id}`;
      document.getElementById('ud-webhook').textContent=wh;
    }
  }catch(e){}
  loadWizardState();
}

async function loadWizardState(){
  if(!SESSION)return;
  try{
    const r=await fetch('/api/user/my-license',{headers:{'Authorization':'Bearer '+SESSION.token}});
    const d=await r.json();
    if(r.ok&&d.license_key){
      WIZ_KEY=d.license_key;WIZ_MAX=d.max_members;
      document.getElementById('ud-license').textContent=WIZ_KEY;
      const gk=document.getElementById('guide-key');if(gk)gk.textContent=WIZ_KEY;
      showWizStep2(d);
    }else{showWizStep1();}
  }catch(e){showWizStep1();}
}

function showWizStep1(){
  const s1=document.getElementById('wiz-step1');
  const s2=document.getElementById('wiz-step2');
  if(s1)s1.style.display='block';
  if(s2)s2.style.display='none';
}

function showWizStep2(data){
  const s1=document.getElementById('wiz-step1');
  const s2=document.getElementById('wiz-step2');
  if(s1)s1.style.display='none';
  if(s2)s2.style.display='block';
  const kd=document.getElementById('wiz-key-display');if(kd)kd.textContent=WIZ_KEY;
  const gk=document.getElementById('guide-key');if(gk)gk.textContent=WIZ_KEY;
  renderWizMembers(data.members||[],data.max_members||1);
}

function renderWizMembers(members,maxM){
  const cnt=members.length;
  const pct=maxM>0?Math.round(cnt/maxM*100):0;
  const sc=document.getElementById('wiz-seat-count');if(sc)sc.textContent=cnt+' / '+maxM;
  const sb=document.getElementById('wiz-seat-bar');if(sb)sb.style.width=pct+'%';
  const addForm=document.getElementById('wiz-add-form');
  if(addForm)addForm.style.display=cnt>=maxM?'none':'block';
  const list=document.getElementById('wiz-members-list');
  if(!list)return;
  if(!members.length){
    list.innerHTML='<div style="text-align:center;padding:24px;color:var(--muted);font-size:13px">No accounts registered yet.<br>Add your Master and Receiver accounts above.</div>';
    return;
  }
  list.innerHTML=members.map(m=>{
    const isM=m.name&&m.name.toLowerCase().includes('master');
    const color=isM?'#f7c04a':'#4ade80';
    return `<div class="mem-row">
      <div class="mem-role-dot" style="background:${color}"></div>
      <div class="mem-info">
        <div class="mem-name">${m.name||'Account'}</div>
        <div class="mem-acc">${m.account}</div>
      </div>
      <button class="mem-del" onclick="removeWizMember(${m.id})">✕</button>
    </div>`;
  }).join('');
}

function selectPlan(n){
  WIZ_PLAN=n;
  [1,5,10].forEach(x=>{const el=document.getElementById('pc-'+x);if(el)el.classList.toggle('selected',x===n);});
  const btn=document.getElementById('wiz-get-btn');if(btn)btn.disabled=false;
}

async function getLicense(){
  if(!WIZ_PLAN)return;
  const btn=document.getElementById('wiz-get-btn');
  const msg=document.getElementById('wiz-step1-msg');
  if(btn){btn.disabled=true;btn.textContent='Generating...';}
  if(msg)msg.textContent='';
  try{
    const r=await fetch('/api/user/get-license',{method:'POST',
      headers:{'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'},
      body:JSON.stringify({max_members:WIZ_PLAN})});
    const d=await r.json();
    if(r.ok){
      WIZ_KEY=d.license_key;WIZ_MAX=d.max_members;
      document.getElementById('ud-license').textContent=WIZ_KEY;
      const gk=document.getElementById('guide-key');if(gk)gk.textContent=WIZ_KEY;
      loadWizardState();
    }else{
      if(msg){msg.textContent='Error: '+(d.detail||'try again');msg.style.color='var(--red)';}
      if(btn){btn.disabled=false;btn.textContent='Get My License Key';}
    }
  }catch(e){
    if(msg){msg.textContent='Network error';msg.style.color='var(--red)';}
    if(btn){btn.disabled=false;btn.textContent='Get My License Key';}
  }
}

async function addWizMember(){
  const account=document.getElementById('wiz-account');
  const role=document.getElementById('wiz-role');
  const msg=document.getElementById('wiz-add-msg');
  if(!account||!account.value.trim()){if(msg){msg.textContent='Enter account number';msg.style.color='var(--red)';}return;}
  const name=role&&role.value==='master'?'Master Account':'Receiver Account';
  if(msg){msg.textContent='Adding...';msg.style.color='var(--muted)';}
  try{
    const r=await fetch('/api/user/add-member',{method:'POST',
      headers:{'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'},
      body:JSON.stringify({member_name:name,account_number:account.value.trim(),role:role?role.value:'receiver'})});
    const d=await r.json();
    if(r.ok){
      if(msg){msg.textContent='✅ Account registered!';msg.style.color='#4ade80';}
      if(account)account.value='';
      setTimeout(()=>{if(msg)msg.textContent='';},2000);
      loadWizardState();
    }else{if(msg){msg.textContent='❌ '+(d.detail||'error');msg.style.color='var(--red)';}}
  }catch(e){if(msg){msg.textContent='Network error';msg.style.color='var(--red)';}}
}

async function removeWizMember(id){
  try{
    const r=await fetch('/api/user/remove-member/'+id,{method:'DELETE',headers:{'Authorization':'Bearer '+SESSION.token}});
    if(r.ok)loadWizardState();
  }catch(e){}
}

function copyLicenseKey(){
  if(!WIZ_KEY)return;
  navigator.clipboard.writeText(WIZ_KEY).then(()=>{
    const t=document.createElement('div');
    t.textContent='✅ License key copied!';
    t.style.cssText='position:fixed;bottom:32px;left:50%;transform:translateX(-50%);background:#1a1825;border:1px solid var(--border);color:#4ade80;padding:10px 24px;border-radius:10px;font-size:13px;z-index:9999;font-family:Space Grotesk,sans-serif;box-shadow:0 8px 32px rgba(0,0,0,0.5);';
    document.body.appendChild(t);
    setTimeout(()=>t.remove(),2500);
  });
}

function switchUTab(tab){
  ['overview','mt5','guide'].forEach(t=>{
    const el=document.getElementById('utab-'+t);
    const btn=document.getElementById('tab-'+t);
    if(el)el.style.display=t===tab?'block':'none';
    if(btn)btn.classList.toggle('active',t===tab);
  });
}

async function loadAdminData(){
  if(!SESSION||SESSION.role!=='admin')return;
  const headers={'Authorization':'Bearer '+SESSION.token};
  try{
    const sr=await fetch('/api/admin/stats',{headers});
    const stats=await sr.json();
    document.getElementById('as-total').textContent=stats.total_users||0;
    document.getElementById('as-active').textContent=stats.active_users||0;
    document.getElementById('as-paid').textContent=stats.paid_users||0;
    document.getElementById('as-signals').textContent=stats.total_signals||0;
  }catch(e){}
  try{
    const ur=await fetch('/api/admin/users',{headers});
    const users=await ur.json();
    const tbody=document.getElementById('admin-users-tbody');
    if(!users.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">No users yet</td></tr>';return;}
    tbody.innerHTML=users.map(u=>`
      <tr>
        <td style="color:var(--muted)">${u.id}</td>
        <td><div style="font-weight:600">${u.name||'—'}</div><div style="font-size:11px;color:var(--muted)">${u.email}</div></td>
        <td><span class="plan-badge plan-${u.plan}">${u.plan.toUpperCase()}</span></td>
        <td style="font-family:'Space Mono',monospace;font-size:11px;color:var(--gold)">${u.license||'—'}</td>
        <td style="font-size:11px;color:var(--muted)">${u.created?u.created.slice(0,10):'—'}</td>
        <td><span style="color:${u.active?'#4ade80':'#f26d6d'};font-size:11px;font-family:monospace">${u.active?'●  Active':'● Inactive'}</span></td>
        <td style="display:flex;gap:8px;align-items:center;">
          <button class="atoggle ${u.active?'atoggle-on':'atoggle-off'}" onclick="toggleUser(${u.id},this)">${u.active?'Disable':'Enable'}</button>
          <select class="aplan-sel" onchange="changePlan(${u.id},this.value)">
            <option ${u.plan==='free'?'selected':''}>free</option>
            <option ${u.plan==='pro'?'selected':''}>pro</option>
            <option ${u.plan==='enterprise'?'selected':''}>enterprise</option>
          </select>
        </td>
      </tr>`).join('');
  }catch(e){document.getElementById('admin-users-tbody').innerHTML='<tr><td colspan="7" style="text-align:center;color:#f26d6d;padding:32px">Error loading users</td></tr>';}
}

async function toggleUser(id,btn){
  const headers={'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'};
  const r=await fetch('/api/admin/user/'+id+'/toggle',{method:'POST',headers});
  const d=await r.json();
  btn.textContent=d.active?'Disable':'Enable';
  btn.className='atoggle '+(d.active?'atoggle-on':'atoggle-off');
}

async function changePlan(id,plan){
  const headers={'Authorization':'Bearer '+SESSION.token,'Content-Type':'application/json'};
  await fetch('/api/admin/user/'+id+'/plan',{method:'POST',headers,body:JSON.stringify({plan})});
}

// Init on load — show landing if not logged in, dashboard if logged in
(function initApp(){
  if(!SESSION){
    // Show public landing page
    document.querySelectorAll('.page').forEach(p=>p.classList.remove('active'));
    document.getElementById('page-landing').classList.add('active');
    history.replaceState(null,'','/');
    return;
  }
  if(SESSION.role==='admin'){
    openPage('admin',null);
    loadAdminData();
  } else {
    openPage('udashboard',null);
    loadUserData();
  }
})();

// MODAL
function showDash(){openPage('dashboard',null);}
function closeDash(){document.getElementById('dash-modal').classList.remove('open');}
document.getElementById('dash-modal').addEventListener('click',e=>{if(e.target.id==='dash-modal')closeDash();});

// CURSOR
const cur=document.getElementById('cursor'),ring=document.getElementById('cursor-ring'),mg=document.getElementById('mglow');
let mx=0,my=0,rx=0,ry=0;
document.addEventListener('mousemove',e=>{
  mx=e.clientX;my=e.clientY;
  cur.style.left=mx+'px';cur.style.top=my+'px';
  mg.style.left=mx+'px';mg.style.top=my+'px';
});
(function lerpR(){rx+=(mx-rx)*0.12;ry+=(my-ry)*0.12;ring.style.left=rx+'px';ring.style.top=ry+'px';requestAnimationFrame(lerpR);})();
document.querySelectorAll('button').forEach(el=>{
  el.addEventListener('mouseenter',()=>document.body.classList.add('hov'));
  el.addEventListener('mouseleave',()=>document.body.classList.remove('hov'));
});

// TICKER
const TICKS=[
  {sym:'BTC/USDT',price:'67,420',chg:'+2.4%',up:true},
  {sym:'ETH/USDT',price:'3,512',chg:'+1.8%',up:true},
  {sym:'XAU/USD',price:'2,631',chg:'-0.3%',up:false},
  {sym:'NIFTY',price:'24,180',chg:'+0.6%',up:true},
  {sym:'SOL/USDT',price:'178.4',chg:'+3.1%',up:true},
  {sym:'EUR/USD',price:'1.0842',chg:'-0.1%',up:false},
  {sym:'BNB/USDT',price:'601',chg:'+1.2%',up:true},
  {sym:'GBP/USD',price:'1.2711',chg:'+0.2%',up:true},
  {sym:'SENSEX',price:'79,440',chg:'+0.4%',up:true},
  {sym:'SPX500',price:'5,618',chg:'+0.7%',up:true},
];
(function(){
  const t=document.getElementById('ticker');
  [...TICKS,...TICKS].forEach(item=>{
    const el=document.createElement('div');el.className='ticker-item';
    el.innerHTML=`<span class="ticker-sym">${item.sym}</span><span class="ticker-price">${item.price}</span><span class="ticker-chg ${item.up?'up':'dn'}">${item.chg}</span>`;
    t.appendChild(el);
  });
})();

// PARTICLES
(function(){
  const canvas=document.getElementById('bg-canvas'),ctx=canvas.getContext('2d');
  let W,H,P=[];
  function resize(){W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;}
  function rand(a,b){return a+Math.random()*(b-a);}
  class Pt{
    constructor(){this.reset();}
    reset(){this.x=rand(0,W);this.y=rand(0,H);this.r=rand(0.4,1.8);this.vx=rand(-0.12,0.12);this.vy=rand(-0.12,0.12);this.a=rand(0.06,0.35);this.c=Math.random()>.55?'139,124,240':'247,192,74';}
    upd(){this.x+=this.vx;this.y+=this.vy;if(this.x<0||this.x>W||this.y<0||this.y>H)this.reset();}
    draw(){ctx.beginPath();ctx.arc(this.x,this.y,this.r,0,Math.PI*2);ctx.fillStyle=`rgba(${this.c},${this.a})`;ctx.fill();}
  }
  function init(){P=[];for(let i=0;i<100;i++)P.push(new Pt());}
  function lines(){
    for(let i=0;i<P.length;i++)for(let j=i+1;j<P.length;j++){
      const dx=P[i].x-P[j].x,dy=P[i].y-P[j].y,d=Math.sqrt(dx*dx+dy*dy);
      if(d<110){ctx.beginPath();ctx.moveTo(P[i].x,P[i].y);ctx.lineTo(P[j].x,P[j].y);ctx.strokeStyle=`rgba(56,189,248,${0.05*(1-d/110)})`;ctx.lineWidth=0.5;ctx.stroke();}
    }
  }
  function loop(){ctx.clearRect(0,0,W,H);lines();P.forEach(p=>{p.upd();p.draw();});requestAnimationFrame(loop);}
  resize();init();loop();
  window.addEventListener('resize',()=>{resize();init();});
})();
</script>
</body>
</html>"""


ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AG TradeBridge — Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --bg:#07080f;--panel:#0d0f1a;--panel2:#131525;--card:#161929;
  --blue:#38bdf8;--blue-dim:#0284c7;--blue-glow:rgba(56,189,248,0.15);
  --gold:#f7c04a;--green:#4ade80;--red:#f26d6d;
  --text:#eef2ff;--muted:#6b7280;--border:#1e2235;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:'Space Grotesk',sans-serif;overflow-x:hidden;}

/* BG EFFECT */
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(56,189,248,0.08),transparent);pointer-events:none;}

/* LAYOUT */
.app{display:flex;min-height:100vh;}
.sidebar{width:240px;background:var(--panel);border-right:1px solid var(--border);padding:24px 0;display:flex;flex-direction:column;position:fixed;height:100vh;z-index:10;}
.main{flex:1;margin-left:240px;padding:32px;}

/* SIDEBAR */
.sb-brand{padding:0 20px 28px;border-bottom:1px solid var(--border);}
.sb-logo{width:38px;height:38px;border-radius:10px;background:linear-gradient(135deg,var(--blue-dim),var(--blue));display:flex;align-items:center;justify-content:center;font-size:18px;margin-bottom:12px;box-shadow:0 0 20px rgba(56,189,248,0.3);}
.sb-name{font-size:15px;font-weight:700;letter-spacing:-0.3px;}
.sb-role{font-size:10px;font-family:'Space Mono',monospace;color:var(--blue);margin-top:2px;background:rgba(56,189,248,0.1);padding:2px 8px;border-radius:20px;border:1px solid rgba(56,189,248,0.2);width:fit-content;}
.sb-nav{flex:1;padding:20px 12px;}
.sb-label{font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;padding:0 8px;margin-bottom:8px;margin-top:16px;letter-spacing:1px;}
.sb-item{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:10px;font-size:13px;font-weight:500;color:var(--muted);cursor:pointer;transition:all 0.15s;margin-bottom:2px;border:1px solid transparent;}
.sb-item:hover{background:rgba(56,189,248,0.06);color:var(--text);border-color:rgba(56,189,248,0.1);}
.sb-item.active{background:rgba(56,189,248,0.1);color:var(--blue);border-color:rgba(56,189,248,0.2);}
.sb-item .icon{width:28px;height:28px;border-radius:7px;display:flex;align-items:center;justify-content:center;font-size:13px;background:rgba(255,255,255,0.04);}
.sb-item.active .icon{background:rgba(56,189,248,0.15);}
.sb-footer{padding:16px 20px;border-top:1px solid var(--border);}
.sb-logout{width:100%;padding:9px;border-radius:9px;background:rgba(242,109,109,0.08);border:1px solid rgba(242,109,109,0.2);color:#f26d6d;font-size:12px;font-weight:600;font-family:'Space Grotesk',sans-serif;cursor:pointer;transition:all 0.2s;}
.sb-logout:hover{background:rgba(242,109,109,0.15);}

/* HEADER */
.page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px;}
.page-title{font-size:22px;font-weight:700;letter-spacing:-0.5px;}
.page-sub{font-size:12px;color:var(--muted);margin-top:3px;}
.live-dot{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--green);font-family:'Space Mono',monospace;}
.live-dot::before{content:'';width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);}

/* STAT CARDS */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px;}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:16px;padding:20px;position:relative;overflow:hidden;transition:border-color 0.2s,transform 0.2s;}
.stat-card:hover{border-color:rgba(56,189,248,0.25);transform:translateY(-2px);}
.stat-card::before{content:'';position:absolute;top:0;right:0;width:80px;height:80px;border-radius:50%;filter:blur(30px);opacity:0.15;}
.stat-card.blue::before{background:var(--blue);}
.stat-card.green::before{background:var(--green);}
.stat-card.gold::before{background:var(--gold);}
.stat-card.red::before{background:var(--red);}
.stat-icon{width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:16px;margin-bottom:14px;}
.stat-icon.blue{background:rgba(56,189,248,0.12);}
.stat-icon.green{background:rgba(74,222,128,0.12);}
.stat-icon.gold{background:rgba(247,192,74,0.12);}
.stat-icon.red{background:rgba(242,109,109,0.12);}
.stat-num{font-size:30px;font-weight:700;letter-spacing:-1px;}
.stat-label{font-size:12px;color:var(--muted);margin-top:4px;}
.stat-change{font-size:11px;margin-top:8px;font-family:'Space Mono',monospace;}

/* PANELS */
.panels{display:grid;grid-template-columns:1.6fr 1fr;gap:16px;margin-bottom:16px;}
.panel{background:var(--card);border:1px solid var(--border);border-radius:16px;overflow:hidden;}
.panel-head{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;}
.panel-title{font-size:14px;font-weight:600;}
.panel-badge{font-size:10px;font-family:'Space Mono',monospace;padding:3px 10px;border-radius:20px;}
.badge-blue{background:rgba(56,189,248,0.1);color:var(--blue);border:1px solid rgba(56,189,248,0.2);}
.badge-green{background:rgba(74,222,128,0.1);color:var(--green);border:1px solid rgba(74,222,128,0.2);}
.badge-gold{background:rgba(247,192,74,0.1);color:var(--gold);border:1px solid rgba(247,192,74,0.2);}
.refresh-btn{font-size:11px;color:var(--blue);cursor:pointer;background:rgba(56,189,248,0.06);border:1px solid rgba(56,189,248,0.15);border-radius:7px;padding:5px 12px;font-family:'Space Grotesk',sans-serif;transition:all 0.2s;}
.refresh-btn:hover{background:rgba(56,189,248,0.12);}

/* TABLE */
.table-wrap{overflow-x:auto;}
table{width:100%;border-collapse:collapse;}
th{padding:10px 16px;text-align:left;font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:0.5px;border-bottom:1px solid var(--border);}
td{padding:12px 16px;font-size:13px;border-bottom:1px solid rgba(30,34,53,0.8);}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(255,255,255,0.015);}
.plan-badge{font-size:10px;font-family:'Space Mono',monospace;padding:3px 10px;border-radius:20px;}
.plan-free{background:rgba(107,114,128,0.1);color:var(--muted);border:1px solid rgba(107,114,128,0.2);}
.plan-pro{background:rgba(56,189,248,0.1);color:var(--blue);border:1px solid rgba(56,189,248,0.2);}
.plan-enterprise{background:rgba(247,192,74,0.1);color:var(--gold);border:1px solid rgba(247,192,74,0.2);}
.tog{font-size:10px;padding:4px 10px;border-radius:6px;cursor:pointer;font-family:'Space Grotesk',sans-serif;font-weight:600;border:1px solid;transition:all 0.2s;}
.tog-on{color:#f26d6d;border-color:rgba(242,109,109,0.3);background:rgba(242,109,109,0.08);}
.tog-off{color:#4ade80;border-color:rgba(74,222,128,0.3);background:rgba(74,222,128,0.08);}
.plan-sel{background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:11px;padding:4px 8px;font-family:'Space Grotesk',sans-serif;cursor:pointer;}

/* SYSTEM STATUS */
.sys-list{padding:8px 0;}
.sys-item{display:flex;align-items:center;gap:12px;padding:12px 20px;border-bottom:1px solid rgba(30,34,53,0.6);}
.sys-item:last-child{border-bottom:none;}
.sys-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.sys-info{flex:1;}
.sys-name{font-size:13px;font-weight:500;}
.sys-sub{font-size:11px;color:var(--muted);margin-top:2px;}
.sys-tag{font-size:10px;font-family:'Space Mono',monospace;letter-spacing:0.5px;}

/* LOGIN PAGE */
.login-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:20px;}
.login-card{background:var(--panel);border:1px solid rgba(56,189,248,0.15);border-radius:24px;padding:48px 40px;width:100%;max-width:420px;box-shadow:0 40px 100px rgba(0,0,0,0.6),0 0 0 1px rgba(56,189,248,0.05);}
.login-icon{width:56px;height:56px;border-radius:16px;background:linear-gradient(135deg,var(--blue-dim),var(--blue));display:flex;align-items:center;justify-content:center;font-size:26px;margin:0 auto 20px;box-shadow:0 0 30px rgba(56,189,248,0.35);}
.login-title{font-size:22px;font-weight:700;text-align:center;margin-bottom:4px;}
.login-sub{font-size:12px;color:var(--muted);text-align:center;margin-bottom:32px;}
.field{margin-bottom:16px;}
.field label{display:block;font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;letter-spacing:1px;margin-bottom:7px;}
.field input{width:100%;padding:12px 16px;border-radius:10px;background:rgba(255,255,255,0.04);border:1px solid var(--border);color:var(--text);font-size:14px;font-family:'Space Grotesk',sans-serif;outline:none;transition:border-color 0.2s,box-shadow 0.2s;}
.field input:focus{border-color:rgba(56,189,248,0.4);box-shadow:0 0 0 3px rgba(56,189,248,0.08);}
.login-btn{width:100%;padding:13px;border-radius:11px;background:linear-gradient(135deg,var(--blue-dim),var(--blue));border:none;color:#fff;font-size:14px;font-weight:700;font-family:'Space Grotesk',sans-serif;cursor:pointer;margin-top:8px;transition:opacity 0.2s,transform 0.1s;letter-spacing:0.3px;}
.login-btn:hover{opacity:0.9;transform:translateY(-1px);}
.login-btn:active{transform:translateY(0);}
.forgot{text-align:center;margin-top:16px;}
.forgot a{font-size:12px;color:var(--muted);text-decoration:none;border-bottom:1px dashed rgba(107,114,128,0.4);transition:color 0.2s;}
.forgot a:hover{color:var(--blue);}
.err{font-size:12px;color:#f26d6d;text-align:center;margin-top:12px;min-height:18px;}
.hidden{display:none;}
</style>
</head>
<body>

<!-- LOGIN -->
<div class="login-screen" id="login-screen">
  <div class="login-card">
    <div class="login-icon">🔐</div>
    <div class="login-title">Admin Control Center</div>
    <div class="login-sub">AG TradeBridge — Restricted Access</div>
    <div class="field">
      <label>MASTER PASSWORD</label>
      <input type="password" id="a-pass" placeholder="Enter password..." onkeydown="if(event.key==='Enter')doLogin()" autofocus>
    </div>
    <button class="login-btn" onclick="doLogin()">Access Admin Panel →</button>
    <div class="forgot"><a href="#" onclick="doForgot()">Forgot password?</a></div>
    <div class="err" id="a-err"></div>
  </div>
</div>

<!-- ADMIN PANEL -->
<div class="app hidden" id="admin-app">
  <!-- SIDEBAR -->
  <div class="sidebar">
    <div class="sb-brand">
      <div class="sb-logo">⚡</div>
      <div class="sb-name">AG TradeBridge</div>
      <div class="sb-role">ADMIN</div>
    </div>
    <div class="sb-nav">
      <div class="sb-label">OVERVIEW</div>
      <div class="sb-item active" onclick="showTab('overview',this)">
        <div class="icon">📊</div> Dashboard
      </div>
      <div class="sb-item" onclick="showTab('users',this)">
        <div class="icon">👥</div> Users
      </div>
      <div class="sb-label">LICENSING</div>
      <div class="sb-item" onclick="showTab('licenses',this)">
        <div class="icon">🔑</div> Licenses
      </div>
      <div class="sb-label">SYSTEM</div>
      <div class="sb-item" onclick="showTab('system',this)">
        <div class="icon">🖥️</div> System Status
      </div>
    </div>
    <div class="sb-footer">
      <button class="sb-logout" onclick="doLogout()">🚪 Logout</button>
    </div>
  </div>

  <!-- MAIN CONTENT -->
  <div class="main">

    <!-- OVERVIEW TAB -->
    <div id="tab-overview">
      <div class="page-header">
        <div>
          <div class="page-title">Dashboard</div>
          <div class="page-sub">Welcome back, AG 👋</div>
        </div>
        <div class="live-dot">All systems live</div>
      </div>
      <div class="stats-grid">
        <div class="stat-card blue">
          <div class="stat-icon blue">👥</div>
          <div class="stat-num" id="s-total">—</div>
          <div class="stat-label">Total Users</div>
          <div class="stat-change" style="color:var(--blue)">Registered</div>
        </div>
        <div class="stat-card green">
          <div class="stat-icon green">✅</div>
          <div class="stat-num" id="s-active">—</div>
          <div class="stat-label">Active Users</div>
          <div class="stat-change" style="color:var(--green)">Live accounts</div>
        </div>
        <div class="stat-card gold">
          <div class="stat-icon gold">💎</div>
          <div class="stat-num" id="s-paid">—</div>
          <div class="stat-label">Paid Users</div>
          <div class="stat-change" style="color:var(--gold)">Pro + Enterprise</div>
        </div>
        <div class="stat-card red">
          <div class="stat-icon red">📡</div>
          <div class="stat-num" id="s-signals">—</div>
          <div class="stat-label">Total Signals</div>
          <div class="stat-change" style="color:var(--blue)">All time</div>
        </div>
      </div>
      <div class="panels">
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">Recent Users</div>
            <button class="refresh-btn" onclick="loadAll()">↻ Refresh</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>USER</th><th>PLAN</th><th>STATUS</th><th>JOINED</th></tr></thead>
              <tbody id="overview-tbody"><tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">Loading...</td></tr></tbody>
            </table>
          </div>
        </div>
        <div class="panel">
          <div class="panel-head">
            <div class="panel-title">System Status</div>
            <span class="panel-badge badge-green">LIVE</span>
          </div>
          <div class="sys-list">
            <div class="sys-item">
              <div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div>
              <div class="sys-info"><div class="sys-name">TradeBridge Engine</div><div class="sys-sub">v2.1 · Running</div></div>
              <div class="sys-tag" style="color:#4ade80">LIVE</div>
            </div>
            <div class="sys-item">
              <div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div>
              <div class="sys-info"><div class="sys-name">Signal Queue</div><div class="sys-sub">0 pending · Ready</div></div>
              <div class="sys-tag" style="color:#4ade80">LIVE</div>
            </div>
            <div class="sys-item">
              <div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div>
              <div class="sys-info"><div class="sys-name">Neon Database</div><div class="sys-sub">PostgreSQL · Connected</div></div>
              <div class="sys-tag" style="color:#4ade80">OK</div>
            </div>
            <div class="sys-item">
              <div class="sys-dot" style="background:#f7c04a;box-shadow:0 0 8px rgba(247,192,74,0.5)"></div>
              <div class="sys-info"><div class="sys-name">Broker API</div><div class="sys-sub">No broker configured</div></div>
              <div class="sys-tag" style="color:#f7c04a">IDLE</div>
            </div>
            <div class="sys-item">
              <div class="sys-dot" style="background:#38bdf8;box-shadow:0 0 8px rgba(56,189,248,0.5)"></div>
              <div class="sys-info"><div class="sys-name">Render Hosting</div><div class="sys-sub">Free tier · agtradebridge.com</div></div>
              <div class="sys-tag" style="color:#38bdf8">UP</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- USERS TAB -->
    <div id="tab-users" class="hidden">
      <div class="page-header">
        <div>
          <div class="page-title">All Users</div>
          <div class="page-sub">Manage accounts, plans and access</div>
        </div>
        <button class="refresh-btn" onclick="loadAll()" style="padding:9px 18px;font-size:12px;">↻ Refresh</button>
      </div>
      <div class="panel">
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>NAME / EMAIL</th><th>PLAN</th><th>LICENSE</th><th>JOINED</th><th>STATUS</th><th>ACTIONS</th></tr></thead>
            <tbody id="users-tbody"><tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">Loading...</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>


    <!-- LICENSES TAB -->
    <div id="tab-licenses" class="hidden">
      <div class="page-header">
        <div>
          <div class="page-title">License Keys</div>
          <div class="page-sub">MT5 Sender/Receiver licensing — AG Trade System</div>
        </div>
        <button class="refresh-btn" onclick="showCreateLicense()" style="padding:9px 18px;font-size:12px;background:rgba(56,189,248,0.1);border-color:rgba(56,189,248,0.3);">+ Create Key</button>
      </div>

      <!-- CREATE FORM -->
      <div id="create-lic-form" class="panel" style="margin-bottom:16px;display:none;">
        <div class="panel-head"><div class="panel-title">Create New License Key</div></div>
        <div style="padding:20px;display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;">
          <div>
            <label style="font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;display:block;margin-bottom:6px;">BUYER NAME</label>
            <input id="lic-name" placeholder="Client name" style="width:100%;padding:9px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          </div>
          <div>
            <label style="font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;display:block;margin-bottom:6px;">BUYER EMAIL</label>
            <input id="lic-email" placeholder="client@email.com" style="width:100%;padding:9px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          </div>
          <div>
            <label style="font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;display:block;margin-bottom:6px;">PLAN NAME</label>
            <input id="lic-plan" placeholder="e.g. 10-Member Pack" style="width:100%;padding:9px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          </div>
          <div>
            <label style="font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;display:block;margin-bottom:6px;">MAX MEMBERS</label>
            <input id="lic-members" type="number" value="1" min="1" style="width:100%;padding:9px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          </div>
          <div>
            <label style="font-size:10px;color:var(--muted);font-family:'Space Mono',monospace;display:block;margin-bottom:6px;">PRODUCT</label>
            <select id="lic-product" style="width:100%;padding:9px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
              <option>AG_TRADE_RECEIVER</option>
              <option>AG_TRADE_SENDER</option>
            </select>
          </div>
          <div style="display:flex;align-items:flex-end;gap:8px;">
            <button onclick="createLicense()" style="flex:1;padding:9px;background:linear-gradient(135deg,var(--blue-dim),var(--blue));border:none;border-radius:8px;color:#fff;font-weight:700;font-family:'Space Grotesk',sans-serif;cursor:pointer;">Generate Key</button>
            <button onclick="document.getElementById('create-lic-form').style.display='none'" style="padding:9px 14px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:8px;color:var(--muted);font-family:'Space Grotesk',sans-serif;cursor:pointer;">Cancel</button>
          </div>
        </div>
        <div id="new-key-result" style="padding:0 20px 16px;font-family:'Space Mono',monospace;font-size:14px;color:var(--gold);display:none;"></div>
      </div>

      <!-- LICENSES TABLE -->
      <div class="panel">
        <div class="panel-head">
          <div class="panel-title">All License Keys</div>
          <button class="refresh-btn" onclick="loadLicenses()">↻ Refresh</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>LICENSE KEY</th><th>BUYER</th><th>PLAN</th><th>MEMBERS</th><th>PRODUCT</th><th>STATUS</th><th>ACTIONS</th></tr></thead>
            <tbody id="lic-tbody"><tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">Loading...</td></tr></tbody>
          </table>
        </div>
      </div>

      <!-- MEMBERS PANEL -->
      <div id="members-panel" class="panel" style="margin-top:16px;display:none;">
        <div class="panel-head">
          <div>
            <div class="panel-title" id="members-title">Members</div>
            <div style="font-size:11px;color:var(--muted);margin-top:2px" id="members-key-display"></div>
          </div>
          <button onclick="document.getElementById('members-panel').style.display='none'" style="font-size:11px;color:var(--muted);background:none;border:1px solid var(--border);border-radius:6px;padding:4px 12px;cursor:pointer;">Close</button>
        </div>
        <div style="padding:16px 20px;display:flex;gap:10px;border-bottom:1px solid var(--border);">
          <input id="m-name" placeholder="Member name" style="flex:1;padding:8px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:7px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          <input id="m-account" placeholder="MT5 Account Number" style="flex:1;padding:8px 12px;background:rgba(255,255,255,0.04);border:1px solid var(--border);border-radius:7px;color:var(--text);font-family:'Space Grotesk',sans-serif;font-size:13px;outline:none;">
          <button onclick="addMember()" style="padding:8px 18px;background:rgba(56,189,248,0.1);border:1px solid rgba(56,189,248,0.3);border-radius:7px;color:var(--blue);font-family:'Space Grotesk',sans-serif;font-size:12px;font-weight:600;cursor:pointer;">+ Add</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>#</th><th>MEMBER NAME</th><th>MT5 ACCOUNT</th><th>ADDED</th><th>ACTION</th></tr></thead>
            <tbody id="members-tbody"><tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No members yet</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>
    <!-- SYSTEM TAB -->
    <div id="tab-system" class="hidden">
      <div class="page-header">
        <div>
          <div class="page-title">System Status</div>
          <div class="page-sub">Infrastructure health</div>
        </div>
        <div class="live-dot">Monitoring active</div>
      </div>
      <div class="panels" style="grid-template-columns:1fr 1fr">
        <div class="panel">
          <div class="panel-head"><div class="panel-title">Services</div><span class="panel-badge badge-green">ALL OK</span></div>
          <div class="sys-list">
            <div class="sys-item"><div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div><div class="sys-info"><div class="sys-name">FastAPI Backend</div><div class="sys-sub">Python 3.12 · main.py</div></div><div class="sys-tag" style="color:#4ade80">LIVE</div></div>
            <div class="sys-item"><div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div><div class="sys-info"><div class="sys-name">Neon PostgreSQL</div><div class="sys-sub">users + signals tables</div></div><div class="sys-tag" style="color:#4ade80">OK</div></div>
            <div class="sys-item"><div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div><div class="sys-info"><div class="sys-name">Render.com</div><div class="sys-sub">Free tier · Auto-deploy ON</div></div><div class="sys-tag" style="color:#4ade80">UP</div></div>
            <div class="sys-item"><div class="sys-dot" style="background:#4ade80;box-shadow:0 0 8px #4ade80"></div><div class="sys-info"><div class="sys-name">GitHub Repo</div><div class="sys-sub">ridhi-trader/tradebridge</div></div><div class="sys-tag" style="color:#4ade80">OK</div></div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-head"><div class="panel-title">Plan Limits</div><span class="panel-badge badge-blue">CONFIG</span></div>
          <div class="sys-list">
            <div class="sys-item"><div class="sys-dot" style="background:var(--muted)"></div><div class="sys-info"><div class="sys-name">Free Plan</div><div class="sys-sub">1 broker · 50 signals/day</div></div><div class="sys-tag" style="color:var(--muted)">FREE</div></div>
            <div class="sys-item"><div class="sys-dot" style="background:var(--blue);box-shadow:0 0 8px rgba(56,189,248,0.5)"></div><div class="sys-info"><div class="sys-name">Pro Plan</div><div class="sys-sub">5 brokers · Unlimited signals</div></div><div class="sys-tag" style="color:var(--blue)">PRO</div></div>
            <div class="sys-item"><div class="sys-dot" style="background:var(--gold);box-shadow:0 0 8px rgba(247,192,74,0.4)"></div><div class="sys-info"><div class="sys-name">Enterprise Plan</div><div class="sys-sub">Unlimited · Priority support</div></div><div class="sys-tag" style="color:var(--gold)">ENT</div></div>
          </div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
let TOKEN = sessionStorage.getItem('admin_token');

async function doLogin(){
  const pass = document.getElementById('a-pass').value;
  document.getElementById('a-err').textContent = '';
  try{
    const r = await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:'',password:pass})});
    const d = await r.json();
    if(!r.ok || d.role !== 'admin'){document.getElementById('a-err').textContent = d.detail || 'Wrong password'; return;}
    TOKEN = d.token;
    sessionStorage.setItem('admin_token', TOKEN);
    showPanel();
  }catch(e){document.getElementById('a-err').textContent = 'Network error';}
}

async function doForgot(){
  await fetch('/api/admin/forgot-password',{method:'POST'});
  document.getElementById('a-err').style.color = '#4ade80';
  document.getElementById('a-err').textContent = 'Reset code sent to your email ✅';
  setTimeout(()=>{document.getElementById('a-err').style.color='#f26d6d';document.getElementById('a-err').textContent='';},5000);
}

function doLogout(){sessionStorage.removeItem('admin_token');TOKEN=null;document.getElementById('login-screen').classList.remove('hidden');document.getElementById('admin-app').classList.add('hidden');}

function showPanel(){document.getElementById('login-screen').classList.add('hidden');document.getElementById('admin-app').classList.remove('hidden');loadAll();}

function showTab(name, el){
  ['overview','users','licenses','system'].forEach(t=>document.getElementById('tab-'+t).classList.add('hidden'));
  document.getElementById('tab-'+name).classList.remove('hidden');
  document.querySelectorAll('.sb-item').forEach(i=>i.classList.remove('active'));
  el.classList.add('active');
}

async function loadAll(){
  const H = {'Authorization':'Bearer '+TOKEN};
  try{
    const s = await (await fetch('/api/admin/stats',{headers:H})).json();
    document.getElementById('s-total').textContent = s.total_users;
    document.getElementById('s-active').textContent = s.active_users;
    document.getElementById('s-paid').textContent = s.paid_users;
    document.getElementById('s-signals').textContent = s.total_signals;
  }catch(e){}
  try{
    const users = await (await fetch('/api/admin/users',{headers:H})).json();
    // Overview table (last 5)
    const ov = document.getElementById('overview-tbody');
    const recent = users.slice(0,5);
    ov.innerHTML = recent.length ? recent.map(u=>`<tr>
      <td><div style="font-weight:600;font-size:13px">${u.name||'—'}</div><div style="font-size:11px;color:var(--muted)">${u.email}</div></td>
      <td><span class="plan-badge plan-${u.plan}">${u.plan.toUpperCase()}</span></td>
      <td><span style="color:${u.active?'#4ade80':'#f26d6d'};font-size:11px">●  ${u.active?'Active':'Inactive'}</span></td>
      <td style="font-size:11px;color:var(--muted)">${u.created?u.created.slice(0,10):'—'}</td>
    </tr>`).join('') : '<tr><td colspan="4" style="text-align:center;color:var(--muted);padding:24px">No users yet</td></tr>';
    // Full users table
    const tb = document.getElementById('users-tbody');
    tb.innerHTML = users.length ? users.map(u=>`<tr>
      <td style="color:var(--muted);font-family:monospace;font-size:11px">${u.id}</td>
      <td><div style="font-weight:600">${u.name||'—'}</div><div style="font-size:11px;color:var(--muted)">${u.email}</div></td>
      <td><span class="plan-badge plan-${u.plan}">${u.plan.toUpperCase()}</span></td>
      <td style="font-family:'Space Mono',monospace;font-size:11px;color:var(--gold)">${u.license||'—'}</td>
      <td style="font-size:11px;color:var(--muted)">${u.created?u.created.slice(0,10):'—'}</td>
      <td><span style="color:${u.active?'#4ade80':'#f26d6d'};font-size:11px">● ${u.active?'Active':'Inactive'}</span></td>
      <td style="display:flex;gap:8px;align-items:center;">
        <button class="tog ${u.active?'tog-on':'tog-off'}" onclick="toggleUser(${u.id},this)">${u.active?'Disable':'Enable'}</button>
        <select class="plan-sel" onchange="changePlan(${u.id},this.value)">
          <option ${u.plan==='free'?'selected':''}>free</option>
          <option ${u.plan==='pro'?'selected':''}>pro</option>
          <option ${u.plan==='enterprise'?'selected':''}>enterprise</option>
        </select>
      </td>
    </tr>`).join('') : '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">No users yet</td></tr>';
  }catch(e){}
}

async function toggleUser(id,btn){
  const r = await fetch('/api/admin/user/'+id+'/toggle',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN}});
  const d = await r.json();
  btn.textContent = d.active?'Disable':'Enable';
  btn.className = 'tog '+(d.active?'tog-on':'tog-off');
}

async function changePlan(id,plan){
  await fetch('/api/admin/user/'+id+'/plan',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'},body:JSON.stringify({plan})});
}


// ── LICENSE ADMIN JS ──
let currentLicKey = null;

function showCreateLicense(){
  const f=document.getElementById('create-lic-form');
  f.style.display=f.style.display==='none'?'block':'none';
  document.getElementById('new-key-result').style.display='none';
}

async function createLicense(){
  const H={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'};
  const body={
    buyer_name:document.getElementById('lic-name').value,
    buyer_email:document.getElementById('lic-email').value,
    plan_name:document.getElementById('lic-plan').value,
    max_members:parseInt(document.getElementById('lic-members').value)||1,
    product:document.getElementById('lic-product').value
  };
  const r=await fetch('/api/license/create',{method:'POST',headers:H,body:JSON.stringify(body)});
  const d=await r.json();
  if(d.key){
    const el=document.getElementById('new-key-result');
    el.style.display='block';
    el.textContent='✅ Key Generated: '+d.key;
    loadLicenses();
  }
}

async function loadLicenses(){
  const H={'Authorization':'Bearer '+TOKEN};
  try{
    const lics=await (await fetch('/api/license/list',{headers:H})).json();
    const tb=document.getElementById('lic-tbody');
    if(!lics.length){tb.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">No licenses yet</td></tr>';return;}
    tb.innerHTML=lics.map(l=>`<tr>
      <td style="font-family:'Space Mono',monospace;font-size:11px;color:var(--gold)">${l.key}</td>
      <td><div style="font-weight:600;font-size:13px">${l.buyer_name||'—'}</div><div style="font-size:11px;color:var(--muted)">${l.buyer_email||''}</div></td>
      <td style="font-size:12px">${l.plan_name||'—'}</td>
      <td><span style="font-family:'Space Mono',monospace;font-size:12px">${l.member_count}/${l.max_members}</span></td>
      <td><span style="font-size:10px;font-family:'Space Mono',monospace;padding:2px 8px;border-radius:20px;background:rgba(56,189,248,0.08);color:var(--blue);border:1px solid rgba(56,189,248,0.15)">${l.product.replace('AG_TRADE_','')}</span></td>
      <td><span style="color:${l.active?'#4ade80':'#f26d6d'};font-size:11px">● ${l.active?'Active':'Disabled'}</span></td>
      <td style="display:flex;gap:6px;">
        <button class="tog ${l.active?'tog-on':'tog-off'}" onclick="toggleLicense('${l.key}',this)">${l.active?'Disable':'Enable'}</button>
        <button onclick="openMembers('${l.key}')" style="font-size:11px;padding:4px 10px;border-radius:6px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.2);color:var(--blue);cursor:pointer;">Members</button>
      </td>
    </tr>`).join('');
  }catch(e){}
}

async function toggleLicense(key,btn){
  const r=await fetch('/api/license/'+key+'/toggle',{method:'POST',headers:{'Authorization':'Bearer '+TOKEN}});
  const d=await r.json();
  btn.textContent=d.active?'Disable':'Enable';
  btn.className='tog '+(d.active?'tog-on':'tog-off');
}

async function openMembers(key){
  currentLicKey=key;
  document.getElementById('members-panel').style.display='block';
  document.getElementById('members-key-display').textContent=key;
  document.getElementById('members-title').textContent='Registered Members';
  await loadMembers();
  document.getElementById('members-panel').scrollIntoView({behavior:'smooth'});
}

async function loadMembers(){
  if(!currentLicKey)return;
  const H={'Authorization':'Bearer '+TOKEN};
  try{
    const members=await (await fetch('/api/license/'+currentLicKey+'/members',{headers:H})).json();
    const tb=document.getElementById('members-tbody');
    if(!members.length){tb.innerHTML='<tr><td colspan="5" style="text-align:center;color:var(--muted);padding:24px">No members registered yet</td></tr>';return;}
    tb.innerHTML=members.map(m=>`<tr>
      <td style="color:var(--muted);font-family:monospace;font-size:11px">${m.id}</td>
      <td style="font-weight:600;font-size:13px">${m.name||'—'}</td>
      <td style="font-family:'Space Mono',monospace;font-size:12px;color:var(--blue)">${m.account}</td>
      <td style="font-size:11px;color:var(--muted)">${m.added?m.added.slice(0,10):'—'}</td>
      <td><button onclick="removeMember(${m.id})" style="font-size:11px;padding:3px 10px;border-radius:6px;background:rgba(242,109,109,0.08);border:1px solid rgba(242,109,109,0.2);color:#f26d6d;cursor:pointer;">Remove</button></td>
    </tr>`).join('');
  }catch(e){}
}

async function addMember(){
  const name=document.getElementById('m-name').value;
  const account=document.getElementById('m-account').value;
  if(!account){alert('MT5 account number required');return;}
  const H={'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'};
  const r=await fetch('/api/license/'+currentLicKey+'/add-member',{method:'POST',headers:H,body:JSON.stringify({member_name:name,account_number:account})});
  const d=await r.json();
  if(d.ok){document.getElementById('m-name').value='';document.getElementById('m-account').value='';await loadMembers();}
  else alert(d.detail||'Error');
}

async function removeMember(id){
  if(!confirm('Remove this member?'))return;
  await fetch('/api/license/'+currentLicKey+'/member/'+id,{method:'DELETE',headers:{'Authorization':'Bearer '+TOKEN}});
  await loadMembers();
}

if(TOKEN) showPanel();
</script>
</body>
</html>"""



@app.get("/", response_class=HTMLResponse)
async def home():
    return HTML

@app.get("/ag-ctrl-x7k2", response_class=HTMLResponse)
async def admin_page():
    return ADMIN_HTML

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
