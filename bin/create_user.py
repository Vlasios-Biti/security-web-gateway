#!/usr/bin/env python3
import getpass,re,sys
from pathlib import Path
APP_ROOT = Path(__file__).resolve().parents[1]
if str(APP_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_ROOT))
from argon2 import PasswordHasher
from app.db import connect,verify_schema
verify_schema()
if len(sys.argv)!=3:
    print("Usage: create_user.py USERNAME ROLE");sys.exit(1)
username=sys.argv[1].strip().lower();role=sys.argv[2].strip().lower()
if not re.fullmatch(r"[a-z0-9._-]{3,64}",username):print("Invalid username.");sys.exit(1)
if role not in("viewer","operator","admin"):print("Role must be viewer, operator or admin.");sys.exit(1)
pw=getpass.getpass("Password: ");cf=getpass.getpass("Confirm password: ")
if pw!=cf:print("Passwords do not match.");sys.exit(1)
if len(pw)<14:print("Password must contain at least 14 characters.");sys.exit(1)
c=connect()
try:
    if c.execute("SELECT 1 FROM users WHERE username=?",(username,)).fetchone():print("User already exists.");sys.exit(1)
    c.execute("INSERT INTO users(username,password_hash,role,enabled) VALUES(?,?,?,1)",(username,PasswordHasher().hash(pw),role));c.commit()
finally:c.close()
print(f"User '{username}' created with role '{role}'.")
