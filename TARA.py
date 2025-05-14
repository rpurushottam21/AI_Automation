import streamlit as st
import json, os, re, bcrypt
import google.generativeai as genai
from config import decrypt, encrypted_api_key, password, encrypted_user_password, user_name


# Configuration

DB_FILE = "users2.json"
ADMIN_USERNAME = user_name
ADMIN_PASSWORD = decrypt(encrypted_user_password,user_name) # In production, use environment variables
#YOUR_GEMINI_API_KEY= "AIzaSyCXV9AYcGLu5GaoTZ6j5WvzqeGeZ5bDPds"
YOUR_GEMINI_API_KEY= decrypt(encrypted_api_key,password)

# Gemini setup

genai.configure(api_key=YOUR_GEMINI_API_KEY)
model = genai.GenerativeModel("gemini-1.5-flash")

# Load Users from JSON

def load_users():
    return json.load(open(DB_FILE)) if os.path.exists(DB_FILE) else {}

# Save Users to JSON

def save_users(users):
    json.dump(users, open(DB_FILE, "w"), indent=4)
# Hashing Passwords

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

# Checking Passwords

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

# Register User

def register_user(email, username, password):
    users = load_users()
    if username in users:
        return False, "User already exists."
    users[email] = {
    "username": username,
    "password": hash_password(password),
    "approved": False
    }
    save_users(users)
    return True, "Registered successfully! Await admin approval."

# Approve User

def approve_user(email):
    users = load_users()
    if email in users:
        users[email]["approved"] = True
        save_users(users)
        return True
    return False

# User Login

def login_user(username, email, password):
    users = load_users()
    if email in users and check_password(password, users[email]["password"]):
        if not users[email]["approved"]:
            return False, "Waiting for admin approval."
        return True, username
    return False, "Invalid credentials."

# Admin Login

def admin_login(username, password):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

# TARA Analysis Function

def tara_analysis(asset_name, use_case):
    prompt = f"""

    You are an expert in Automotive Cybersecurity following ISO/SAE 21434.
    Perform a complete Threat Analysis and Risk Assessment (TARA) as per Clause 9 and Clause 15.
    Inputs:
        Asset Name: {asset_name}
        Use Case / Functionality: {use_case}
    Generate the following for each identified asset:
    1. Affected CIA properties (only list impacted ones)
    2. For each affected CIA property:
        - Damage Scenario
        - Threat Scenario
        - Impact Rating (Severe/Major/Moderate/Negligible)
        -Safety: (Severe,Major,Moderate,Negligible)
        -Financial: (Severe,Major,Moderate,Negligible)
        -Operational: (Severe,Major,Moderate,Negligible)
        -Privacy: (Severe,Major,Moderate,Negligible)
        - Attack Feasibility Rating: (High/Medium/Low/verylow)
        -Elapsed time: Enumerate(<=1day,<=week,<=1month,<=6months,>6months)
        -Specialist expertise: Enumerate(Layman,Proficient,Expert,Multiple experts)
        -Knowledge of the item or component: Enumerate(Public, Restricted, Confidential,Strictly confidential)
        -Window of opportunity: Enumerate(Unlimited,Easy,Moderate,Difficult)
        -Equipment: Enumerate(Standard,Specialized,Bespoke,Multiple bespoke)
        - Final Risk Value (1, 2, 3, 4, 5)
        - Risk Treatment (Reduce / Retain / Share / Avoid)
        - If Final Risk Value > 2, suggest Cybersecurity Control
        - Else suggest claims
    Note: Format clearly and use structured bullet points and sub-points
    """
    response = model.generate_content(prompt)
    return response.text

# Streamlit UI

st.set_page_config("TARA Framework", layout="centered")

st.title("TARA Framework - ISO 21434")

# Default Page State

if "page" not in st.session_state:
    st.session_state.page = "register"
if "username" not in st.session_state: #tbc
    st.session_state.username = ""
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# Sidebar Navigation

with st.sidebar:
    st.markdown("### Dashboard")
    if st.button("Register", key="1"):
        st.session_state.page = "register"
    if st.button("Admin Panel",key="2"):
        st.session_state.page = "admin_login"
    if st.button("Login",key="3"):
        st.session_state.page = "login"

# Show Registration Page

if st.session_state.page == "register":
    st.subheader("User Registration")
    email = st.text_input("email-ID")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Register"):
        if password != confirm_password:
            st.error("Passwords do not match.")
        elif len(password) < 8:
            st.error("Password must be at least 8 characters long.")
        else:
            success, msg = register_user(email, username, password)
            if success:
                st.success(msg)
                st.session_state.page = "login"    
            else:
                st.error(msg)

# Show Admin Login Page

elif st.session_state.page == "admin_login":
    st.subheader("Admin Login")
    admin_username = st.text_input("Admin Username")
    admin_password = st.text_input("Password", type="password")
    
    if st.button("Login as Admin"):
        if admin_login(admin_username, admin_password):
            st.session_state.page = "admin_panel"
        else:
            st.error("Invalid admin credentials.")

# Show Admin Panel (After Admin Login)

elif st.session_state.page == "admin_panel":
    st.subheader("Admin Panel - Approve Users") 
    users = load_users()
    pending_users = [u for u in users if not users[u]["approved"]]
    if pending_users:
        for user in pending_users:
            st.write(f"User: {user}")
            if st.button(f"Approve {user}"):
                approve_user(user)
                st.success(f"Approved {user}")
    else:
        st.info("No users pending approval.")

# Show Login Page

elif st.session_state.page == "login":
    st.subheader("User Login")
    username = st.text_input("username")
    email = st.text_input("email ID")
    password = st.text_input("Password", type="password")
    if st.button("Login", key="6"):
        success, msg = login_user(username, email, password)
        if success:
            st.session_state.username = msg
            st.session_state.logged_in = True
            st.session_state.page = "tara_analysis"
        else:
            st.error(msg)

# Show TARA Analysis Page (After User Login)
elif st.session_state.page == "tara_analysis":
    st.subheader(f"TARA Analysis - Welcome {st.session_state.username}")

    asset_name = st.text_input("Asset Name")
    use_case = st.text_area("Functionality / Use Case")

    if st.button("Generate TARA Analysis",key="7"):
        if asset_name and use_case:
            with st.spinner("Generating analysis..."):
                result = tara_analysis(asset_name, use_case)
            st.subheader(f"Analysis for {asset_name}")
            st.write(result)
        else:
            st.warning("Please provide both inputs.")
    if st.button("Logout"):
        st.session_state.page = "login"
        st.session_state.username = ""
        st.session_state.logged_in = False