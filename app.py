# app.py
import streamlit as st
import pandas as pd
import bcrypt
import json
import base64
import uuid
import os
import re
from pathlib import Path
from datetime import datetime

# ---------- CONFIG ----------
BASE = Path(__file__).parent
DATA_DIR = BASE / "data"
DOC_DIR = DATA_DIR / "documents"
USER_FOLDER_DIR = DATA_DIR / "user_folders"
SESSION_FILE = DATA_DIR / "session.json"

USER_FILE = DATA_DIR / "users.csv"
ROLE_FILE = DATA_DIR / "roles.csv"
DEPT_FILE = DATA_DIR / "departments.csv"
DOC_DB = DATA_DIR / "documents.csv"
AUDIT_FILE = DATA_DIR / "audit_log.csv"

LOGO_FILE = BASE / "logo.png"
DASH_BG = BASE / "photo1.jpg"   # required dashboard background
LOGIN_BG = BASE / "photo.jpg"   # optional login background (if present)

# ensure directories
for d in (DATA_DIR, DOC_DIR, USER_FOLDER_DIR):
    d.mkdir(parents=True, exist_ok=True)

st.set_page_config(page_title="KOFIKROM SDA S-Documentary", layout="wide")

# ---------- HELPERS ----------
def ensure_csv(path: Path, cols: list, default_rows=None):
    if not path.exists():
        df = pd.DataFrame(columns=cols)
        if default_rows:
            df = pd.DataFrame(default_rows)
        df.to_csv(path, index=False)
    else:
        try:
            df = pd.read_csv(path)
        except Exception:
            df = pd.DataFrame(columns=cols)
        for c in cols:
            if c not in df.columns:
                df[c] = ""
        cols_in_df = [c for c in cols if c in df.columns]
        other = [c for c in df.columns if c not in cols_in_df]
        df = df[cols_in_df + other]
        df.to_csv(path, index=False)

def load_csv(path: Path) -> pd.DataFrame:
    if path.exists():
        try:
            return pd.read_csv(path)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

def save_csv(df: pd.DataFrame, path: Path):
    df.to_csv(path, index=False)

def sanitize_csv_value(val: str) -> str:
    s = str(val)
    if s.startswith(("=", "+", "-", "@")):
        return "'" + s
    return s

def hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_pw(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def audit(user, role, action, target="", details=""):
    ensure_csv(AUDIT_FILE, ["Timestamp","User","Role","Action","Target","Details"])
    logs = load_csv(AUDIT_FILE)
    logs = pd.concat([logs, pd.DataFrame([{
        "Timestamp": now_ts(),
        "User": sanitize_csv_value(user),
        "Role": sanitize_csv_value(role),
        "Action": sanitize_csv_value(action),
        "Target": sanitize_csv_value(target),
        "Details": sanitize_csv_value(details)
    }])], ignore_index=True)
    save_csv(logs, AUDIT_FILE)

def img_to_base64(path: Path):
    if not path.exists():
        return ""
    return base64.b64encode(path.read_bytes()).decode()

def save_session(data: dict):
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SESSION_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f)

def load_session():
    if SESSION_FILE.exists():
        try:
            return json.load(open(SESSION_FILE, "r", encoding="utf-8"))
        except Exception:
            return None
    return None

def clear_session():
    if SESSION_FILE.exists():
        try:
            SESSION_FILE.unlink()
        except Exception:
            pass

def user_folder(username: str) -> Path:
    p = USER_FOLDER_DIR / username
    p.mkdir(parents=True, exist_ok=True)
    return p

def profile_json_path(username: str) -> Path:
    return user_folder(username) / "profile.json"

def write_profile(username: str, payload: dict):
    p = profile_json_path(username)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def read_profile(username: str) -> dict:
    p = profile_json_path(username)
    if p.exists():
        try:
            return json.load(open(p, "r", encoding="utf-8"))
        except Exception:
            return {}
    return {}

def safe_filename(name: str) -> str:
    base = Path(name).name
    return f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex}_{base}"

def embed_pdf(path: Path, height=700):
    if not path.exists():
        return "<div>PDF missing</div>"
    data = base64.b64encode(path.read_bytes()).decode()
    return f'<iframe src="data:application/pdf;base64,{data}" width="100%" height="{height}px" style="border:none;"></iframe>'

# ---------- Ensure DBs ----------
ensure_csv(USER_FILE, ["Username","Password","Name","Role","Department"],
           default_rows=[{"Username":"admin","Password":hash_pw("admin123"),"Name":"Administrator","Role":"Admin","Department":"Administration"}])
ensure_csv(ROLE_FILE, ["Role"], default_rows=[{"Role":"Admin"},{"Role":"HR"},{"Role":"Nurse Manager"},{"Role":"Head of Facility"}])
ensure_csv(DEPT_FILE, ["Department"], default_rows=[{"Department":"Administration"},{"Department":"Human Resources"},{"Department":"Finance"}])
ensure_csv(DOC_DB, ["Title","Category","Department","Uploader","Upload Date","File Path","Shared With"])
ensure_csv(AUDIT_FILE, ["Timestamp","User","Role","Action","Target","Details"])

# ---------- Session state defaults ----------
default_state = {
    "auth": False,
    "username": "",
    "name": "",
    "role": "",
    "dept": "",
    "remember": False,
    "token": "",
    "dark": False
}
for k,v in default_state.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ---------- Auto-login ----------
saved = load_session()
if saved and not st.session_state["auth"]:
    u = saved.get("username")
    token = saved.get("token","")
    users = load_csv(USER_FILE)
    if not users.empty and u in users["Username"].values:
        user = users[users["Username"]==u].iloc[0]
        st.session_state.update({
            "auth": True,
            "username": user["Username"],
            "name": user.get("Name",""),
            "role": user.get("Role",""),
            "dept": user.get("Department",""),
            "remember": True,
            "token": token
        })

# ---------- LOGIN UI (Glass Theme Centered) ----------
if not st.session_state["auth"]:
    login_bg_b64 = img_to_base64(LOGIN_BG) if LOGIN_BG.exists() else ""
    ext = LOGIN_BG.suffix.replace(".", "") if LOGIN_BG.exists() else "jpg"

    st.markdown(f"""
    <style>
    .stApp {{
        background: url("data:image/{ext};base64,{login_bg_b64}") no-repeat center center fixed;
        background-size: cover;
        font-family: 'Segoe UI', sans-serif;
    }}
    .login-container {{
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        width: 340px;
        padding: 30px 26px;
        background: rgba(255, 255, 255, 0.08);
        border: 1px solid rgba(255, 255, 255, 0.18);
        border-radius: 16px;
        backdrop-filter: blur(12px);
        box-shadow: 0 8px 40px rgba(0, 0, 0, 0.35);
        color: #fff;
        text-align: center;
    }}
    .login-title {{
        font-weight: 700;
        font-size: 1.1rem;
        margin-top: 10px;
        margin-bottom: 4px;
        color: #002fffdd;
    }}
    .login-sub {{
        color: #00ff26;
        margin-bottom: 18px;
        font-size: 0.9rem;
    }}
    .stTextInput > div > div > input {{
        background-color: rgba(255, 255, 255, 0.18);
        color: white;
        border-radius: 10px;
        border: none;
        padding: 8px 10px;
        width: 92%;
        font-weight: 500;
    }}
    .stTextInput > div > label {{
        color: #f0f0f0;
        font-size: 0.85rem;
        font-weight: 600;
    }}
    .stButton button {{
        width: 92%;
        border-radius: 12px;
        padding: 8px;
        background: linear-gradient(135deg, #4dabf7, #228be6);
        color: #fff;
        font-weight: 700;
        border: none;
        transition: all 0.25s ease-in-out;
    }}
    .stButton button:hover {{
        transform: scale(1.03);
        background: linear-gradient(135deg, #74c0fc, #1c7ed6);
    }}
    .stCheckbox label {{
        color: #f0f0f0;
        font-weight: 500;
        font-size: 0.85rem;
    }}
    </style>
    """, unsafe_allow_html=True)

    st.markdown('<div class="login-container">', unsafe_allow_html=True)
    if LOGO_FILE.exists():
        st.image(str(LOGO_FILE), width=80)
    st.markdown('<div class="login-title">KOFIKROM SDA S-Documentary</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-sub">Secure access portal</div>', unsafe_allow_html=True)

    with st.form("login_form", clear_on_submit=False):
        un = st.text_input("Username", placeholder="username")
        pw = st.text_input("Password", type="password", placeholder="••••••")
        remember = st.checkbox("Remember me")
        submitted = st.form_submit_button("Login")

        if submitted:
            users = load_csv(USER_FILE)
            if users.empty or un not in users["Username"].values:
                st.error("User not found.")
            else:
                user = users[users["Username"] == un].iloc[0]
                if check_pw(pw, user["Password"]):
                    st.session_state.update({
                        "auth": True,
                        "username": user["Username"],
                        "name": user.get("Name", ""),
                        "role": user.get("Role", ""),
                        "dept": user.get("Department", ""),
                        "remember": bool(remember),
                        "token": uuid.uuid4().hex
                    })
                    if remember:
                        save_session({"username": user["Username"], "token": st.session_state["token"]})
                    audit(st.session_state["name"], st.session_state["role"], "Login")
                    st.success(f"Welcome {st.session_state['name']} ({st.session_state['role']})")
                    st.rerun()
                else:
                    st.error("Incorrect password.")
    st.markdown('</div>', unsafe_allow_html=True)
    st.stop()


# ---------- Dashboard background and header ----------
dash_b64 = img_to_base64(DASH_BG) if DASH_BG.exists() else ""
ext = DASH_BG.suffix.replace(".","") if DASH_BG.exists() else "jpg"

# dark toggle
col_a, col_b = st.columns([9,1])
with col_b:
    st.session_state["dark"] = st.checkbox("Dark", value=st.session_state.get("dark", False))

dark_css = "filter: invert(0%);" if not st.session_state["dark"] else "filter: invert(92%) hue-rotate(180deg);"

st.markdown(f"""
    <style>
    .stApp {{
        background: url("data:image/{ext};base64,{dash_b64}") no-repeat center fixed;
        background-size: cover;
    }}
    .header-card {{ background: rgba(255,255,255,0.85); border-radius:10px; padding:8px; }}
    .dark-body {{ {dark_css} }}
    </style>
""", unsafe_allow_html=True)

# header
c1, c2, c3 = st.columns([1,7,1])
with c1:
    if LOGO_FILE.exists():
        st.image(str(LOGO_FILE), width=70)
with c2:
    st.markdown(f"### 📁 KOFIKROM SDA HOSPITAL ADMINISTRATIVE S-DOCUMENTARY")
    st.markdown(f"**{st.session_state.get('name','')}** • {st.session_state.get('role','')} • {st.session_state.get('dept','')}")
with c3:
    if st.button("🚪 Logout"):
        audit(st.session_state.get("name",""), st.session_state.get("role",""), "Logout")
        remember_flag = st.session_state.get("remember", False)
        dark_pref = st.session_state.get("dark", False)
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.session_state["dark"] = dark_pref
        if remember_flag:
            clear_session()
        st.rerun()

st.markdown("---")

# ---------- Sidebar & Menu ----------
def is_admin():
    return st.session_state.get("role","").strip().lower()=="admin"

def is_hr():
    return st.session_state.get("role","").strip().lower()=="hr"

base_menu = [
    "📤 Upload Document",
    "📂 My & Shared Documents",
    "🔗 Share Document",
    "🔎 Search Documents",
    "ℹ️ About"
]
admin_menu = []
if is_admin() or is_hr():
    admin_menu.append("🗂️ User Files")
if is_admin():
    admin_menu += ["🏢 Department Management", "👔 Role Management", "👥 User Management", "🧾 Audit Log"]

st.sidebar.markdown("#### Quick Actions")
if st.sidebar.button("＋ Upload"):
    choice = "📤 Upload Document"
elif st.sidebar.button("🔗 Share"):
    choice = "🔗 Share Document"
elif st.sidebar.button("🔎 Search"):
    choice = "🔎 Search Documents"
else:
    choice = st.sidebar.radio("Menu", base_menu + admin_menu, index=0)

# ---------- DB helpers ----------
def load_docs():
    ensure_csv(DOC_DB, ["Title","Category","Department","Uploader","Upload Date","File Path","Shared With"])
    return load_csv(DOC_DB)

def save_docs(df):
    for c in ["Title","Category","Department","Uploader","Shared With"]:
        if c in df.columns:
            df[c] = df[c].astype(str).map(sanitize_csv_value)
    save_csv(df, DOC_DB)

# ---------- Upload ----------
if choice == "📤 Upload Document":
    st.header("📤 Upload Document")
    title = st.text_input("Title")
    category = st.text_input("Category", placeholder="HR, Finance, etc.")
    depts = load_csv(DEPT_FILE)
    dept_list = depts["Department"].tolist() if not depts.empty else [st.session_state.get("dept","General")]
    default_dept = st.session_state.get("dept","General")
    department = st.selectbox("Department", dept_list, index=dept_list.index(default_dept) if default_dept in dept_list else 0)
    file = st.file_uploader("Select file", type=["pdf","docx","xlsx","png","jpg","jpeg"])
    if st.button("Upload"):
        if not (title and category and file):
            st.error("Please fill all fields and attach file.")
        else:
            fname = safe_filename(file.name)
            path = DOC_DIR / fname
            with open(path, "wb") as f:
                f.write(file.read())
            db = load_docs()
            db = pd.concat([db, pd.DataFrame([{
                "Title": sanitize_csv_value(title),
                "Category": sanitize_csv_value(category),
                "Department": sanitize_csv_value(department),
                "Uploader": st.session_state["username"],
                "Upload Date": now_ts(),
                "File Path": str(path),
                "Shared With": ""
            }])], ignore_index=True)
            save_docs(db)
            audit(st.session_state["name"], st.session_state["role"], "Upload", target=title, details=f"Dept={department}")
            st.success("Uploaded successfully.")
            st.rerun()

# ---------- My & Shared Documents ----------
elif choice == "📂 My & Shared Documents":
    st.header("📂 My Documents & Shared With Me")
    db = load_docs()
    if db.empty:
        st.info("No documents found.")
    else:
        def shared_with_me(s):
            if pd.isna(s) or str(s).strip()=="":
                return False
            users = [u.strip() for u in str(s).split(",") if u.strip()]
            return st.session_state["username"] in users
        visible = db[(db["Uploader"]==st.session_state["username"]) | (db["Shared With"].apply(shared_with_me))]
        if visible.empty:
            st.info("No documents available for you.")
        else:
            for idx, row in visible.sort_values("Upload Date", ascending=False).iterrows():
                with st.expander(f"{row['Title']}  —  {row['Category']}"):
                    st.write(f"**Uploader:** {row['Uploader']}")
                    st.write(f"**Department:** {row.get('Department','')}")
                    st.write(f"**Uploaded:** {row.get('Upload Date','')}")
                    st.write(f"**Shared With:** {row.get('Shared With','') or '—'}")

                    fp = Path(row["File Path"])
                    if fp.exists():
                        if fp.suffix.lower()==".pdf":
                            if st.button("Preview PDF", key=f"pv_{idx}"):
                                with st.modal(f"Preview — {row['Title']}"):
                                    st.markdown(f"**{row['Title']}** — {row.get('Category','')}")
                                    st.components.v1.html(embed_pdf(fp, height=700), height=720)
                        elif fp.suffix.lower() in [".png",".jpg",".jpeg"]:
                            if st.button("Preview Image", key=f"ip_{idx}"):
                                with st.modal(f"Preview — {row['Title']}"):
                                    st.image(str(fp))
                        try:
                            st.download_button("Download", open(row["File Path"], "rb"), file_name=Path(row["File Path"]).name)
                        except FileNotFoundError:
                            st.error("File missing on server.")
                    else:
                        st.error("File missing on server.")

                    if (row["Uploader"]==st.session_state["username"]) or is_admin():
                        col1, col2 = st.columns(2)
                        with col1:
                            depts = load_csv(DEPT_FILE)
                            dept_opts = depts["Department"].tolist() if not depts.empty else []
                            dsel = st.selectbox("Select Department", ["(All)"]+dept_opts, key=f"dsel_{idx}")
                            users_df = load_csv(USER_FILE)
                            if dsel != "(All)":
                                users_df = users_df[users_df["Department"]==dsel]
                            share_user = st.selectbox("Share with (username)", [""] + users_df["Username"].tolist(), key=f"share_{idx}")
                            if st.button("Share", key=f"share_btn_{idx}"):
                                if not share_user:
                                    st.error("Choose a recipient.")
                                else:
                                    cur = str(db.at[idx,"Shared With"]) if pd.notna(db.at[idx,"Shared With"]) else ""
                                    cur_set = set([u.strip() for u in cur.split(",") if u.strip()])
                                    cur_set.add(share_user)
                                    db.at[idx,"Shared With"] = ",".join(sorted(cur_set))
                                    save_docs(db)
                                    audit(st.session_state["name"], st.session_state["role"], "Share", target=row["Title"], details=f"To {share_user}")
                                    st.success(f"Shared with {share_user}")
                                    st.rerun()
                        with col2:
                            revoke_user = st.text_input("Revoke user (username)", key=f"revoke_{idx}")
                            if st.button("Revoke", key=f"revoke_btn_{idx}"):
                                cur = str(db.at[idx,"Shared With"]) if pd.notna(db.at[idx,"Shared With"]) else ""
                                new_list = [u.strip() for u in cur.split(",") if u.strip() and u.strip()!=revoke_user]
                                db.at[idx,"Shared With"] = ",".join(new_list)
                                save_docs(db)
                                audit(st.session_state["name"], st.session_state["role"], "Revoke", target=row["Title"], details=f"From {revoke_user}")
                                st.warning(f"Revoked {revoke_user}")
                                st.rerun()

# ---------- Share Document (dept → multi-select users) ----------
elif choice == "🔗 Share Document":
    st.header("🔗 Share Document")
    db = load_docs()
    if db.empty:
        st.info("No documents.")
    else:
        options = db["Title"].tolist() if is_admin() else db[db["Uploader"]==st.session_state["username"]]["Title"].tolist()
        if not options:
            st.info("No documents you can share.")
        else:
            sel = st.selectbox("Document", options)
            depts = load_csv(DEPT_FILE)
            dept_opts = depts["Department"].tolist() if not depts.empty else []
            dsel = st.selectbox("Select Department", ["(All)"] + dept_opts)
            users_df = load_csv(USER_FILE)
            if dsel != "(All)":
                users_df = users_df[users_df["Department"]==dsel]
            usernames = users_df["Username"].tolist()
            targets = st.multiselect("Select recipients", usernames)
            if st.button("Share to Selected"):
                if not targets:
                    st.error("Select at least one recipient.")
                else:
                    idx = db.index[db["Title"]==sel][0]
                    cur = str(db.at[idx,"Shared With"]) if pd.notna(db.at[idx,"Shared With"]) else ""
                    s = set([u.strip() for u in cur.split(",") if u.strip()])
                    for t in targets:
                        s.add(t)
                    db.at[idx,"Shared With"] = ",".join(sorted(s))
                    save_docs(db)
                    audit(st.session_state["name"], st.session_state["role"], "Share", target=sel, details=f"To {', '.join(targets)}")
                    st.success(f"Shared '{sel}' with {', '.join(targets)}")

# ---------- Search Documents ----------
elif choice == "🔎 Search Documents":
    st.header("🔎 Search Documents")
    q = st.text_input("Keyword or category", placeholder="enter keyword...")
    if st.button("Search"):
        db = load_docs()
        if db.empty:
            st.info("No docs.")
        else:
            ql = q.lower().strip()
            if ql=="":
                st.warning("Enter a keyword.")
            else:
                def match(r):
                    return any(ql in str(r.get(c,"")).lower() for c in ["Title","Category","Department","Uploader","Shared With"])
                res = db[db.apply(match, axis=1)]
                if res.empty:
                    st.warning("No matches.")
                else:
                    st.dataframe(res.sort_values("Upload Date", ascending=False), use_container_width=True)

# ---------- User Files (HR/Admin) with profile & profile picture thumbnails ----------
elif choice == "🗂️ User Files" and (is_admin() or is_hr()):
    st.header("🗂️ User Files & Profiles")
    users = load_csv(USER_FILE)
    if users.empty:
        st.info("No users.")
    else:
        username = st.selectbox("Select User", users["Username"].tolist())
        profile = read_profile(username)
        st.subheader("Profile")
        with st.form(f"profile_{username}"):
            full_name = st.text_input("Full name", value=profile.get("full_name", users[users["Username"]==username]["Name"].iloc[0]))
            role = st.text_input("Role", value=profile.get("role", users[users["Username"]==username]["Role"].iloc[0]))
            dept = st.text_input("Department", value=profile.get("department", users[users["Username"]==username]["Department"].iloc[0]))
            doj = st.date_input("Employment Date", value=pd.to_datetime(profile.get("employment_date", datetime.today().date())))
            notes = st.text_area("Notes", value=profile.get("notes",""))
            pic = st.file_uploader("Profile picture (png/jpg)", type=["png","jpg","jpeg"], key=f"pic_{username}")
            save_profile = st.form_submit_button("Save Profile")
            if save_profile:
                payload = {
                    "full_name": sanitize_csv_value(full_name),
                    "role": sanitize_csv_value(role),
                    "department": sanitize_csv_value(dept),
                    "employment_date": str(doj),
                    "notes": notes
                }
                # save profile json
                write_profile(username, payload)
                # save pic if provided
                if pic:
                    pf = user_folder(username) / f"profile_{safe_filename(pic.name)}"
                    with open(pf, "wb") as f:
                        f.write(pic.read())
                    # record path in profile
                    payload["profile_pic"] = str(pf)
                    write_profile(username, payload)
                audit(st.session_state["name"], st.session_state["role"], "Save Profile", target=username)
                st.success("Profile saved.")
                st.rerun()

        st.subheader("User Folder")
        uf = user_folder(username)
        uploaded = st.file_uploader("Upload to user folder", key=f"userup_{username}", type=["pdf","docx","xlsx","png","jpg","jpeg"])
        if st.button("Upload to folder"):
            if uploaded is None:
                st.error("Choose a file.")
            else:
                dest = uf / safe_filename(uploaded.name)
                with open(dest, "wb") as f:
                    f.write(uploaded.read())
                audit(st.session_state["name"], st.session_state["role"], "Upload to User Folder", target=username, details=dest.name)
                st.success("Uploaded to user folder.")
                st.rerun()

        st.write("### Files in user folder")
        files = sorted([p for p in uf.glob("*") if p.is_file()])
        if not files:
            st.info("No files.")
        else:
            for p in files:
                c1, c2 = st.columns([4,1])
                with c1:
                    st.write(p.name)
                    # thumbnail for images
                    if p.suffix.lower() in [".png",".jpg",".jpeg"]:
                        try:
                            st.image(str(p), width=150)
                        except Exception:
                            pass
                with c2:
                    try:
                        st.download_button("Download", open(p, "rb"), file_name=p.name, key=f"dl_{username}_{p.name}")
                    except FileNotFoundError:
                        st.error("File missing")

        # show profile pic thumbnail if exists
        prof = read_profile(username)
        pic_path = prof.get("profile_pic","")
        if pic_path:
            pp = Path(pic_path)
            if pp.exists():
                st.write("### Profile picture")
                st.image(str(pp), width=160)

# ---------- Department Management ----------
elif choice == "🏢 Department Management" and is_admin():
    st.header("🏢 Departments")
    depts = load_csv(DEPT_FILE)
    st.dataframe(depts, use_container_width=True)
    new = st.text_input("New department name", placeholder="e.g. Radiology")
    if st.button("Add Department"):
        if new.strip()=="":
            st.error("Enter a name.")
        elif new in depts["Department"].values:
            st.warning("Already exists.")
        else:
            depts = pd.concat([depts, pd.DataFrame([{"Department":new}])], ignore_index=True)
            save_csv(depts, DEPT_FILE)
            audit(st.session_state["name"], st.session_state["role"], "Add Department", details=new)
            st.success("Added.")
            st.rerun()
    if not depts.empty:
        pick = st.selectbox("Select to rename/delete", depts["Department"].tolist())
        rename = st.text_input("Rename to", key="rename_dept")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Rename Department"):
                if rename.strip()=="":
                    st.error("Enter a name.")
                else:
                    depts.loc[depts["Department"]==pick,"Department"] = rename
                    save_csv(depts, DEPT_FILE)
                    audit(st.session_state["name"], st.session_state["role"], "Rename Department", target=pick, details=rename)
                    st.success("Renamed.")
                    st.rerun()
        with c2:
            if st.button("Delete Department"):
                depts = depts[depts["Department"]!=pick]
                save_csv(depts, DEPT_FILE)
                audit(st.session_state["name"], st.session_state["role"], "Delete Department", details=pick)
                st.warning("Deleted.")
                st.rerun()

# ---------- Role Management ----------
elif choice == "👔 Role Management" and is_admin():
    st.header("👔 Roles")
    roles = load_csv(ROLE_FILE)
    st.dataframe(roles, use_container_width=True)
    newrole = st.text_input("New role name")
    if st.button("Add Role"):
        if newrole.strip()=="":
            st.error("Enter name.")
        elif newrole in roles["Role"].values:
            st.warning("Exists.")
        else:
            roles = pd.concat([roles, pd.DataFrame([{"Role":newrole}])], ignore_index=True)
            save_csv(roles, ROLE_FILE)
            audit(st.session_state["name"], st.session_state["role"], "Add Role", details=newrole)
            st.success("Added.")
            st.rerun()
    if not roles.empty:
        pick = st.selectbox("Select role to rename/delete", roles["Role"].tolist())
        rename_role = st.text_input("Rename to", key="rename_role")
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Rename Role"):
                if rename_role.strip()=="":
                    st.error("Enter name.")
                else:
                    roles.loc[roles["Role"]==pick,"Role"] = rename_role
                    save_csv(roles, ROLE_FILE)
                    audit(st.session_state["name"], st.session_state["role"], "Rename Role", target=pick, details=rename_role)
                    st.success("Renamed.")
                    st.rerun()
        with c2:
            if st.button("Delete Role"):
                if pick=="Admin":
                    st.error("Cannot delete Admin role.")
                else:
                    roles = roles[roles["Role"]!=pick]
                    save_csv(roles, ROLE_FILE)
                    audit(st.session_state["name"], st.session_state["role"], "Delete Role", details=pick)
                    st.warning("Deleted.")
                    st.rerun()

# ---------- User Management ----------
elif choice == "👥 User Management" and is_admin():
    st.header("👥 User Management")
    users = load_csv(USER_FILE)
    st.dataframe(users[["Username","Name","Role","Department"]], use_container_width=True)
    st.subheader("Add new user")
    new_un = st.text_input("Username", key="new_un")
    new_name = st.text_input("Full name", key="new_name")
    new_pw = st.text_input("Password", key="new_pw", type="password")
    roles = load_csv(ROLE_FILE)["Role"].tolist()
    depts = load_csv(DEPT_FILE)["Department"].tolist()
    new_role = st.selectbox("Role", roles if roles else ["HR"])
    new_dept = st.selectbox("Department", depts if depts else ["Administration"])
    if st.button("Add User"):
        if not (new_un and new_name and new_pw):
            st.error("Fill all fields.")
        elif not re.match(r"^[A-Za-z0-9._-]+$", new_un):
            st.error("Username can contain letters, numbers, dot, underscore, hyphen.")
        elif new_un in users["Username"].values:
            st.error("Username exists.")
        else:
            users = pd.concat([users, pd.DataFrame([{
                "Username": sanitize_csv_value(new_un),
                "Password": hash_pw(new_pw),
                "Name": sanitize_csv_value(new_name),
                "Role": sanitize_csv_value(new_role),
                "Department": sanitize_csv_value(new_dept)
            }])], ignore_index=True)
            save_csv(users, USER_FILE)
            user_folder(new_un)
            audit(st.session_state["name"], st.session_state["role"], "Add User", target=new_un, details=f"{new_name}|{new_role}|{new_dept}")
            st.success("User added.")
            st.rerun()
    if not users.empty:
        del_user = st.selectbox("Select user to delete", users["Username"].tolist())
        if st.button("Delete User"):
            if del_user=="admin":
                st.error("Cannot delete main admin.")
            else:
                users = users[users["Username"]!=del_user]
                save_csv(users, USER_FILE)
                audit(st.session_state["name"], st.session_state["role"], "Delete User", target=del_user)
                st.warning("Deleted.")
                st.rerun()

# ---------- Audit Log ----------
elif choice == "🧾 Audit Log" and is_admin():
    st.header("🧾 Audit Log")
    logs = load_csv(AUDIT_FILE)
    if logs.empty:
        st.info("No logs yet.")
    else:
        st.dataframe(logs.sort_values("Timestamp", ascending=False), use_container_width=True)

# ---------- About ----------
elif choice == "ℹ️ About":
    st.header("ℹ️ About")
    st.markdown("""
    **KOFIKROM SDA Hospital S-Documentary**
    - Paperless document management
    - Roles, departments, users, sharing (by department → select users), per-user folders and profile pictures
    - Audit logging and secure password hashing
    - Built with Streamlit
    """)

# ---------- END ----------
