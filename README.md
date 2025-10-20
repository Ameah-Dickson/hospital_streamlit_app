Hospital Admin System — Streamlit MVP
-------------------------------------
Run this demo locally:

1. Create a virtual env and install requirements:
   python -m venv venv
   source venv/bin/activate   (or venv\Scripts\activate on Windows)
   pip install -r requirements.txt

2. Run the app:
   streamlit run app.py

Demo users:
  - admin@hospital.test / admin123  (Administrator)
  - hr@hospital.test / hrpass       (HR Manager)
  - nurse@hospital.test / nursepass (Nurse Manager)
  - head@hospital.test / headpass   (Head of Facility)

Notes:
- This is a demo scaffold using CSV files for storage (data/ folder).
- Not production ready. Replace auth and CSV persistence with a real DB for production.
