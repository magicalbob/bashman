import os
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

# ←— ensure this is at top level so tests can monkey-patch it
QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

@app.get("/scripts")
async def list_scripts():
    files = [f for f in os.listdir(QUARANTINE_DIR) if f.endswith(".sh")]
    return JSONResponse(content=files)

@app.post("/scripts")
async def upload_script(file: UploadFile = File(...)):
    if not file.filename.endswith(".sh"):
        raise HTTPException(400, "Only .sh files are allowed")
    dest = os.path.join(QUARANTINE_DIR, file.filename)
    if os.path.exists(dest):
        raise HTTPException(409, f"{file.filename} already exists")
    contents = await file.read()
    with open(dest, "wb") as f:
        f.write(contents)
    return {"status": "quarantined", "filename": file.filename}

