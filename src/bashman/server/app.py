# src/bashman/server/app.py

import os
import re
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse

app = FastAPI()

QUARANTINE_DIR = os.path.join(os.getcwd(), "quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

# Allow absolute paths ending in sh|bash|zsh|csh|ksh|dash|fish, 
# plus the /usr/bin/env trick
SHELL_REGEX = re.compile(
    r"^#!\s*(?:/[^ \t]+/)*(?:env\s+)?(sh|bash|zsh|csh|ksh|dash|fish)\b"
)

@app.get("/scripts")
async def list_scripts():
    valid = []
    for fname in os.listdir(QUARANTINE_DIR):
        path = os.path.join(QUARANTINE_DIR, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "rb") as f:
            first = f.readline().decode(errors="ignore")
        if SHELL_REGEX.match(first):
            valid.append(fname)
    return JSONResponse(content=valid)

@app.post("/scripts")
async def upload_script(file: UploadFile = File(...)):
    snippet = await file.read(1024)
    first_line = snippet.splitlines()[0].decode(errors="ignore") if snippet else ""
    if not SHELL_REGEX.match(first_line):
        raise HTTPException(
            400,
            detail=(
                "Script must begin with a recognized shell shebang, "
                "e.g. #!/bin/bash or #!/usr/bin/env bash"
            )
        )

    await file.seek(0)
    dest = os.path.join(QUARANTINE_DIR, file.filename)
    if os.path.exists(dest):
        raise HTTPException(409, f"{file.filename} already exists")
    contents = await file.read()
    with open(dest, "wb") as out:
        out.write(contents)

    return {"status": "quarantined", "filename": file.filename}
