from __future__ import annotations

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

from analyzer_v2 import analyze_all

app = FastAPI(title="Threat Triage Chatbot API (v2)", version="2.0.0")

# 배포 후에는 allow_origins 에 프론트 도메인을 넣는 게 더 안전함
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 예: ["https://phishing-frontend.vercel.app"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_BYTES = 10 * 1024 * 1024  # 10MB


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/analyze")
async def analyze(
    input_type: str = Form("auto"),
    url: str = Form(""),
    email_raw: str = Form(""),
    html: str = Form(""),
    text: str = Form(""),
    upload: UploadFile | None = File(None),
):
    """
    통합 분석 엔드포인트.
    - URL
    - 이메일 원문
    - HTML 소스
    - 메시지 텍스트
    - 파일(HTML/EML/TXT/이미지/실행파일 등)
    """

    file_bytes = None
    filename = ""

    if upload is not None:
        file_bytes = await upload.read()
        if len(file_bytes) > MAX_FILE_BYTES:
            return {"error": "파일이 너무 큽니다(최대 10MB)."}

        filename = upload.filename or "upload"

    # 엔진 v2에 모든 정보를 전달
    report = analyze_all(
        url=url,
        html=html,
        email=email_raw,
        text=text,
        file_bytes=file_bytes,
        filename=filename,
    )

    return report

