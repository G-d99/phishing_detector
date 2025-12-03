from __future__ import annotations

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

from analyzer import (
    analyze_url,
    analyze_html,
    analyze_email_raw,
    analyze_text,
    sha256_bytes,
    clamp,
    decide_family_and_subtype,
    build_report,
)

app = FastAPI(title="Threat Triage Chatbot API", version="1.0.0")

# 배포 후 allow_origins는 Vercel 도메인으로 제한 권장
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    print("TEXT_RECEIVED:", repr(text))


    score = 0
    evid = []

    combined_text = " ".join([email_raw, html, text, url]).strip()

    # URL 분석
    if url.strip():
        s, e = analyze_url(url)
        score += s
        evid += e

    # HTML 분석
    if html.strip():
        s, e, _flags = analyze_html(html)
        score += s
        evid += e

    # 이메일 분석
    if email_raw.strip():
        s, e = analyze_email_raw(email_raw)
        score += s
        evid += e

    # 메시지 텍스트 분석 (빈 줄/공백만 있을 때 무시)
    safe_text = text if text is not None else ""
    if safe_text.replace("\r", "").replace("\n", "").strip() != "":
        s, e = analyze_text(safe_text)
        score += s
        evid += e

    file_info = None

    # 파일 분석
    if upload is not None:
        data = await upload.read()
        if len(data) > MAX_FILE_BYTES:
            return {"error": "파일이 너무 큽니다(최대 10MB)."}

        filename = (upload.filename or "upload").lower()
        digest = sha256_bytes(data)

        # 위험 확장자
        if filename.endswith(
            (
                ".exe",
                ".scr",
                ".js",
                ".vbs",
                ".bat",
                ".ps1",
                ".lnk",
                ".iso",
                ".msi",
            )
        ):
            score += 30
            evid.append("exec_attachment")

        # HTML 파일 내용 분석
        if filename.endswith((".html", ".htm")):
            try:
                html_text = data.decode("utf-8", errors="ignore")
                s, e, _flags = analyze_html(html_text)
                score += s
                evid += e
                combined_text += " " + html_text
            except Exception:
                pass

        # 텍스트 기반 파일 (.eml, .txt)
        if filename.endswith((".eml", ".txt")):
            try:
                raw_text = data.decode("utf-8", errors="ignore")
                s1, e1 = analyze_email_raw(raw_text)
                s2, e2 = analyze_text(raw_text)
                score += s1 + s2
                evid += e1 + e2
                combined_text += " " + raw_text
            except Exception:
                pass

        file_info = {
            "filename": upload.filename,
            "sha256": digest,
            "bytes": len(data),
        }

    # v2 후처리(시그널 조합 강화) + 점수 범위 조정
    from analyzer import refine_score  # 파일 상단에 이미 import 했다면 이 줄은 생략

    score = refine_score(score, evid)
    score = clamp(score, 0, 100)

    # 위협 패밀리 분류
    family, phish_sub = decide_family_and_subtype(combined_text, evid)

    # 최종 리포트 생성
    report = build_report(score, evid, family, phish_sub)

    # 파일 정보 추가
    if file_info:
        report["file"] = file_info

    return report
