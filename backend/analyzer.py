from __future__ import annotations

import re
import hashlib
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

import idna
import tldextract
from bs4 import BeautifulSoup

PHISHING_SUBTYPES = [
    ("mfa_token_theft", ["otp", "인증코드", "보안코드", "2단계", "2fa", "mfa", "auth code"]),
    ("credential_harvesting", ["로그인", "login", "비밀번호", "password", "계정", "아이디", "id"]),
    ("payment_info_theft", ["결제", "payment", "카드", "card", "청구", "구독", "billing"]),
    ("financial_info_theft", ["계좌", "은행", "bank", "이체", "송금", "통장"]),
    ("refund_scam", ["환불", "refund", "반품", "정산", "취소"]),
    ("social_engineering", ["긴급", "지금", "즉시", "비밀", "상사", "대표", "CEO", "확인 바랍니다"])
]

RANSOM_KEYWORDS = [
    "files are encrypted", "decrypt", "decryption", "ransom",
    "비트코인", "bitcoin", "복호화", "암호화", "몸값", "지불", "48시간", "72시간",
    "키를 구매", "your data has been locked"
]

C_EVIDENCE_LABELS = {
    "url_tamper": "URL 변조, 도메인 스푸핑, 문자 치환(paypa1 등)",
    "no_https": "HTTPS 미사용",
    "ui_changed": "페이지 UI/문구가 공식 서비스 대비 변경됨(의심 정황)",
    "asks_credentials": "개인정보·로그인 정보·결제 정보 입력 요구",
    "exec_attachment": "첨부 실행파일 유도(.exe .scr .js .vbs 등)",
    "asks_payment_otp": "송금·암호화폐 지불·OTP 제출 요구",
    "zip_password": "다운로드 후 암호 해제 요구(zip+비밀번호 패턴 등)",
    "email_auth_fail": "이메일 헤더 위조(SPF/DKIM/DMARC 불일치)"
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def _has_lookalike_chars(domain: str) -> bool:
    return bool(re.search(r"(paypa1|g00gle|micr0soft|faceb00k|app1e)", domain, re.IGNORECASE))


def _has_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def _subdomain_depth(host: str) -> int:
    ext = tldextract.extract(host)
    sub = ext.subdomain
    if not sub:
        return 0
    return len([p for p in sub.split(".") if p])


def analyze_url(url: str) -> Tuple[int, List[str]]:
    score = 0
    evid = []
    try:
        p = urlparse(url.strip())
        scheme = (p.scheme or "").lower()
        host = (p.hostname or "").lower()
        path = p.path or ""
        full = url.strip()

        if "@" in full:
            score += 15
            evid.append("url_tamper")

        if scheme != "https":
            score += 10
            evid.append("no_https")

        if _looks_like_ip(host):
            score += 20
            evid.append("url_tamper")

        if _has_punycode(host):
            score += 20
            evid.append("url_tamper")

        try:
            idna.decode(host.encode("utf-8"))
        except Exception:
            score += 5
            evid.append("url_tamper")

        if _has_lookalike_chars(host):
            score += 20
            evid.append("url_tamper")

        if _subdomain_depth(host) >= 3:
            score += 10
            evid.append("url_tamper")

        if len(full) >= 120:
            score += 10
            evid.append("url_tamper")

        if re.search(r"(verify|update|secure|confirm|login|signin|payment|invoice)", path, re.IGNORECASE):
            score += 10
            evid.append("asks_credentials")

    except Exception:
        score += 15
        evid.append("url_tamper")

    return score, sorted(set(evid))


def analyze_html(html: str) -> Tuple[int, List[str], Dict[str, bool]]:
    score = 0
    evid = []
    flags = {"has_password_form": False, "has_otp": False, "has_download": False}

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    lower = text.lower()

    if any(k in lower for k in ["login", "signin", "password", "otp", "verify", "인증", "비밀번호", "로그인", "결제", "카드"]):
        score += 10
        evid.append("ui_changed")

    pwd_inputs = soup.select("input[type='password']")
    if pwd_inputs:
        flags["has_password_form"] = True
        score += 25
        evid.append("asks_credentials")

    if re.search(r"\b(otp|2fa|mfa|auth code)\b|인증코드|보안코드|2단계", text, re.IGNORECASE):
        flags["has_otp"] = True
        score += 20
        evid.append("asks_payment_otp")

    if re.search(r"download|다운로드|install|설치|exe|vbs|js|zip|압축", lower):
        flags["has_download"] = True
        score += 15
        evid.append("exec_attachment")

    return score, sorted(set(evid)), flags


def analyze_email_raw(raw: str) -> Tuple[int, List[str]]:
    score = 0
    evid = []
    lower = raw.lower()

    if "authentication-results" in lower:
        if re.search(r"\bspf=(fail|softfail|none)\b", lower):
            score += 20
            evid.append("email_auth_fail")
        if re.search(r"\bdkim=(fail|none)\b", lower):
            score += 20
            evid.append("email_auth_fail")
        if re.search(r"\bdmarc=(fail|none)\b", lower):
            score += 20
            evid.append("email_auth_fail")

    if re.search(r"로그인|비밀번호|계정|otp|인증코드|결제|카드|송금|bitcoin|환불|긴급", raw, re.IGNORECASE):
        score += 10
        evid.append("asks_credentials")

    if re.search(r"\.exe|\.scr|\.js|\.vbs|\.bat|\.ps1|압축|zip|암호", lower):
        score += 15
        evid.append("exec_attachment")

    if re.search(r"(zip|압축).*(비밀번호|암호|password|pw)", lower):
        score += 15
        evid.append("zip_password")

    return score, sorted(set(evid))


def analyze_text(msg: str) -> Tuple[int, List[str]]:
    score = 0
    evid = []
    lower = msg.lower()

    # 1. 실행 파일 요청 — 멀웨어 유도형 (가장 위험)
    exec_patterns = [
        "invoice.js",
        "파일을 실행", 
        "첨부파일 실행", 
        "run the file",
        "open the file",
        "js 파일", 
        "exe 파일"
    ]
    if any(p in lower for p in exec_patterns):
        score += 40
        evid.append("exec_attachment")

    # 2. 일반 실행파일 확장자
    if re.search(r"\.(exe|scr|js|vbs|bat|ps1)\b", lower):
        score += 25
        evid.append("exec_attachment")

    # 3. OTP·보안코드 요구 — MFA 탈취 패턴
    if re.search(r"otp|인증코드|보안코드|2단계|mfa|auth code", msg, re.IGNORECASE):
        score += 25
        evid.append("asks_payment_otp")

    # 4. 로그인 정보 요구 — 크리덴셜 하베스팅
    if re.search(r"로그인|비밀번호|계정|아이디|신분증|password|login", msg, re.IGNORECASE):
        score += 20
        evid.append("asks_credentials")

    # 5. 송금·결제 유도
    if re.search(r"송금|이체|결제|카드|청구|결제 요청|지불", msg, re.IGNORECASE):
        score += 20
        evid.append("asks_payment_otp")

    # 6. zip + 비밀번호 조합 — 악성 압축파일
    if re.search(r"(zip|압축).*(비밀번호|암호|password|pw)", lower):
        score += 15
        evid.append("zip_password")

    # 7. 강한 사회공학 패턴
    if re.search(r"긴급|지금|즉시|오늘까지|계정잠김|정지|법적조치|중요", msg, re.IGNORECASE):
        score += 10
        evid.append("ui_changed")

    return score, sorted(set(evid))



def decide_family_and_subtype(all_text: str, evid: List[str]) -> Tuple[Optional[str], Optional[str]]:
    t = all_text.lower()

    if any(k in t for k in [kw.lower() for kw in RANSOM_KEYWORDS]):
        return "랜섬웨어", None

    if "exec_attachment" in evid or re.search(r"\.(exe|scr|vbs|js|bat|ps1|lnk|iso|msi)\b", t):
        return "멀웨어", None

    for subtype, keys in PHISHING_SUBTYPES:
        if any(k.lower() in t for k in keys):
            label_map = {
                "credential_harvesting": "크리덴셜 하베스팅(로그인 정보 탈취)",
                "financial_info_theft": "금융정보 탈취",
                "payment_info_theft": "결제정보 갈취",
                "social_engineering": "사회공학형",
                "refund_scam": "환불 유도형",
                "mfa_token_theft": "MFA 토큰 탈취"
            }
            return "피싱", label_map.get(subtype, "사회공학형")

    return "피싱", "사회공학형"


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def verdict_from_score(score: int) -> str:
    if score <= 30:
        return "정상"
    if score <= 60:
        return "의심"
    return "악성"


def response_actions(family: str) -> List[str]:
    if family == "피싱":
        return ["신고", "계정 비밀번호 변경", "MFA 재등록", "URL 차단"]
    if family == "멀웨어":
        return ["파일 격리", "시스템 검사", "백신 업데이트"]
    if family == "랜섬웨어":
        return ["네트워크 분리", "백업 복원", "금전 지불 금지"]
    return []


def build_report(score: int, evid_keys: List[str], family: Optional[str], phish_sub: Optional[str]) -> Dict:
    final = verdict_from_score(score)
    out = {
        "final_verdict": final,
        "risk_score": score
    }

    if final in ("의심", "악성"):
        evid_keys = sorted(set(evid_keys))
        out.update({
            "family": family,
            "phishing_subtype": phish_sub if family == "피싱" else None,
            "evidence": [C_EVIDENCE_LABELS[k] for k in evid_keys if k in C_EVIDENCE_LABELS],
            "recommended_actions": response_actions(family or "")
        })

    return out

def refine_score(score: int, evid: List[str]) -> int:
    """
    v2: 규칙 조합 기반 후처리 점수 조정.
    - 강한 신호 여러 개가 동시에 있을 때 추가 가중치 부여.
    """
    e = set(evid)
    extra = 0

    # 실행파일 + 자격증명/OTP 요구 → 매우 위험
    if "exec_attachment" in e and ("asks_credentials" in e or "asks_payment_otp" in e):
        extra += 20

    # URL 변조 + 자격증명 요구 → 피싱 가능성 상승
    if "url_tamper" in e and "asks_credentials" in e:
        extra += 10

    # zip 암호 + 실행파일 → 랜섬웨어·멀웨어 의심
    if "zip_password" in e and "exec_attachment" in e:
        extra += 10

    # UI 변경 + OTP/결제 요구 → 사회공학형 피싱 강화
    if "ui_changed" in e and "asks_payment_otp" in e:
        extra += 5

    return score + extra
