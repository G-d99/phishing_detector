from __future__ import annotations

import re
import hashlib
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

import idna
import tldextract
from bs4 import BeautifulSoup

# 이미지/OCR 관련 (옵션)
from io import BytesIO
try:
    from PIL import Image
except ImportError:  # Pillow가 없으면 이미지 분석은 비활성화
    Image = None  # type: ignore

try:
    import pytesseract  # 시스템에 tesseract가 없으면 런타임에서 예외 날 수 있음
except ImportError:
    pytesseract = None  # type: ignore

# -----------------------------
# 피싱 유형 / 랜섬 / C-Evidence 정의
# -----------------------------

PHISHING_SUBTYPES = [
    ("mfa_token_theft", ["otp", "인증코드", "보안코드", "2단계", "2fa", "mfa", "auth code"]),
    ("credential_harvesting", ["로그인", "login", "비밀번호", "password", "계정", "아이디", "id"]),
    ("payment_info_theft", ["결제", "payment", "카드", "card", "청구", "구독", "billing"]),
    ("financial_info_theft", ["계좌", "은행", "bank", "이체", "송금", "통장"]),
    ("refund_scam", ["환불", "refund", "반품", "정산", "취소"]),
    ("social_engineering", ["긴급", "지금", "즉시", "비밀", "상사", "대표", "ceo", "확인 바랍니다"]),
]

RANSOM_KEYWORDS = [
    "files are encrypted",
    "decrypt",
    "decryption",
    "ransom",
    "비트코인",
    "bitcoin",
    "복호화",
    "암호화",
    "몸값",
    "지불",
    "48시간",
    "72시간",
    "키를 구매",
    "your data has been locked",
]

C_EVIDENCE_LABELS = {
    "url_tamper": "URL 변조, 도메인 스푸핑, 문자 치환(paypa1 등)",
    "no_https": "HTTPS 미사용",
    "ui_changed": "페이지 UI/문구가 공식 서비스 대비 변경됨(의심 정황)",
    "asks_credentials": "개인정보·로그인 정보·결제 정보 입력 요구",
    "exec_attachment": "첨부 실행파일 유도(.exe .scr .js .vbs 등)",
    "asks_payment_otp": "송금·암호화폐 지불·OTP 제출 요구",
    "zip_password": "다운로드 후 암호 해제 요구(zip+비밀번호 패턴 등)",
    "email_auth_fail": "이메일 헤더 위조(SPF/DKIM/DMARC 불일치)",
}

DANGEROUS_EXTS = (
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


# -----------------------------
# 공통 유틸
# -----------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def clamp(n: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, n))


def _looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def _has_lookalike_chars(domain: str) -> bool:
    # 대표적인 브랜드 도메인 치환
    return bool(
        re.search(
            r"(paypa1|g00gle|micr0soft|faceb00k|app1e|naver-secure|kaka0|k0rea|k0okmin)",
            domain,
            re.IGNORECASE,
        )
    )


def _has_punycode(host: str) -> bool:
    return "xn--" in host.lower()


def _subdomain_depth(host: str) -> int:
    ext = tldextract.extract(host)
    sub = ext.subdomain
    if not sub:
        return 0
    return len([p for p in sub.split(".") if p])


# -----------------------------
# URL 분석
# -----------------------------


def analyze_url(url: str) -> Tuple[int, List[str]]:
    score = 0
    evid: List[str] = []

    try:
        full = url.strip()
        p = urlparse(full)
        scheme = (p.scheme or "").lower()
        host = (p.hostname or "").lower()
        path = p.path or ""
        query = p.query or ""

        # @ 포함 → URL 스푸핑 패턴
        if "@" in full:
            score += 15
            evid.append("url_tamper")

        # HTTPS 미사용
        if scheme != "https":
            score += 10
            evid.append("no_https")

        # IP 주소 직접 사용
        if _looks_like_ip(host):
            score += 20
            evid.append("url_tamper")

        # punycode 사용
        if _has_punycode(host):
            score += 20
            evid.append("url_tamper")

        # IDNA 디코딩 실패
        try:
            idna.decode(host.encode("utf-8"))
        except Exception:
            score += 5
            evid.append("url_tamper")

        # 유명 브랜드 도메인 치환
        if _has_lookalike_chars(host):
            score += 25
            evid.append("url_tamper")

        # 서브도메인 과도 사용
        if _subdomain_depth(host) >= 3:
            score += 10
            evid.append("url_tamper")

        # URL 길이가 지나치게 긴 경우
        if len(full) >= 150:
            score += 10
            evid.append("url_tamper")

        # path / query 에서 피싱 관련 키워드
        if re.search(
            r"(verify|update|secure|confirm|login|signin|payment|invoice|auth|session)",
            path + "?" + query,
            re.IGNORECASE,
        ):
            score += 10
            evid.append("asks_credentials")

        # 쿼리 파라미터에 token, session 등 포함
        if re.search(r"(token|sessionid|auth|otp|code)=", query, re.IGNORECASE):
            score += 10
            evid.append("asks_payment_otp")

    except Exception:
        # URL 파싱 자체가 실패하면 일단 의심
        score += 15
        evid.append("url_tamper")

    return score, sorted(set(evid))


# -----------------------------
# HTML 분석
# -----------------------------


def analyze_html(html: str) -> Tuple[int, List[str], Dict[str, bool]]:
    score = 0
    evid: List[str] = []
    flags = {"has_password_form": False, "has_otp": False, "has_download": False}

    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    lower = text.lower()

    # 로그인 / 인증 / 결제 관련 문구
    if any(
        k in lower
        for k in [
            "login",
            "signin",
            "password",
            "otp",
            "verify",
            "인증",
            "비밀번호",
            "로그인",
            "결제",
            "카드",
            "본인인증",
            "계정 잠김",
        ]
    ):
        score += 10
        evid.append("ui_changed")

    # form + password input
    pwd_inputs = soup.select("input[type='password']")
    if pwd_inputs:
        flags["has_password_form"] = True
        score += 25
        evid.append("asks_credentials")

    # id/pw, otp, 2FA 관련 input name
    login_like_inputs = soup.find_all(
        "input",
        attrs={"name": re.compile(r"(id|user|login|account|email|otp|code)", re.IGNORECASE)},
    )
    if login_like_inputs:
        score += 10
        evid.append("asks_credentials")

    # OTP/2FA 문구
    if re.search(
        r"\b(otp|2fa|mfa|auth code|one-time password)\b|인증코드|보안코드|2단계",
        text,
        re.IGNORECASE,
    ):
        flags["has_otp"] = True
        score += 20
        evid.append("asks_payment_otp")

    # 다운로드 / 실행 / 설치 유도
    if re.search(
        r"download|다운로드|install|설치|\.exe|\.vbs|\.js|\.scr|\.bat|\.ps1|압축|zip",
        lower,
    ):
        flags["has_download"] = True
        score += 15
        evid.append("exec_attachment")

    return score, sorted(set(evid)), flags


# -----------------------------
# 이메일 원문 분석
# -----------------------------


def analyze_email_raw(raw: str) -> Tuple[int, List[str]]:
    score = 0
    evid: List[str] = []
    lower = raw.lower()

    # SPF/DKIM/DMARC 실패
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

    # 계정/비밀번호/OTP/결제/송금 관련 문구
    if re.search(
        r"로그인|비밀번호|계정|otp|인증코드|결제|카드|송금|bitcoin|환불|긴급|정지|본인인증",
        raw,
        re.IGNORECASE,
    ):
        score += 10
        evid.append("asks_credentials")

    # 실행 파일 / 압축 / 비밀번호 보호
    if re.search(r"\.exe|\.scr|\.js|\.vbs|\.bat|\.ps1|압축|zip|암호", lower):
        score += 15
        evid.append("exec_attachment")

    if re.search(r"(zip|압축).*(비밀번호|암호|password|pw)", lower):
        score += 15
        evid.append("zip_password")

    return score, sorted(set(evid))


# -----------------------------
# 일반 텍스트(메시지/카톡 등) 분석
# -----------------------------


def analyze_text(msg: str) -> Tuple[int, List[str]]:
    score = 0
    evid: List[str] = []
    lower = msg.lower()

    # OTP / 인증코드 / MFA
    if re.search(r"otp|인증코드|보안코드|2단계|mfa|one[- ]time password", msg, re.IGNORECASE):
        score += 25
        evid.append("asks_payment_otp")

    # 계정/비밀번호/개인정보/카드/결제
    if re.search(
        r"로그인|비밀번호|계정|아이디|카드|결제|개인정보|신분증|계정잠김|본인인증",
        msg,
        re.IGNORECASE,
    ):
        score += 20
        evid.append("asks_credentials")

    # 송금/이체/암호화폐/결제 요청
    if re.search(
        r"송금|이체|bitcoin|비트코인|암호화폐|지불|결제 요청|입금",
        msg,
        re.IGNORECASE,
    ):
        score += 25
        evid.append("asks_payment_otp")

    # 실행파일/다운로드/설치
    if re.search(r"\.exe|\.scr|\.js|\.vbs|\.bat|\.ps1|다운로드|설치", lower):
        score += 25
        evid.append("exec_attachment")

    # 압축 + 비밀번호
    if re.search(r"(zip|압축).*(비밀번호|암호|password|pw)", lower):
        score += 15
        evid.append("zip_password")

    # 긴급/계정정지/법적조치
    if re.search(r"긴급|지금|즉시|오늘까지|계정잠김|정지|법적조치", msg, re.IGNORECASE):
        score += 10
        evid.append("ui_changed")

    return score, sorted(set(evid))


# -----------------------------
# OCR 기반 이미지 텍스트 추출
# -----------------------------


def extract_text_from_image(image_bytes: bytes) -> str:
    """
    이미지에서 텍스트를 추출한다.
    - Pillow / pytesseract 가 모두 없는 환경이면 빈 문자열 반환
    - Render 등의 서버에서 Tesseract가 없다면 예외 발생 → 안전하게 무시
    """
    if Image is None or pytesseract is None:
        return ""

    try:
        img = Image.open(BytesIO(image_bytes))
        # 한글/영문 혼합 환경, 시스템에 한글 traineddata 설치 여부에 따라 품질 달라짐
        text = pytesseract.image_to_string(img, lang="kor+eng")
        return text.strip()
    except Exception:
        # OCR 실패 시에도 서버 전체는 죽지 않도록
        return ""


# -----------------------------
# 위협 패밀리 / 서브타입 결정
# -----------------------------


def decide_family_and_subtype(all_text: str, evid: List[str]) -> Tuple[Optional[str], Optional[str]]:
    t = all_text.lower()

    # 랜섬웨어 문구
    if any(k.lower() in t for k in [kw.lower() for kw in RANSOM_KEYWORDS]):
        return "랜섬웨어", None

    # 실행파일 / 스크립트 첨부 → 멀웨어 우선
    if "exec_attachment" in evid or re.search(
        r"\.(exe|scr|vbs|js|bat|ps1|lnk|iso|msi)\b", t
    ):
        return "멀웨어", None

    # 피싱 서브타입 판정
    for subtype, keys in PHISHING_SUBTYPES:
        if any(k.lower() in t for k in keys):
            label_map = {
                "credential_harvesting": "크리덴셜 하베스팅(로그인 정보 탈취)",
                "financial_info_theft": "금융정보 탈취",
                "payment_info_theft": "결제정보 갈취",
                "social_engineering": "사회공학형",
                "refund_scam": "환불 유도형",
                "mfa_token_theft": "MFA 토큰 탈취",
            }
            return "피싱", label_map.get(subtype, "사회공학형")

    # 기본 피싱 유형
    return "피싱", "사회공학형"


# -----------------------------
# 점수 → 판정/대응
# -----------------------------


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


def refine_score(score: int, evid: List[str]) -> int:
    """
    시그널 조합에 따른 v2 후처리 가중치.
    여러 근거가 동시에 나타나면 점수를 추가로 올려 악성에 가깝게 조정한다.
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


# -----------------------------
# 리포트 빌드 + 통합 분석
# -----------------------------


def build_report(
    score: int,
    evid_keys: List[str],
    family: Optional[str],
    phish_sub: Optional[str],
    file_info: Optional[Dict] = None,
) -> Dict:
    final = verdict_from_score(score)
    out: Dict = {
        "final_verdict": final,
        "risk_score": score,
    }

    if final in ("의심", "악성"):
        evid_keys = sorted(set(evid_keys))
        out.update(
            {
                "family": family,
                "phishing_subtype": phish_sub if family == "피싱" else None,
                "evidence": [
                    C_EVIDENCE_LABELS[k] for k in evid_keys if k in C_EVIDENCE_LABELS
                ],
                "recommended_actions": response_actions(family or ""),
            }
        )

    if file_info:
        out["file"] = file_info

    return out


def analyze_all(
    url: str = "",
    html: str = "",
    email: str = "",
    text: str = "",
    file_bytes: Optional[bytes] = None,
    filename: str = "",
) -> Dict:
    """
    URL / HTML / 이메일 / 텍스트 / 파일(옵션) 을 한 번에 받아
    최종 리포트를 반환하는 v2 엔진 엔트리 포인트.
    """
    score = 0
    evid: List[str] = []
    combined_text = " ".join([url, html, email, text]).strip()

    # URL
    if url.strip():
        s, e = analyze_url(url)
        score += s
        evid += e

    # HTML
    if html.strip():
        s, e, _flags = analyze_html(html)
        score += s
        evid += e

    # 이메일 원문
    if email.strip():
        s, e = analyze_email_raw(email)
        score += s
        evid += e

    # 일반 텍스트
    safe_text = text or ""
    if safe_text.replace("\r", "").replace("\n", "").strip() != "":
        s, e = analyze_text(safe_text)
        score += s
        evid += e

    file_info = None

    # 파일 분석
    if file_bytes is not None and filename:
        lower_name = filename.lower()
        digest = sha256_bytes(file_bytes)
        size = len(file_bytes)

        # 위험 확장자
        if lower_name.endswith(DANGEROUS_EXTS):
            score += 30
            evid.append("exec_attachment")

        # HTML 파일
        if lower_name.endswith((".html", ".htm")):
            html_text = file_bytes.decode("utf-8", errors="ignore")
            s, e, _f = analyze_html(html_text)
            score += s
            evid += e
            combined_text += " " + html_text

        # 이메일/텍스트 기반 파일
        if lower_name.endswith((".eml", ".txt")):
            raw_text = file_bytes.decode("utf-8", errors="ignore")
            s1, e1 = analyze_email_raw(raw_text)
            s2, e2 = analyze_text(raw_text)
            score += s1 + s2
            evid += e1 + e2
            combined_text += " " + raw_text

        # 이미지 파일 → OCR
        if lower_name.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff")):
            ocr_text = extract_text_from_image(file_bytes)
            if ocr_text:
                combined_text += " " + ocr_text
                s3, e3 = analyze_text(ocr_text)
                score += s3
                evid += e3

        file_info = {
            "filename": filename,
            "sha256": digest,
            "bytes": size,
        }

    # v2 후처리 + 점수 범위 조정
    score = refine_score(score, evid)
    score = clamp(score, 0, 100)

    family, phish_sub = decide_family_and_subtype(combined_text, list(set(evid)))
    report = build_report(score, list(set(evid)), family, phish_sub, file_info=file_info)
    return report
