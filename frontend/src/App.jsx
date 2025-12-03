import { useMemo, useState } from "react";
import axios from "axios";
import "./App.css";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";

function EvidenceList({ items }) {
  if (!items?.length) return null;
  return (
    <ul className="evidence-list">
      {items.map((x, i) => (
        <li key={i}>{x}</li>
      ))}
    </ul>
  );
}

function RiskBar({ score }) {
  const width = Math.max(0, Math.min(100, score));
  let level = "low";
  if (score > 60) level = "high";
  else if (score > 30) level = "mid";

  return (
    <div className="riskbar">
      <div className={`riskbar-fill riskbar-${level}`} style={{ width: `${width}%` }} />
    </div>
  );
}

export default function App() {
  const [inputType, setInputType] = useState("auto");
  const [url, setUrl] = useState("");
  const [emailRaw, setEmailRaw] = useState("");
  const [html, setHtml] = useState("");
  const [text, setText] = useState("");
  const [file, setFile] = useState(null);

  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [err, setErr] = useState("");

  const showThreatSection = useMemo(
    () => result?.final_verdict === "의심" || result?.final_verdict === "악성",
    [result]
  );

  async function onAnalyze() {
    setErr("");
    setResult(null);
    setLoading(true);

    try {
      const form = new FormData();
      form.append("input_type", inputType);
      form.append("url", url);
      form.append("email_raw", emailRaw);
      form.append("html", html);
      form.append("text", text);
      if (file) form.append("upload", file);

      const res = await axios.post(`${API_BASE}/analyze`, form, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      setResult(res.data);
    } catch (e) {
      setErr(e?.response?.data?.error || e.message || "요청 실패");
    } finally {
      setLoading(false);
    }
  }

  const verdictClass =
    result?.final_verdict === "악성"
      ? "badge badge-high"
      : result?.final_verdict === "의심"
      ? "badge badge-mid"
      : "badge badge-low";

  return (
    <div className="app-root">
      <div className="app-shell">
        <header className="app-header">
          <div>
            <h1>위협 판별 챗봇</h1>
            <p className="subtitle">URL·이메일·HTML·메시지·파일 기반 보안 triage MVP</p>
          </div>
          <span className="tag-mvp">MVP</span>
        </header>

        <main className="app-main">
          {/* 입력 패널 */}
          <section className="panel panel-input fade-in">
            <div className="panel-title-row">
              <h2>입력</h2>
              <small>분석하고 싶은 데이터를 붙여 넣거나 업로드하세요.</small>
            </div>

            <div className="grid-2">
              <label className="field">
                <span className="field-label">입력 타입</span>
                <select
                  value={inputType}
                  onChange={(e) => setInputType(e.target.value)}
                  className="select"
                >
                  <option value="auto">자동</option>
                  <option value="url">URL</option>
                  <option value="email">이메일 원문</option>
                  <option value="html">HTML</option>
                  <option value="text">메시지 텍스트</option>
                  <option value="file">파일</option>
                </select>
              </label>

              <label className="field">
                <span className="field-label">파일 업로드(선택)</span>
                <input
                  type="file"
                  onChange={(e) => setFile(e.target.files?.[0] || null)}
                  className="file-input"
                />
              </label>
            </div>

            <label className="field">
              <span className="field-label">URL</span>
              <input
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://..."
                className="text-input"
              />
            </label>

            <label className="field">
              <span className="field-label">이메일 원문(헤더+본문)</span>
              <textarea
                value={emailRaw}
                onChange={(e) => setEmailRaw(e.target.value)}
                rows={4}
                className="text-area"
              />
            </label>

            <label className="field">
              <span className="field-label">웹페이지 HTML 소스</span>
              <textarea
                value={html}
                onChange={(e) => setHtml(e.target.value)}
                rows={4}
                className="text-area"
              />
            </label>

            <label className="field">
              <span className="field-label">메시지 텍스트(문자/카톡)</span>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                rows={4}
                className="text-area"
              />
            </label>

            <button
              onClick={onAnalyze}
              disabled={loading}
              className={`btn-primary ${loading ? "btn-loading" : ""}`}
            >
              {loading ? "분석 중..." : "분석하기"}
            </button>

            {err && <div className="error-box">{err}</div>}
          </section>

          {/* 결과 카드 */}
          {result && (
            <section className="panel panel-result fade-in">
              <div className="panel-title-row">
                <h2>분석 결과</h2>
                <span className={verdictClass}>{result.final_verdict}</span>
              </div>

              <div className="score-row">
                <div>
                  <div className="score-label">위험 점수</div>
                  <div className="score-value">
                    {result.risk_score}
                    <span className="score-max">/100</span>
                  </div>
                </div>
                <div className="score-bar-wrapper">
                  <RiskBar score={result.risk_score} />
                </div>
              </div>

              {showThreatSection && (
                <div className="result-grid">
                  <div>
                    <h3 className="section-subtitle">위협 분류</h3>
                    <p>
                      <b>구분:</b> {result.family}
                    </p>
                    {result.family === "피싱" && result.phishing_subtype && (
                      <p>
                        <b>피싱 유형:</b> {result.phishing_subtype}
                      </p>
                    )}
                  </div>

                  <div>
                    <h3 className="section-subtitle">판단 근거 (C 방식)</h3>
                    <EvidenceList items={result.evidence} />
                  </div>

                  <div>
                    <h3 className="section-subtitle">권장 대응(실행 수준)</h3>
                    <EvidenceList items={result.recommended_actions} />
                  </div>
                </div>
              )}

              {result.file && (
                <div className="file-box">
                  <h3 className="section-subtitle">파일 정보</h3>
                  <p>
                    <b>파일명:</b> {result.file.filename}
                  </p>
                  <p>
                    <b>SHA-256:</b> {result.file.sha256}
                  </p>
                  <p>
                    <b>크기:</b> {result.file.bytes} bytes
                  </p>
                </div>
              )}
            </section>
          )}
        </main>
      </div>
    </div>
  );
}
