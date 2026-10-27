"""중대재해처벌법 이행 점검 및 증빙 관리 앱 (건설업·제조업).

- 사업장(현장)별, 반기별로 의무 이행 상태를 점검하고 증빙 파일을 보관한다.
- 데이터는 앱 폴더의 data/ 아래에 SQLite(DB)와 업로드 파일로 저장된다.
- 본 앱은 자체 점검을 돕는 도구이며 법률 자문을 대체하지 않는다.
"""

import hashlib
import hmac
import io
import re
import shutil
import sqlite3
import uuid
import zipfile
from contextlib import closing
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(page_title="중대재해처벌법 이행 점검", page_icon=":material/health_and_safety:", layout="wide")

DATA_DIR = Path(__file__).parent / "data"
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "compliance.db"

INDUSTRIES = ["건설업", "제조업"]
STATUSES = ["미점검", "이행", "부분 이행", "미이행", "해당 없음"]
STATUS_SCORE = {"이행": 1.0, "부분 이행": 0.5, "미이행": 0.0, "미점검": 0.0}
DEFAULT_PASSWORD = "9408"  # 초기 비밀번호. 배포 시 secrets의 app_password로 덮어쓰는 것을 권장
ACTION_STATUSES = ["미착수", "진행 중", "완료"]
PRIORITIES = ["높음", "보통", "낮음"]
EXPIRY_WARN_DAYS = 30

# ---------------------------------------------------------------------------
# 점검 항목 정의 (id, 분류, 적용 업종, 항목, 근거, 권장 증빙)
# 근거 조문은 참고용이므로 최신 법령으로 반드시 확인한다.
# ---------------------------------------------------------------------------
ITEMS = [
    # 공통: 중대재해처벌법 시행령 제4조(안전보건관리체계의 구축 및 이행), 제5조(점검)
    ("C01", "경영방침·조직", "공통", "안전보건 목표와 경영방침 설정", "시행령 제4조 제1호", "경영방침 문서, 목표 공표·게시 사진"),
    ("C02", "경영방침·조직", "공통", "안전·보건 전담조직 설치 (상시근로자 500명 이상 등 해당 시)", "시행령 제4조 제2호", "조직도, 직무기술서, 인사발령문"),
    ("C03", "경영방침·조직", "공통", "안전관리자·보건관리자 등 선임 및 배치", "시행령 제4조 제6호", "선임 보고서, 선임 공문, 업무수행 기록"),
    ("C04", "경영방침·조직", "공통", "안전보건관리책임자 등의 권한·예산 부여 및 반기 1회 평가", "시행령 제4조 제5호", "권한·예산 위임 문서, 평가표"),
    ("C05", "위험요인 관리", "공통", "유해·위험요인 확인·개선 절차 마련", "시행령 제4조 제3호", "위험요인 확인·개선 절차서"),
    ("C06", "위험요인 관리", "공통", "유해·위험요인 반기 1회 이상 점검 및 개선 조치", "시행령 제4조 제3호", "점검 결과서, 개선 조치 사진·완료 보고"),
    ("C07", "위험요인 관리", "공통", "위험성평가 실시 및 결과 반영", "산업안전보건법 제36조", "위험성평가 보고서, 감소대책 이행 기록"),
    ("C08", "예산·인력", "공통", "재해예방 인력·시설·장비 구비 및 예산 편성·집행", "시행령 제4조 제4호", "예산 편성안, 집행 내역, 장비 구매 내역"),
    ("C09", "종사자 참여", "공통", "종사자 의견 청취 절차 마련 및 개선방안 이행", "시행령 제4조 제7호", "의견 청취 절차서, 접수대장, 개선 조치 기록"),
    ("C10", "비상 대응", "공통", "중대산업재해·급박한 위험 대비 매뉴얼 마련 및 반기 1회 점검(훈련)", "시행령 제4조 제8호", "대응 매뉴얼, 비상대응 훈련 결과"),
    ("C11", "도급·관계법령", "공통", "도급·용역·위탁 시 안전보건 평가기준·절차 마련 및 이행 점검", "시행령 제4조 제9호", "수급인 평가표, 계약서 안전보건 조항"),
    ("C12", "도급·관계법령", "공통", "관계 법령상 안전보건 의무 이행 반기 1회 점검 및 결과 보고", "시행령 제5조", "점검 결과 보고서(경영책임자 확인)"),
    ("C13", "도급·관계법령", "공통", "법정 안전보건교육 실시 여부 점검", "시행령 제5조, 산업안전보건법 제29조", "교육 일지, 참석자 서명부"),
    # 건설업
    ("K01", "건설 현장 안전", "건설업", "산업안전보건관리비 계상 및 목적 외 사용 방지", "산업안전보건법 제72조", "관리비 사용계획서, 사용내역서, 증빙 영수증"),
    ("K02", "건설 현장 안전", "건설업", "추락 방지 (작업발판, 안전난간, 개구부 덮개, 안전대 부착설비)", "산업안전보건기준에 관한 규칙 제42조 등", "일일 점검표, 설치 사진"),
    ("K03", "건설 현장 안전", "건설업", "굴착·흙막이 등 붕괴 방지 조치 및 지반 점검", "산업안전보건기준에 관한 규칙 제3편", "굴착 작업계획서, 흙막이 계측 결과"),
    ("K04", "건설 현장 안전", "건설업", "비계·거푸집 동바리 등 가설구조물 구조 검토 및 설치 점검", "산업안전보건기준에 관한 규칙 제3편", "구조 검토서, 조립도, 설치 후 점검 기록"),
    ("K05", "건설 현장 안전", "건설업", "크레인·굴착기 등 건설기계 점검, 작업계획서 및 신호수 배치", "산업안전보건기준에 관한 규칙 제2편·제3편", "장비 점검표, 작업계획서, 신호수 배치 기록"),
    ("K06", "건설 현장 안전", "건설업", "용접·용단 등 화재·폭발 위험 작업 시 화재감시자 배치", "산업안전보건기준에 관한 규칙 제241조 등", "화기작업 허가서, 감시자 배치 기록"),
    ("K07", "건설 현장 안전", "건설업", "밀폐공간 작업 프로그램 수립 및 산소·유해가스 농도 측정", "산업안전보건기준에 관한 규칙 제10편", "작업 허가서, 측정 기록"),
    ("K08", "건설 현장 안전", "건설업", "작업 전 안전점검회의(TBM) 및 일일 안전점검 실시", "산업안전보건법 제16조 등", "TBM 일지, 일일 점검표"),
    ("K09", "도급·관계법령", "건설업", "도급인·수급인 안전보건협의체 구성 및 정기 운영", "산업안전보건법 제64조", "협의체 회의록, 합동 안전점검 결과"),
    # 제조업
    ("M01", "제조 설비 안전", "제조업", "기계·기구 방호장치 설치 및 유지 (프레스, 컨베이어 등)", "산업안전보건기준에 관한 규칙 제2편", "방호장치 점검표, 설비 안전인증 서류"),
    ("M02", "제조 설비 안전", "제조업", "끼임 방지: 정비·청소 시 운전 정지 및 잠금·표지(LOTO) 절차 이행", "산업안전보건기준에 관한 규칙 제92조", "LOTO 절차서, 작업 기록, 교육 기록"),
    ("M03", "제조 설비 안전", "제조업", "지게차 등 운반기계 안전조치 (신호수, 보행자 동선 분리)", "산업안전보건기준에 관한 규칙 제2편", "운행 규칙, 점검표, 동선도"),
    ("M04", "제조 설비 안전", "제조업", "화재·폭발 예방 (가연물 관리, 전기설비, 방폭구조)", "산업안전보건기준에 관한 규칙 제5편", "소방·전기 점검 결과서"),
    ("M05", "보건 관리", "제조업", "화학물질 관리: 물질안전보건자료(MSDS) 비치·교육, 국소배기장치 점검", "산업안전보건법 제110조·제114조", "MSDS 목록, 교육 일지, 국소배기 성능 검사"),
    ("M06", "보건 관리", "제조업", "밀폐공간(탱크·맨홀 등) 작업 프로그램 및 산소·유해가스 측정", "산업안전보건기준에 관한 규칙 제10편", "작업 허가서, 측정 기록"),
    ("M07", "보건 관리", "제조업", "작업환경측정 및 특수건강진단 실시와 사후관리", "산업안전보건법 제125조·제130조", "측정 결과 보고서, 건강진단 결과 및 조치 기록"),
    ("M08", "보건 관리", "제조업", "근골격계 유해요인조사 및 개선", "산업안전보건기준에 관한 규칙 제12편", "유해요인조사표, 개선 계획서"),
    ("M09", "도급·관계법령", "제조업", "협력업체 안전보건협의체 운영 및 합동 점검", "산업안전보건법 제64조", "협의체 회의록, 합동 점검 결과"),
]
ITEM_COLUMNS = ["id", "category", "scope", "title", "basis", "hint"]
ITEM_DF = pd.DataFrame(ITEMS, columns=ITEM_COLUMNS)
ITEM_TITLE = {row.id: row.title for row in ITEM_DF.itertuples()}


def items_for(industry: str) -> pd.DataFrame:
    return ITEM_DF[ITEM_DF["scope"].isin(["공통", industry])].reset_index(drop=True)


def item_label(item_id: str) -> str:
    return f"{item_id} · {ITEM_TITLE.get(item_id, '')}"


# ---------------------------------------------------------------------------
# 데이터베이스
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    industry TEXT NOT NULL,
    manager TEXT,
    workers INTEGER,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assessments (
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    item_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT,
    checked_on TEXT,
    note TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (site_id, period, item_id)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    item_id TEXT NOT NULL,
    title TEXT NOT NULL,
    doc_date TEXT,
    expiry_date TEXT,
    uploader TEXT,
    filename TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    period TEXT NOT NULL,
    item_id TEXT,
    title TEXT NOT NULL,
    owner TEXT,
    due_date TEXT,
    priority TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    closed_at TEXT
);
"""


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    EVIDENCE_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with closing(connect()) as conn, conn:
        conn.executescript(SCHEMA)


def execute(sql: str, params: tuple = ()) -> int:
    with closing(connect()) as conn, conn:
        return conn.execute(sql, params).lastrowid


def executemany(sql: str, rows: list[tuple]) -> None:
    with closing(connect()) as conn, conn:
        conn.executemany(sql, rows)


def query(sql: str, params: tuple = ()) -> pd.DataFrame:
    with closing(connect()) as conn:
        return pd.read_sql_query(sql, conn, params=params)


def iso_or_none(value) -> str | None:
    """date/Timestamp/NaT/None/빈 문자열을 ISO 날짜 문자열 또는 None으로 변환한다."""
    if value is None or value == "" or pd.isna(value):
        return None
    return pd.to_datetime(value).date().isoformat()


def text_or_none(value) -> str | None:
    if value is None or pd.isna(value):
        return None
    value = str(value).strip()
    return value or None


# ---------------------------------------------------------------------------
# 도메인 로직
# ---------------------------------------------------------------------------
def load_sites() -> pd.DataFrame:
    return query("SELECT * FROM sites ORDER BY name")


def checklist_frame(site: pd.Series, period: str) -> pd.DataFrame:
    """사업장·기간의 점검 항목에 점검 결과와 유효 증빙 건수를 결합한다."""
    items = items_for(site["industry"])
    assessed = query(
        "SELECT item_id AS id, status, owner, checked_on, note FROM assessments WHERE site_id = ? AND period = ?",
        (int(site["id"]), period),
    )
    evidence = query(
        """SELECT item_id AS id, COUNT(*) AS evidence_count FROM evidence
           WHERE site_id = ? AND period = ? AND (expiry_date IS NULL OR expiry_date = '' OR expiry_date >= ?)
           GROUP BY item_id""",
        (int(site["id"]), period, date.today().isoformat()),
    )
    df = items.merge(assessed, on="id", how="left").merge(evidence, on="id", how="left")
    df["status"] = df["status"].fillna("미점검")
    df["evidence_count"] = df["evidence_count"].fillna(0).astype(int)
    df["checked_on"] = pd.to_datetime(df["checked_on"], errors="coerce")
    df["owner"] = df["owner"].fillna("")
    df["note"] = df["note"].fillna("")
    return df


def summarize(df: pd.DataFrame) -> dict:
    applicable = df[df["status"] != "해당 없음"]
    total = len(applicable)
    checked = int((applicable["status"] != "미점검").sum())
    score = applicable["status"].map(STATUS_SCORE).sum()
    needs_evidence = applicable[applicable["status"].isin(["이행", "부분 이행"])]
    with_evidence = int((needs_evidence["evidence_count"] > 0).sum())
    return {
        "total": total,
        "checked": checked,
        "rate": (score / total * 100) if total else 0.0,
        "progress": (checked / total * 100) if total else 0.0,
        "evidence_rate": (with_evidence / len(needs_evidence) * 100) if len(needs_evidence) else 0.0,
        "evidence_missing": len(needs_evidence) - with_evidence,
        "counts": df["status"].value_counts().reindex(STATUSES, fill_value=0),
    }


def evidence_state(expiry: str | None) -> str:
    if not expiry:
        return "기한 없음"
    exp = date.fromisoformat(expiry)
    today = date.today()
    if exp < today:
        return "만료"
    if exp <= today + timedelta(days=EXPIRY_WARN_DAYS):
        return "만료 임박"
    return "유효"


def load_evidence(site_id: int, period: str | None = None) -> pd.DataFrame:
    sql = "SELECT * FROM evidence WHERE site_id = ?"
    params: tuple = (site_id,)
    if period:
        sql += " AND period = ?"
        params += (period,)
    df = query(sql + " ORDER BY uploaded_at DESC, id DESC", params)
    df["state"] = df["expiry_date"].map(lambda v: evidence_state(v) if isinstance(v, str) and v else "기한 없음")
    df["item"] = df["item_id"].map(item_label)
    return df


def load_actions(site_id: int, period: str | None = None) -> pd.DataFrame:
    sql = "SELECT * FROM actions WHERE site_id = ?"
    params: tuple = (site_id,)
    if period:
        sql += " AND period = ?"
        params += (period,)
    df = query(sql + " ORDER BY id DESC", params)
    today = date.today().isoformat()
    df["overdue"] = (df["status"] != "완료") & df["due_date"].notna() & (df["due_date"] < today)
    return df


def safe_filename(name: str) -> str:
    return re.sub(r'[\\/:*?"<>|\x00-\x1f]', "_", Path(name).name) or "file"


def resolve_stored_path(stored_path: str) -> Path | None:
    """저장 경로를 data/evidence 내부로 제한한다."""
    path = (DATA_DIR / stored_path).resolve()
    return path if path.is_relative_to(EVIDENCE_DIR.resolve()) else None


def csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8-sig")  # 엑셀에서 한글이 깨지지 않도록 BOM 포함


# ---------------------------------------------------------------------------
# 페이지
# ---------------------------------------------------------------------------
def current_context() -> tuple[pd.Series, str]:
    return st.session_state["site"], st.session_state["period"]


def page_dashboard():
    site, period = current_context()
    st.title("이행 현황 대시보드")
    st.caption(f"{site['name']} ({site['industry']}) · {period}")

    df = checklist_frame(site, period)
    s = summarize(df)
    actions = load_actions(int(site["id"]), period)
    open_actions = actions[actions["status"] != "완료"]
    expired = load_evidence(int(site["id"]), period)
    expiring = expired[expired["state"].isin(["만료", "만료 임박"])]

    cols = st.columns(4)
    cols[0].metric("이행률", f"{s['rate']:.0f}%", f"점검 {s['checked']}/{s['total']}항목", delta_color="off", border=True, height="stretch")
    cols[1].metric("증빙 확보율", f"{s['evidence_rate']:.0f}%", f"증빙 누락 {s['evidence_missing']}건", delta_color="off", border=True, height="stretch")
    cols[2].metric("미완료 시정조치", f"{len(open_actions)}건", f"기한 초과 {int(actions['overdue'].sum())}건", delta_color="off", border=True, height="stretch")
    cols[3].metric("만료·만료 임박 증빙", f"{len(expiring)}건", f"{EXPIRY_WARN_DAYS}일 이내 기준", delta_color="off", border=True, height="stretch")

    if s["progress"] < 100:
        st.progress(s["progress"] / 100, text=f"점검 진행률 {s['progress']:.0f}%")

    left, right = st.columns([3, 2])
    with left:
        with st.container(border=True):
            st.subheader("분류별 이행률")
            applicable = df[df["status"] != "해당 없음"].copy()
            if applicable.empty:
                st.info("적용 대상 항목이 없습니다.")
            else:
                applicable["score"] = applicable["status"].map(STATUS_SCORE)
                by_cat = applicable.groupby("category")["score"].mean().mul(100).round(0).rename("이행률(%)").reset_index()
                by_cat = by_cat.rename(columns={"category": "분류"})
                st.bar_chart(by_cat, x="분류", y="이행률(%)", horizontal=True, alt="분류별 이행률(%) 막대 차트")
    with right:
        with st.container(border=True):
            st.subheader("상태별 항목 수")
            counts = s["counts"].rename("항목 수").reset_index().rename(columns={"status": "상태", "index": "상태"})
            st.dataframe(counts, hide_index=True, alt="점검 상태별 항목 수 표")

    with st.container(border=True):
        st.subheader("조치가 필요한 항목")
        todo = df[df["status"].isin(["미이행", "부분 이행"]) | ((df["status"] == "이행") & (df["evidence_count"] == 0))].copy()
        if todo.empty:
            st.success("조치가 필요한 항목이 없습니다.", icon=":material/check_circle:")
        else:
            todo["사유"] = todo.apply(
                lambda r: r["status"] if r["status"] != "이행" else "이행 표기, 증빙 누락", axis=1
            )
            st.dataframe(
                todo[["id", "category", "title", "사유", "owner"]].rename(
                    columns={"id": "번호", "category": "분류", "title": "점검 항목", "owner": "담당자"}
                ),
                hide_index=True,
                alt="조치가 필요한 점검 항목 목록",
            )

    overdue = actions[actions["overdue"]]
    if not overdue.empty:
        st.warning(f"기한이 지난 시정조치가 {len(overdue)}건 있습니다.", title="시정조치 기한 초과", icon=":material/alarm:")


def page_checklist():
    site, period = current_context()
    st.title("의무 이행 점검")
    st.caption(f"{site['name']} ({site['industry']}) · {period} · 상태, 담당자, 점검일, 비고를 입력한 뒤 저장하세요.")

    df = checklist_frame(site, period)
    categories = list(dict.fromkeys(df["category"]))
    picked = st.pills("분류 필터", categories, selection_mode="multi", key="checklist_filter")
    view = df[df["category"].isin(picked)] if picked else df

    editor_key = f"checklist_editor_{st.session_state.get('checklist_version', 0)}"
    edited = st.data_editor(
        view[["id", "category", "title", "status", "owner", "checked_on", "evidence_count", "note", "hint", "basis"]],
        key=editor_key,
        hide_index=True,
        height="content",
        disabled=["id", "category", "title", "evidence_count", "hint", "basis"],
        column_config={
            "id": st.column_config.TextColumn("번호", width="small"),
            "category": st.column_config.TextColumn("분류"),
            "title": st.column_config.TextColumn("점검 항목", width="large"),
            "status": st.column_config.SelectboxColumn("상태", options=STATUSES, required=True),
            "owner": st.column_config.TextColumn("담당자"),
            "checked_on": st.column_config.DateColumn("점검일", format="YYYY-MM-DD"),
            "evidence_count": st.column_config.NumberColumn("유효 증빙(건)", format="%d"),
            "note": st.column_config.TextColumn("비고", width="medium"),
            "hint": st.column_config.TextColumn("권장 증빙", width="medium"),
            "basis": st.column_config.TextColumn("근거", width="medium"),
        },
        alt="의무 이행 점검 항목 편집 표",
    )

    if st.button("저장", type="primary", icon=":material/save:"):
        now = date.today().isoformat()
        upserts, deletes = [], []
        for row in edited.itertuples():
            owner, note = text_or_none(row.owner), text_or_none(row.note)
            checked_on = iso_or_none(row.checked_on)
            if row.status == "미점검" and not owner and not note and not checked_on:
                deletes.append((int(site["id"]), period, row.id))
                continue
            if row.status != "미점검" and not checked_on:
                checked_on = now
            upserts.append((int(site["id"]), period, row.id, row.status, owner, checked_on, note, now))
        executemany(
            """INSERT INTO assessments (site_id, period, item_id, status, owner, checked_on, note, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(site_id, period, item_id) DO UPDATE SET
                 status = excluded.status, owner = excluded.owner, checked_on = excluded.checked_on,
                 note = excluded.note, updated_at = excluded.updated_at""",
            upserts,
        )
        executemany("DELETE FROM assessments WHERE site_id = ? AND period = ? AND item_id = ?", deletes)
        st.session_state["checklist_version"] = st.session_state.get("checklist_version", 0) + 1
        st.toast("점검 결과를 저장했습니다.", icon=":material/check_circle:")
        st.rerun()

    st.caption("조문 표기는 참고용입니다. 법령 개정 여부와 사업장 적용 대상 여부는 최신 법령과 전문가를 통해 확인하세요.")


@st.dialog("증빙 삭제")
def confirm_delete_evidence(evidence_id: int, filename: str, stored_path: str):
    st.write(f"**{filename}** 파일과 등록 정보를 삭제합니다. 이 작업은 되돌릴 수 없습니다.")
    with st.container(horizontal=True):
        if st.button("삭제", type="primary", icon=":material/delete:"):
            path = resolve_stored_path(stored_path)
            if path and path.exists():
                path.unlink()
            execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
            st.session_state["evidence_version"] = st.session_state.get("evidence_version", 0) + 1
            st.rerun()
        if st.button("취소"):
            st.rerun()


def save_uploaded_files(site, period, item_id, files, title, doc_date, expiry, uploader) -> tuple[int, list[str]]:
    site_dir = EVIDENCE_DIR / str(int(site["id"]))
    site_dir.mkdir(parents=True, exist_ok=True)
    existing = set(
        query(
            "SELECT sha256 FROM evidence WHERE site_id = ? AND period = ? AND item_id = ?",
            (int(site["id"]), period, item_id),
        )["sha256"]
    )
    saved, skipped = 0, []
    for f in files:
        data = f.getvalue()
        digest = hashlib.sha256(data).hexdigest()
        if digest in existing:
            skipped.append(f.name)
            continue
        stored = site_dir / f"{uuid.uuid4().hex}_{safe_filename(f.name)}"
        stored.write_bytes(data)
        execute(
            """INSERT INTO evidence (site_id, period, item_id, title, doc_date, expiry_date, uploader,
                                     filename, stored_path, sha256, size, uploaded_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                int(site["id"]), period, item_id,
                title.strip() if title and len(files) == 1 else Path(f.name).stem,
                iso_or_none(doc_date), iso_or_none(expiry), text_or_none(uploader),
                f.name, stored.relative_to(DATA_DIR).as_posix(), digest, len(data),
                pd.Timestamp.now().strftime("%Y-%m-%d %H:%M"),
            ),
        )
        existing.add(digest)
        saved += 1
    return saved, skipped


def page_evidence():
    site, period = current_context()
    st.title("증빙 자료 관리")
    st.caption(f"{site['name']} · {period}")

    items = items_for(site["industry"])
    with st.expander("증빙 등록", expanded=True, icon=":material/upload_file:"):
        with st.form("evidence_upload", clear_on_submit=True):
            item_id = st.selectbox("점검 항목", items["id"].tolist(), format_func=item_label)
            files = st.file_uploader("파일 (여러 개 선택 가능)", accept_multiple_files=True)
            title = st.text_input("제목 (파일 1개 등록 시, 비우면 파일명 사용)")
            with st.container(horizontal=True, vertical_alignment="bottom"):
                doc_date = st.date_input("문서 일자", value=date.today())
                has_expiry = st.checkbox("유효기한 있음")
                expiry = st.date_input("유효기한", value=date.today() + timedelta(days=365))
                uploader = st.text_input("등록자")
            submitted = st.form_submit_button("등록", type="primary", icon=":material/upload:")
        if submitted:
            if not files:
                st.error("등록할 파일을 선택하세요.")
            else:
                saved, skipped = save_uploaded_files(site, period, item_id, files, title, doc_date, expiry if has_expiry else None, uploader)
                if saved:
                    st.toast(f"{saved}개 파일을 등록했습니다.", icon=":material/check_circle:")
                if skipped:
                    st.warning("이미 등록된 동일 파일은 건너뛰었습니다: " + ", ".join(skipped))
                if saved:
                    st.session_state["evidence_version"] = st.session_state.get("evidence_version", 0) + 1
                    st.rerun()

    with st.container(horizontal=True, vertical_alignment="bottom"):
        scope = st.segmented_control("조회 범위", ["선택한 기간", "전체 기간"], default="선택한 기간", key="evidence_scope")
        state_filter = st.pills("상태", ["유효", "만료 임박", "만료", "기한 없음"], selection_mode="multi", key="evidence_state_filter")
        keyword = st.text_input("검색", type="search", placeholder="제목·파일명·항목", key="evidence_keyword")

    ev = load_evidence(int(site["id"]), period if scope != "전체 기간" else None)
    if state_filter:
        ev = ev[ev["state"].isin(state_filter)]
    if keyword:
        mask = ev[["title", "filename", "item"]].apply(lambda c: c.str.contains(keyword, case=False, na=False)).any(axis=1)
        ev = ev[mask]

    if ev.empty:
        st.info("등록된 증빙이 없습니다.")
        return

    ev = ev.reset_index(drop=True)
    shown = ev[["item", "title", "filename", "period", "doc_date", "expiry_date", "state", "uploader", "uploaded_at"]].rename(
        columns={
            "item": "점검 항목", "title": "제목", "filename": "파일명", "period": "기간", "doc_date": "문서 일자",
            "expiry_date": "유효기한", "state": "상태", "uploader": "등록자", "uploaded_at": "등록 일시",
        }
    )
    event = st.dataframe(
        shown,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        key=f"evidence_table_{st.session_state.get('evidence_version', 0)}",
        alt="등록된 증빙 자료 목록. 행을 선택하면 다운로드와 삭제를 할 수 있습니다.",
    )

    rows = event.selection.rows
    if not rows:
        st.caption("행을 선택하면 파일을 내려받거나 삭제할 수 있습니다.")
        return
    row = ev.iloc[rows[0]]
    path = resolve_stored_path(row["stored_path"])
    with st.container(border=True):
        st.subheader(row["title"])
        st.caption(f"{row['item']} · {row['filename']} · {row['size'] / 1024:.1f} KB · SHA-256 {row['sha256'][:16]}…")
        if path is None or not path.exists():
            st.error("저장된 파일을 찾을 수 없습니다. 등록 정보만 남아 있습니다.")
        else:
            if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp"}:
                st.image(str(path), width=360, alt=f"증빙 이미지: {row['title']}")
            with st.container(horizontal=True):
                st.download_button("다운로드", data=path.read_bytes(), file_name=row["filename"], icon=":material/download:")
                if st.button("삭제", icon=":material/delete:"):
                    confirm_delete_evidence(int(row["id"]), row["filename"], row["stored_path"])


def page_actions():
    site, period = current_context()
    st.title("시정조치 관리")
    st.caption(f"{site['name']} · {period}")

    df = checklist_frame(site, period)
    actions = load_actions(int(site["id"]), period)
    open_item_ids = set(actions.loc[actions["status"] != "완료", "item_id"].dropna())
    gaps = df[df["status"].isin(["미이행", "부분 이행"]) & ~df["id"].isin(open_item_ids)]

    with st.container(border=True):
        st.subheader("자동 생성")
        st.write(f"미이행·부분 이행 항목 중 진행 중인 시정조치가 없는 항목: **{len(gaps)}건**")
        if st.button("시정조치 일괄 생성", disabled=gaps.empty, icon=":material/playlist_add:"):
            due = (date.today() + timedelta(days=30)).isoformat()
            now = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M")
            executemany(
                """INSERT INTO actions (site_id, period, item_id, title, owner, due_date, priority, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, '미착수', ?)""",
                [
                    (int(site["id"]), period, r.id, f"[{r.id}] {r.title} 개선", text_or_none(r.owner), due,
                     "높음" if r.status == "미이행" else "보통", now)
                    for r in gaps.itertuples()
                ],
            )
            st.toast(f"{len(gaps)}건을 생성했습니다.", icon=":material/check_circle:")
            st.rerun()

    with st.expander("시정조치 직접 추가", icon=":material/add:"):
        with st.form("action_add", clear_on_submit=True):
            item_id = st.selectbox("관련 항목", [None] + df["id"].tolist(), format_func=lambda v: "항목 없음" if v is None else item_label(v))
            title = st.text_input("조치 내용")
            with st.container(horizontal=True):
                owner = st.text_input("담당자")
                due = st.date_input("기한", value=date.today() + timedelta(days=30))
                priority = st.segmented_control("우선순위", PRIORITIES, default="보통")
            if st.form_submit_button("추가", type="primary", icon=":material/add:"):
                if not title.strip():
                    st.error("조치 내용을 입력하세요.")
                else:
                    execute(
                        """INSERT INTO actions (site_id, period, item_id, title, owner, due_date, priority, status, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, '미착수', ?)""",
                        (int(site["id"]), period, item_id, title.strip(), text_or_none(owner), iso_or_none(due),
                         priority or "보통", pd.Timestamp.now().strftime("%Y-%m-%d %H:%M")),
                    )
                    st.rerun()

    st.subheader("조치 목록")
    if actions.empty:
        st.info("등록된 시정조치가 없습니다.")
        return

    table = actions[["id", "item_id", "title", "owner", "due_date", "priority", "status", "overdue"]].copy()
    table["due_date"] = pd.to_datetime(table["due_date"], errors="coerce")
    table["삭제"] = False
    key = f"actions_editor_{st.session_state.get('actions_version', 0)}"
    edited = st.data_editor(
        table,
        key=key,
        hide_index=True,
        disabled=["id", "item_id", "overdue"],
        column_config={
            "id": st.column_config.NumberColumn("번호", format="%d", width="small"),
            "item_id": st.column_config.TextColumn("관련 항목", width="small"),
            "title": st.column_config.TextColumn("조치 내용", width="large"),
            "owner": st.column_config.TextColumn("담당자"),
            "due_date": st.column_config.DateColumn("기한", format="YYYY-MM-DD"),
            "priority": st.column_config.SelectboxColumn("우선순위", options=PRIORITIES, required=True),
            "status": st.column_config.SelectboxColumn("상태", options=ACTION_STATUSES, required=True),
            "overdue": st.column_config.CheckboxColumn("기한 초과"),
        },
        alt="시정조치 목록 편집 표",
    )
    if st.button("변경 사항 저장", type="primary", icon=":material/save:"):
        today = date.today().isoformat()
        for r in edited.itertuples():
            if r.삭제:
                execute("DELETE FROM actions WHERE id = ?", (int(r.id),))
                continue
            execute(
                """UPDATE actions SET title = ?, owner = ?, due_date = ?, priority = ?, status = ?,
                       closed_at = CASE WHEN ? = '완료' THEN COALESCE(closed_at, ?) ELSE NULL END
                   WHERE id = ?""",
                (str(r.title).strip() or "(제목 없음)", text_or_none(r.owner), iso_or_none(r.due_date), r.priority,
                 r.status, r.status, today, int(r.id)),
            )
        st.session_state["actions_version"] = st.session_state.get("actions_version", 0) + 1
        st.toast("저장했습니다.", icon=":material/check_circle:")
        st.rerun()
    st.caption("'삭제' 칸을 선택하고 저장하면 해당 조치가 삭제됩니다.")


def build_report_markdown(site: pd.Series, period: str, df: pd.DataFrame, actions: pd.DataFrame) -> str:
    s = summarize(df)
    lines = [
        f"# 중대재해처벌법 이행 점검 보고서",
        "",
        f"- 사업장: {site['name']} ({site['industry']})",
        f"- 점검 기간: {period}",
        f"- 작성일: {date.today().isoformat()}",
        f"- 안전보건 담당: {site['manager'] or '-'}",
        "",
        "## 요약",
        f"- 이행률: {s['rate']:.0f}% (점검 {s['checked']}/{s['total']}항목)",
        f"- 증빙 확보율: {s['evidence_rate']:.0f}% (증빙 누락 {s['evidence_missing']}건)",
        f"- 미완료 시정조치: {int((actions['status'] != '완료').sum())}건",
        "",
        "## 항목별 점검 결과",
        "",
        "| 번호 | 분류 | 점검 항목 | 상태 | 담당자 | 점검일 | 증빙(건) |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in df.itertuples():
        checked = r.checked_on.date().isoformat() if pd.notna(r.checked_on) else "-"
        lines.append(f"| {r.id} | {r.category} | {r.title} | {r.status} | {r.owner or '-'} | {checked} | {r.evidence_count} |")
    lines += ["", "## 시정조치", ""]
    if actions.empty:
        lines.append("등록된 시정조치가 없습니다.")
    else:
        lines += ["| 번호 | 내용 | 담당자 | 기한 | 상태 |", "|---|---|---|---|---|"]
        for r in actions.itertuples():
            lines.append(f"| {r.id} | {r.title} | {r.owner or '-'} | {r.due_date or '-'} | {r.status} |")
    lines += ["", "---", "본 보고서는 자체 점검 기록이며 법률 자문이 아닙니다."]
    return "\n".join(lines)


def build_evidence_zip(site: pd.Series, period: str) -> bytes:
    ev = load_evidence(int(site["id"]), period)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        ledger = ev[["item_id", "title", "filename", "period", "doc_date", "expiry_date", "state", "uploader", "uploaded_at", "sha256"]]
        zf.writestr("증빙대장.csv", csv_bytes(ledger))
        for r in ev.itertuples():
            path = resolve_stored_path(r.stored_path)
            if path and path.exists():
                zf.write(path, f"{r.item_id}/{safe_filename(r.filename)}")
    return buffer.getvalue()


def page_report():
    site, period = current_context()
    st.title("보고서·내보내기")
    st.caption(f"{site['name']} · {period}")

    df = checklist_frame(site, period)
    actions = load_actions(int(site["id"]), period)
    ev = load_evidence(int(site["id"]), period)

    report = build_report_markdown(site, period, df, actions)
    with st.container(border=True):
        st.subheader("점검 보고서")
        st.markdown(report)

    st.subheader("내보내기")
    result = df[["id", "category", "title", "basis", "status", "owner", "checked_on", "evidence_count", "note"]].rename(
        columns={"id": "번호", "category": "분류", "title": "점검 항목", "basis": "근거", "status": "상태",
                 "owner": "담당자", "checked_on": "점검일", "evidence_count": "유효 증빙(건)", "note": "비고"}
    )
    prefix = f"{safe_filename(site['name'])}_{period}"
    with st.container(horizontal=True):
        st.download_button("보고서 (Markdown)", report.encode("utf-8"), f"{prefix}_보고서.md", "text/markdown", icon=":material/description:")
        st.download_button("점검 결과 (CSV)", csv_bytes(result), f"{prefix}_점검결과.csv", "text/csv", icon=":material/table:")
        st.download_button(
            "증빙 대장 (CSV)",
            csv_bytes(ev.drop(columns=["stored_path", "item"], errors="ignore")),
            f"{prefix}_증빙대장.csv", "text/csv", icon=":material/folder_open:",
        )
        st.download_button(
            "시정조치 (CSV)", csv_bytes(actions.drop(columns=["overdue"], errors="ignore")),
            f"{prefix}_시정조치.csv", "text/csv", icon=":material/task_alt:",
        )

    with st.container(border=True):
        st.subheader("증빙 일괄 내려받기")
        st.caption("선택한 기간의 증빙 파일과 증빙 대장을 ZIP으로 묶습니다.")
        zip_key = f"zip_{site['id']}_{period}"
        if st.button("ZIP 생성", icon=":material/archive:", disabled=ev.empty):
            st.session_state[zip_key] = build_evidence_zip(site, period)
        if zip_key in st.session_state:
            st.download_button("ZIP 다운로드", st.session_state[zip_key], f"{prefix}_증빙.zip", "application/zip", icon=":material/download:")


def page_sites():
    st.title("사업장 설정")
    sites = load_sites()
    if sites.empty:
        st.info("먼저 점검할 사업장(현장)을 등록하세요.", icon=":material/info:")

    with st.container(border=True):
        st.subheader("사업장 등록")
        with st.form("site_add", clear_on_submit=True):
            name = st.text_input("사업장·현장명")
            industry = st.segmented_control("업종", INDUSTRIES, default=INDUSTRIES[0])
            with st.container(horizontal=True):
                manager = st.text_input("안전보건 담당자")
                workers = st.number_input("상시근로자 수", min_value=0, value=50, step=1)
            if st.form_submit_button("등록", type="primary", icon=":material/add_business:"):
                if not name.strip():
                    st.error("사업장명을 입력하세요.")
                elif name.strip() in set(sites["name"]):
                    st.error("같은 이름의 사업장이 이미 있습니다.")
                else:
                    execute(
                        "INSERT INTO sites (name, industry, manager, workers, created_at) VALUES (?, ?, ?, ?, ?)",
                        (name.strip(), industry or INDUSTRIES[0], text_or_none(manager), int(workers), date.today().isoformat()),
                    )
                    st.rerun()
        st.caption("상시근로자 5명 미만 사업장은 중대재해처벌법 적용 대상이 아닙니다. 적용 여부는 사업장별로 확인하세요.")

    if sites.empty:
        return
    st.subheader("등록된 사업장")
    st.dataframe(
        sites[["name", "industry", "manager", "workers", "created_at"]].rename(
            columns={"name": "사업장", "industry": "업종", "manager": "담당자", "workers": "상시근로자", "created_at": "등록일"}
        ),
        hide_index=True,
        alt="등록된 사업장 목록",
    )

    with st.expander("사업장 삭제", icon=":material/delete:"):
        target = st.selectbox("삭제할 사업장", sites["id"].tolist(), format_func=lambda i: sites.set_index("id").loc[i, "name"])
        st.warning("점검 결과, 증빙 파일, 시정조치가 모두 삭제되며 복구할 수 없습니다.")
        confirmed = st.checkbox("삭제 내용을 확인했습니다.")
        if st.button("사업장 삭제", disabled=not confirmed, type="primary"):
            execute("DELETE FROM sites WHERE id = ?", (int(target),))
            shutil.rmtree(EVIDENCE_DIR / str(int(target)), ignore_errors=True)
            st.session_state.pop("site_id", None)
            st.rerun()


# ---------------------------------------------------------------------------
# 앱 진입점
# ---------------------------------------------------------------------------
def app_password() -> str:
    """Streamlit secrets의 app_password를 우선 사용하고, 없으면 초기 비밀번호를 쓴다."""
    try:
        return str(st.secrets.get("app_password", DEFAULT_PASSWORD))
    except Exception:  # secrets.toml이 없는 환경
        return DEFAULT_PASSWORD


if not st.session_state.get("authenticated"):
    st.warning("⚠️ 본 애플리케이션은 시연 및 테스트용입니다. 입력한 데이터는 서버 재시작 시 초기화될 수 있습니다.")
    st.title("중대재해처벌법 이행 점검")
    with st.form("login"):
        password = st.text_input("비밀번호를 입력하세요", type="password")
        submitted = st.form_submit_button("로그인", type="primary", icon=":material/login:")
    if submitted:
        if hmac.compare_digest(password.encode("utf-8"), app_password().encode("utf-8")):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("비밀번호가 올바르지 않습니다.")
    st.stop()

init_db()
sites_df = load_sites()

with st.sidebar:
    st.header(":material/health_and_safety: 중대재해 이행 점검")
    if st.button("로그아웃", icon=":material/logout:", width="stretch"):
        st.session_state.clear()
        st.rerun()
    if not sites_df.empty:
        ids = sites_df["id"].tolist()
        if st.session_state.get("site_id") not in ids:
            st.session_state["site_id"] = ids[0]
        site_id = st.selectbox(
            "사업장", ids, key="site_id", format_func=lambda i: sites_df.set_index("id").loc[i, "name"]
        )
        today = date.today()
        year = st.selectbox("연도", list(range(today.year - 3, today.year + 2)), index=3, key="year")
        half = st.segmented_control("반기", ["상반기", "하반기"], default="상반기" if today.month <= 6 else "하반기", key="half")
        st.session_state["site"] = sites_df.set_index("id", drop=False).loc[site_id]
        st.session_state["period"] = f"{year}년 {half or '상반기'}"

if sites_df.empty:
    pages = [st.Page(page_sites, title="사업장 설정", icon=":material/settings:", url_path="sites")]
else:
    pages = [
        st.Page(page_dashboard, title="대시보드", icon=":material/dashboard:", url_path="dashboard", default=True),
        st.Page(page_checklist, title="이행 점검", icon=":material/fact_check:", url_path="checklist"),
        st.Page(page_evidence, title="증빙 자료", icon=":material/folder_open:", url_path="evidence"),
        st.Page(page_actions, title="시정조치", icon=":material/task_alt:", url_path="actions"),
        st.Page(page_report, title="보고서", icon=":material/summarize:", url_path="report"),
        st.Page(page_sites, title="사업장 설정", icon=":material/settings:", url_path="sites"),
    ]

st.warning("⚠️ 본 애플리케이션은 시연 및 테스트용입니다. 입력한 데이터는 서버 재시작 시 초기화될 수 있습니다.")
st.navigation(pages).run()
