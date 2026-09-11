#!/usr/bin/env python3
"""
WEB-IDS23 Option B inference worker

Pipeline:
    Zeek live capture -> conn.log + flowmeter.log -> this worker
    -> predictions.jsonl -> PostgreSQL ml_events.ml_predictions

Perbaikan versi ini:
- Tetap menulis hasil prediksi ke predictions.jsonl.
- Hanya prediksi selain benign yang disimpan ke PostgreSQL.
- Field yang memakai format ECS seperti source.ip, destination.ip, dan ml.predicted_label
  tetap didukung.
- Tabel ml_predictions dan unique index source_id dibuat otomatis jika belum ada.
- Insert database dibuat lebih aman dengan JSON sanitizer agar numpy/pandas/NaN tidak
  membuat insert JSONB gagal.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import math
import os
import signal
import sys
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import pandas as pd

try:
    import psycopg2
    from psycopg2.extras import Json
except ImportError:
    print("Module 'psycopg2' belum terpasang. Install: pip install psycopg2-binary", file=sys.stderr)
    sys.exit(1)

try:
    from dotenv import load_dotenv
except ImportError:
    print("Module 'python-dotenv' belum terpasang. Install: pip install python-dotenv", file=sys.stderr)
    sys.exit(1)


ENV_PATH = Path(__file__).with_name(".env")
load_dotenv(ENV_PATH)


try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except Exception:
    pass


# ============================================================
# Helper functions
# ============================================================

def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json_atomic(path: Path, payload: Dict[str, Any]) -> None:
    ensure_parent(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f)
    tmp.replace(path)


def setup_logging(log_path: Path, level: str = "INFO") -> None:
    ensure_parent(log_path)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[
            logging.FileHandler(log_path, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def now_epoch() -> float:
    return time.time()


def safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    return str(value)


def parse_ip(value: Optional[str]) -> Optional[ipaddress._BaseAddress]:
    if not value:
        return None

    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def ts_to_iso_from_zeek(value: Any) -> Optional[str]:
    if value is None:
        return None

    try:
        ts = pd.to_datetime(float(value), unit="s", utc=True)
        if pd.isna(ts):
            return None
        return ts.isoformat()
    except Exception:
        pass

    try:
        ts = pd.to_datetime(value, utc=True, errors="coerce")
        if pd.isna(ts):
            return None
        return ts.isoformat()
    except Exception:
        return None


def zeek_unescape(token: str) -> str:
    return bytes(token, "utf-8").decode("unicode_escape")


def to_int(value: Any) -> Optional[int]:
    try:
        if value is None or value == "":
            return None
        return int(float(value))
    except Exception:
        return None


def to_float(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        result = float(value)
        if math.isnan(result) or math.isinf(result):
            return None
        return result
    except Exception:
        return None


def first_not_empty(*values: Any) -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def json_safe(value: Any) -> Any:
    """
    Mengubah nilai pandas/numpy/NaN agar aman masuk kolom JSONB PostgreSQL.
    """
    if value is None:
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]

    if hasattr(value, "item"):
        try:
            return json_safe(value.item())
        except Exception:
            pass

    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value

    if isinstance(value, (str, int, bool)):
        return value

    return str(value)


# ============================================================
# Zeek ASCII tailer
# ============================================================

@dataclass
class ZeekHeader:
    separator: str = "\t"
    set_separator: str = ","
    empty_field: str = "(empty)"
    unset_field: str = "-"
    path: Optional[str] = None
    fields: List[str] = field(default_factory=list)
    types: List[str] = field(default_factory=list)


class ZeekAsciiTailer:
    def __init__(
        self,
        file_path: Path,
        state_path: Path,
        start_at_end: bool = True,
    ) -> None:
        self.file_path = file_path
        self.state_path = state_path
        self.start_at_end = start_at_end

        self.fh = None
        self.header = ZeekHeader()
        self.inode: Optional[int] = None
        self.dev: Optional[int] = None
        self.offset: int = 0

    def _load_state(self) -> Dict[str, Any]:
        if not self.state_path.exists():
            return {}

        try:
            with self.state_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _save_state(self) -> None:
        payload = {
            "path": str(self.file_path),
            "inode": self.inode,
            "dev": self.dev,
            "offset": self.offset,
        }
        save_json_atomic(self.state_path, payload)

    def _reset_header(self) -> None:
        self.header = ZeekHeader()

    def _stat(self) -> Optional[os.stat_result]:
        try:
            return self.file_path.stat()
        except FileNotFoundError:
            return None

    def _needs_reopen(self) -> bool:
        if self.fh is None:
            return True

        st = self._stat()
        if st is None:
            return False

        if self.inode != st.st_ino or self.dev != st.st_dev:
            return True

        if self.offset > st.st_size:
            return True

        return False

    def _consume_header_line(self, line: str) -> None:
        line = line.rstrip("\n")
        if not line.startswith("#"):
            return

        if line.startswith("#separator"):
            parts = line.split(None, 1)
            if len(parts) > 1:
                self.header.separator = zeek_unescape(parts[1])
            return

        if line.startswith("#set_separator"):
            parts = line.split(None, 1)
            if len(parts) > 1:
                self.header.set_separator = parts[1]
            return

        if line.startswith("#empty_field"):
            parts = line.split(None, 1)
            if len(parts) > 1:
                self.header.empty_field = parts[1]
            return

        if line.startswith("#unset_field"):
            parts = line.split(None, 1)
            if len(parts) > 1:
                self.header.unset_field = parts[1]
            return

        if line.startswith("#path"):
            parts = line.split(None, 1)
            if len(parts) > 1:
                self.header.path = parts[1]
            return

        if line.startswith("#open") or line.startswith("#close"):
            return

        if line.startswith("#fields"):
            payload = line[len("#fields"):].lstrip(" \t")
            self.header.fields = payload.split(self.header.separator)
            return

        if line.startswith("#types"):
            payload = line[len("#types"):].lstrip(" \t")
            self.header.types = payload.split(self.header.separator)
            return

    def _parse_record_line(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.rstrip("\n")
        if not line:
            return None

        if line.startswith("#"):
            self._consume_header_line(line)
            return None

        if not self.header.fields:
            logging.warning("Header fields for %s not ready yet; skipping line.", self.file_path)
            return None

        parts = line.split(self.header.separator)
        if len(parts) != len(self.header.fields):
            logging.warning(
                "Field count mismatch in %s: got %s values, expected %s. Line skipped.",
                self.file_path,
                len(parts),
                len(self.header.fields),
            )
            return None

        record: Dict[str, Any] = {}
        for key, raw in zip(self.header.fields, parts):
            if raw == self.header.unset_field:
                record[key] = None
            elif raw == self.header.empty_field:
                record[key] = ""
            else:
                record[key] = raw

        return record

    def _open(self) -> bool:
        st = self._stat()
        if st is None:
            return False

        self._reset_header()
        self.fh = self.file_path.open("r", encoding="utf-8", errors="replace")
        self.inode = st.st_ino
        self.dev = st.st_dev

        first_data_offset = 0
        while True:
            pos = self.fh.tell()
            line = self.fh.readline()
            if not line:
                first_data_offset = self.fh.tell()
                break

            if line.startswith("#"):
                self._consume_header_line(line)
                continue

            first_data_offset = pos
            break

        saved = self._load_state()
        if (
            saved.get("inode") == self.inode
            and saved.get("dev") == self.dev
            and isinstance(saved.get("offset"), int)
            and 0 <= saved["offset"] <= st.st_size
        ):
            self.fh.seek(saved["offset"])
        else:
            if self.start_at_end:
                self.fh.seek(0, os.SEEK_END)
            else:
                self.fh.seek(first_data_offset)

        self.offset = self.fh.tell()
        self._save_state()
        logging.info("Opened %s at offset %s", self.file_path, self.offset)
        return True

    def read_available(self, max_lines: int = 1000) -> List[Dict[str, Any]]:
        if self._needs_reopen():
            if self.fh is not None:
                try:
                    self.fh.close()
                except Exception:
                    pass

                self.fh = None

            if not self._open():
                return []

        out: List[Dict[str, Any]] = []

        while len(out) < max_lines:
            line = self.fh.readline()
            if not line:
                break

            self.offset = self.fh.tell()
            record = self._parse_record_line(line)
            if record is not None:
                out.append(record)

        self._save_state()
        return out


# ============================================================
# Main inference worker
# ============================================================

class WebIDSInferenceWorker:
    def __init__(self, cfg: Dict[str, Any]) -> None:
        self.cfg = cfg
        self.running = True

        artifacts_dir = Path(cfg["artifacts_dir"])

        self.model = joblib.load(artifacts_dir / "model.joblib")
        self.scaler = joblib.load(artifacts_dir / "scaler.joblib")
        self.label_encoder = joblib.load(artifacts_dir / "label_encoder.joblib")
        self.feature_names: List[str] = list(joblib.load(artifacts_dir / "feature_names.joblib"))
        self.preprocess_config: Dict[str, Any] = joblib.load(artifacts_dir / "preprocess_config.joblib")

        self.model_name = cfg.get("model_name", "random_forest_webids23")
        self.model_version = cfg.get("model_version", "1.0.0")

        self.db_enabled = bool(cfg.get("db_enabled", True))
        self.ml_db_config = {
            "host": os.getenv("ML_DB_HOST", cfg.get("ml_db_host", "127.0.0.1")),
            "port": int(os.getenv("ML_DB_PORT", str(cfg.get("ml_db_port", 5432)))),
            "dbname": os.getenv("ML_DB_NAME", cfg.get("ml_db_name", "ml_events")),
            "user": os.getenv("ML_DB_USER", cfg.get("ml_db_user", "postgres")),
            "password": os.getenv("ML_DB_PASS", cfg.get("ml_db_pass", "wazuh123")),
        }

        self.output_path = Path(cfg["output_jsonl"])
        ensure_parent(self.output_path)

        state_dir = Path(cfg["state_dir"])
        state_dir.mkdir(parents=True, exist_ok=True)

        self.conn_tailer = ZeekAsciiTailer(
            file_path=Path(cfg["conn_log_path"]),
            state_path=state_dir / "conn.state.json",
            start_at_end=cfg.get("start_at_end", True),
        )

        self.flow_tailer = ZeekAsciiTailer(
            file_path=Path(cfg["flowmeter_log_path"]),
            state_path=state_dir / "flowmeter.state.json",
            start_at_end=cfg.get("start_at_end", True),
        )

        self.poll_interval_seconds = float(cfg.get("poll_interval_seconds", 1.0))
        self.batch_size = int(cfg.get("batch_size", 500))
        self.conn_cache_ttl_seconds = int(cfg.get("conn_cache_ttl_seconds", 900))
        self.pending_flow_ttl_seconds = int(cfg.get("pending_flow_ttl_seconds", 600))

        self.internal_networks = [ipaddress.ip_network(x) for x in cfg["internal_networks"]]

        self.skip_local_noise = bool(cfg.get("skip_local_noise", True))
        self.write_only_non_benign = bool(cfg.get("write_only_non_benign", True))
        self.skip_external_external = bool(cfg.get("skip_external_external", False))

        self.conn_cache: Dict[str, Dict[str, Any]] = {}
        self.pending_flows: Dict[str, Dict[str, Any]] = {}

        self.scaled_numerical_cols = [
            col for col in self.preprocess_config["numerical_cols"] if col in self.feature_names
        ]
        self.service_dummy_cols = [c for c in self.feature_names if c.startswith("service_")]
        self.direction_dummy_cols = [c for c in self.feature_names if c.startswith("traffic_direction_")]

        self.service_dummy_map = {
            c[len("service_"):]: c for c in self.service_dummy_cols
        }
        self.direction_dummy_map = {
            c[len("traffic_direction_"):]: c for c in self.direction_dummy_cols
        }
        self.known_direction_categories = set(self.direction_dummy_map.keys())

        self.common_server_ports = {
            20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
            143, 161, 162, 389, 443, 445, 465, 514, 587, 631, 993, 995, 1433, 1521,
            1723, 1883, 2049, 2375, 2376, 3306, 3389, 5060, 5432, 5672, 5900, 6379,
            8080, 8443, 9200, 9300, 11211, 27017,
        }

        if self.db_enabled:
            self._init_database()

        logging.info("Loaded %s feature columns.", len(self.feature_names))
        logging.info(
            "ML PostgreSQL target: %s:%s/%s",
            self.ml_db_config["host"],
            self.ml_db_config["port"],
            self.ml_db_config["dbname"],
        )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    def _init_database(self) -> None:
        """
        Membuat tabel dan unique index jika belum ada.
        Jika tabel sudah ada, perintah ini aman dijalankan ulang.
        """
        conn = psycopg2.connect(**self.ml_db_config)

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ml_predictions (
                            id BIGSERIAL PRIMARY KEY,
                            timestamp TIMESTAMPTZ DEFAULT NOW(),
                            source_id TEXT,
                            uid TEXT,
                            source_ip INET,
                            source_port INTEGER,
                            destination_ip INET,
                            destination_port INTEGER,
                            protocol TEXT,
                            service TEXT,
                            traffic_direction TEXT,
                            duration DOUBLE PRECISION,
                            orig_bytes BIGINT,
                            resp_bytes BIGINT,
                            orig_pkts BIGINT,
                            resp_pkts BIGINT,
                            model_name TEXT,
                            model_version TEXT,
                            predicted_label TEXT,
                            predicted_class TEXT,
                            confidence DOUBLE PRECISION,
                            is_attack BOOLEAN,
                            probabilities JSONB,
                            features JSONB,
                            raw_event JSONB,
                            created_at TIMESTAMPTZ DEFAULT NOW()
                        );
                    """)

                    cur.execute("""
                        CREATE UNIQUE INDEX IF NOT EXISTS unique_ml_prediction_source_id
                        ON ml_predictions (source_id)
                        WHERE source_id IS NOT NULL;
                    """)

                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_ml_predictions_timestamp
                        ON ml_predictions (timestamp DESC);
                    """)

                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_ml_predictions_predicted_label
                        ON ml_predictions (predicted_label);
                    """)

                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_ml_predictions_is_attack
                        ON ml_predictions (is_attack);
                    """)

        finally:
            conn.close()

    # --------------------------------------------------------
    # IP helpers
    # --------------------------------------------------------

    def _is_internal(self, ip_value: Optional[str]) -> bool:
        ip_obj = parse_ip(ip_value)
        if ip_obj is None:
            return False

        return any(ip_obj in net for net in self.internal_networks)

    def _is_noise_ip(self, ip_value: Optional[str]) -> bool:
        ip_obj = parse_ip(ip_value)
        if ip_obj is None:
            return False

        if ip_value == "255.255.255.255":
            return True

        if ip_obj.is_multicast:
            return True

        if getattr(ip_obj, "version", None) == 6 and ip_obj.is_link_local:
            return True

        return False

    # --------------------------------------------------------
    # Role and traffic direction mapping
    # --------------------------------------------------------

    def _normalize_service(self, value: Optional[str]) -> str:
        if value is None or value == "":
            return self.preprocess_config["service_fill_value"]

        return str(value)

    def _infer_role_from_ports(
        self,
        orig_p: Optional[int],
        resp_p: Optional[int],
        service: str,
    ) -> str:
        service_known = service not in ("", "Unknown", None)

        if service_known:
            return "client->server"

        if orig_p is None and resp_p is None:
            return "client->server"

        if resp_p in self.common_server_ports and (orig_p is None or orig_p > 1024):
            return "client->server"

        if orig_p in self.common_server_ports and (resp_p is None or resp_p > 1024):
            return "server->client"

        if resp_p is not None and resp_p <= 1024 and (orig_p is None or orig_p > resp_p):
            return "client->server"

        if orig_p is not None and orig_p <= 1024 and (resp_p is None or resp_p > orig_p):
            return "server->client"

        return "client->server"

    def _pick_first_known_direction(self, candidates: List[str]) -> Optional[str]:
        for candidate in candidates:
            if candidate in self.known_direction_categories:
                return candidate

        return None

    def _derive_training_direction(
        self,
        orig_h: Optional[str],
        resp_h: Optional[str],
        orig_p: Optional[int],
        resp_p: Optional[int],
        service: str,
    ) -> Optional[str]:
        orig_internal = self._is_internal(orig_h)
        resp_internal = self._is_internal(resp_h)

        role = self._infer_role_from_ports(orig_p, resp_p, service)

        if orig_internal and resp_internal:
            if role == "server->client":
                candidates = ["server->client", "client->server"]
            else:
                candidates = ["client->server", "server->client"]

            return self._pick_first_known_direction(candidates)

        if orig_internal and not resp_internal:
            if role == "server->client":
                candidates = ["server->internet", "client->internet", "server->client"]
            else:
                candidates = ["client->internet", "server->internet", "client->server"]

            return self._pick_first_known_direction(candidates)

        if not orig_internal and resp_internal:
            if role == "server->client":
                candidates = ["internet->client", "server->client", "internet->server"]
            else:
                candidates = ["internet->server", "internet->client", "client->server"]

            return self._pick_first_known_direction(candidates)

        candidates = ["internet->internet", "external->external"]
        return self._pick_first_known_direction(candidates)

    # --------------------------------------------------------
    # Cache cleanup
    # --------------------------------------------------------

    def _cleanup_caches(self) -> None:
        now = now_epoch()

        stale_conn = [
            uid for uid, value in self.conn_cache.items()
            if now - value.get("_seen_at", now) > self.conn_cache_ttl_seconds
        ]
        for uid in stale_conn:
            self.conn_cache.pop(uid, None)

        stale_pending = [
            uid for uid, value in self.pending_flows.items()
            if now - value.get("_seen_at", now) > self.pending_flow_ttl_seconds
        ]
        for uid in stale_pending:
            self.pending_flows.pop(uid, None)

    # --------------------------------------------------------
    # Conn metadata
    # --------------------------------------------------------

    def _build_conn_meta(self, conn_record: Dict[str, Any]) -> Dict[str, Any]:
        src_ip = safe_str(conn_record.get("id.orig_h"))
        dst_ip = safe_str(conn_record.get("id.resp_h"))
        service = self._normalize_service(conn_record.get("service"))
        orig_p = to_int(conn_record.get("id.orig_p"))
        resp_p = to_int(conn_record.get("id.resp_p"))

        training_direction = self._derive_training_direction(
            orig_h=src_ip,
            resp_h=dst_ip,
            orig_p=orig_p,
            resp_p=resp_p,
            service=service,
        )

        meta = {
            "uid": safe_str(conn_record.get("uid")),
            "ts": conn_record.get("ts"),
            "id.orig_h": src_ip,
            "id.resp_h": dst_ip,
            "id.orig_p": orig_p,
            "id.resp_p": resp_p,
            "proto": safe_str(conn_record.get("proto")),
            "service": service,
            "traffic_direction": training_direction,
            "_seen_at": now_epoch(),
        }
        return meta

    # --------------------------------------------------------
    # Filtering
    # --------------------------------------------------------

    def _should_skip_flow(self, meta: Dict[str, Any]) -> bool:
        src_ip = meta.get("id.orig_h")
        dst_ip = meta.get("id.resp_h")

        if self.skip_local_noise:
            if self._is_noise_ip(src_ip) or self._is_noise_ip(dst_ip):
                return True

        if self.skip_external_external:
            if (not self._is_internal(src_ip)) and (not self._is_internal(dst_ip)):
                return True

        return False

    # --------------------------------------------------------
    # Preprocessing
    # --------------------------------------------------------

    def _apply_manual_one_hot(self, df: pd.DataFrame) -> pd.DataFrame:
        for col in self.service_dummy_cols + self.direction_dummy_cols:
            if col not in df.columns:
                df[col] = 0

        service_value = safe_str(df.at[0, "service"]) or self.preprocess_config["service_fill_value"]
        direction_value = safe_str(df.at[0, "traffic_direction"])

        service_col = self.service_dummy_map.get(service_value)
        if service_col:
            df.at[0, service_col] = 1

        direction_col = self.direction_dummy_map.get(direction_value)
        if direction_col:
            df.at[0, direction_col] = 1

        for cat_col in self.preprocess_config["categorical_cols"]:
            if cat_col in df.columns:
                df = df.drop(columns=[cat_col])

        return df

    def _prepare_model_row(
        self,
        flow_record: Dict[str, Any],
        conn_meta: Dict[str, Any],
    ) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        merged = dict(flow_record)
        merged.update(conn_meta)

        meta = {
            "uid": safe_str(merged.get("uid")),
            "ts": merged.get("ts"),
            "id.orig_h": safe_str(merged.get("id.orig_h")),
            "id.resp_h": safe_str(merged.get("id.resp_h")),
            "id.orig_p": to_int(merged.get("id.orig_p")),
            "id.resp_p": to_int(merged.get("id.resp_p")),
            "proto": safe_str(merged.get("proto")),
            "service": self._normalize_service(merged.get("service")),
            "traffic_direction": safe_str(merged.get("traffic_direction")),
            "duration": to_float(first_not_empty(merged.get("duration"), merged.get("flow_duration"))),
            "orig_bytes": to_int(first_not_empty(merged.get("orig_bytes"), merged.get("orig_ip_bytes"))),
            "resp_bytes": to_int(first_not_empty(merged.get("resp_bytes"), merged.get("resp_ip_bytes"))),
            "orig_pkts": to_int(first_not_empty(merged.get("orig_pkts"), merged.get("orig_pkts_total"))),
            "resp_pkts": to_int(first_not_empty(merged.get("resp_pkts"), merged.get("resp_pkts_total"))),
        }

        merged["service"] = meta["service"]
        merged["traffic_direction"] = meta["traffic_direction"]

        df = pd.DataFrame([merged])

        if "ts" in df.columns:
            try:
                df["ts"] = pd.to_datetime(df["ts"].astype(float), unit="s", utc=True, errors="coerce")
            except Exception:
                df["ts"] = pd.to_datetime(df["ts"], utc=True, errors="coerce")

        df = self._apply_manual_one_hot(df)

        drop_cols = [c for c in self.preprocess_config["drop_cols_before_model"] if c in df.columns]
        df = df.drop(columns=drop_cols, errors="ignore")

        for col in self.feature_names:
            if col not in df.columns:
                df[col] = 0

        df = df.reindex(columns=self.feature_names)

        for col in df.columns:
            if col in self.scaled_numerical_cols:
                df[col] = pd.to_numeric(df[col], errors="coerce")
            elif str(df[col].dtype) == "bool":
                df[col] = df[col].astype(int)

        for col in self.scaled_numerical_cols:
            df[col] = df[col].fillna(0.0)

        if self.scaled_numerical_cols:
            df[self.scaled_numerical_cols] = self.scaler.transform(df[self.scaled_numerical_cols])

        for col in df.columns:
            if df[col].dtype == object:
                try:
                    df[col] = pd.to_numeric(df[col], errors="raise")
                except Exception:
                    pass

        return df, meta

    # --------------------------------------------------------
    # Prediction + PostgreSQL
    # --------------------------------------------------------

    def _is_benign_label(self, label: Any) -> bool:
        return str(label or "").strip().lower() == "benign"

    def _build_probabilities(self, X: pd.DataFrame) -> Tuple[Optional[float], Dict[str, float]]:
        confidence = None
        probabilities: Dict[str, float] = {}

        if not hasattr(self.model, "predict_proba"):
            return confidence, probabilities

        try:
            proba = self.model.predict_proba(X)[0]
            confidence = float(max(proba))

            classes = getattr(self.model, "classes_", [])
            for encoded_class, value in zip(classes, proba):
                try:
                    label = self.label_encoder.inverse_transform([encoded_class])[0]
                except Exception:
                    label = str(encoded_class)

                probabilities[str(label)] = float(value)

        except Exception:
            confidence = None
            probabilities = {}

        return confidence, probabilities

    def _predict_one(
        self,
        flow_record: Dict[str, Any],
        conn_meta: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        X, meta = self._prepare_model_row(flow_record, conn_meta)

        pred_encoded = self.model.predict(X)[0]
        pred_label = str(self.label_encoder.inverse_transform([pred_encoded])[0])

        if self.write_only_non_benign and self._is_benign_label(pred_label):
            return None

        confidence, probabilities = self._build_probabilities(X)

        features = {}
        for col in X.columns:
            features[col] = json_safe(X.iloc[0][col])

        event = {
            "@timestamp": ts_to_iso_from_zeek(meta["ts"]) or pd.Timestamp.utcnow().isoformat(),
            "event.dataset": "webids.prediction",
            "event.kind": "event",
            "zeek.uid": meta["uid"],
            "source.ip": meta["id.orig_h"],
            "source.port": meta["id.orig_p"],
            "destination.ip": meta["id.resp_h"],
            "destination.port": meta["id.resp_p"],
            "network.transport": meta["proto"],
            "network.service": meta["service"],
            "webids.traffic_direction": meta["traffic_direction"],
            "flow.duration": meta["duration"],
            "source.bytes": meta["orig_bytes"],
            "destination.bytes": meta["resp_bytes"],
            "source.packets": meta["orig_pkts"],
            "destination.packets": meta["resp_pkts"],
            "ml.predicted_label": pred_label,
            "ml.predicted_class": pred_label,
            "ml.confidence": confidence,
            "ml.is_attack": not self._is_benign_label(pred_label),
            "ml.probabilities": probabilities,
            "ml.model_name": self.model_name,
            "ml.model_version": self.model_version,
            "ml.features": features,
        }
        return json_safe(event)

    def _save_event_to_database(self, event: Dict[str, Any]) -> bool:
        if not self.db_enabled:
            return False

        predicted_label = event.get("ml.predicted_label")
        if self._is_benign_label(predicted_label):
            return False

        source_id = event.get("zeek.uid")
        if not source_id:
            source_id = "|".join([
                str(event.get("@timestamp") or ""),
                str(event.get("source.ip") or ""),
                str(event.get("destination.ip") or ""),
                str(event.get("ml.predicted_label") or ""),
            ])

        conn = psycopg2.connect(**self.ml_db_config)

        try:
            with conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ml_predictions (
                            timestamp,
                            source_id,
                            uid,
                            source_ip,
                            source_port,
                            destination_ip,
                            destination_port,
                            protocol,
                            service,
                            traffic_direction,
                            duration,
                            orig_bytes,
                            resp_bytes,
                            orig_pkts,
                            resp_pkts,
                            model_name,
                            model_version,
                            predicted_label,
                            predicted_class,
                            confidence,
                            is_attack,
                            probabilities,
                            features,
                            raw_event
                        ) VALUES (
                            COALESCE(%s::timestamptz, NOW()),
                            %s,
                            %s,
                            NULLIF(%s, '')::inet,
                            %s,
                            NULLIF(%s, '')::inet,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        ON CONFLICT (source_id) WHERE source_id IS NOT NULL DO NOTHING
                        """,
                        (
                            event.get("@timestamp"),
                            source_id,
                            event.get("zeek.uid"),
                            event.get("source.ip"),
                            event.get("source.port"),
                            event.get("destination.ip"),
                            event.get("destination.port"),
                            event.get("network.transport"),
                            event.get("network.service"),
                            event.get("webids.traffic_direction"),
                            event.get("flow.duration"),
                            event.get("source.bytes"),
                            event.get("destination.bytes"),
                            event.get("source.packets"),
                            event.get("destination.packets"),
                            event.get("ml.model_name"),
                            event.get("ml.model_version"),
                            event.get("ml.predicted_label"),
                            event.get("ml.predicted_class"),
                            event.get("ml.confidence"),
                            event.get("ml.is_attack"),
                            Json(json_safe(event.get("ml.probabilities", {}))),
                            Json(json_safe(event.get("ml.features", {}))),
                            Json(json_safe(event)),
                        ),
                    )

                    return cur.rowcount == 1

        finally:
            conn.close()

    def _write_event(self, event: Dict[str, Any]) -> None:
        event = json_safe(event)

        ensure_parent(self.output_path)
        with self.output_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

        try:
            inserted = self._save_event_to_database(event)
            if inserted:
                logging.info(
                    "Inserted ML prediction to PostgreSQL uid=%s label=%s",
                    event.get("zeek.uid"),
                    event.get("ml.predicted_label"),
                )
            else:
                logging.info(
                    "ML prediction not inserted or duplicate uid=%s label=%s",
                    event.get("zeek.uid"),
                    event.get("ml.predicted_label"),
                )
        except Exception as e:
            logging.exception("Failed to insert ML prediction to PostgreSQL: %s", e)

    # --------------------------------------------------------
    # Handlers
    # --------------------------------------------------------

    def _handle_conn_records(self, records: List[Dict[str, Any]]) -> None:
        for record in records:
            uid = safe_str(record.get("uid"))
            if not uid:
                continue

            meta = self._build_conn_meta(record)
            self.conn_cache[uid] = meta

            pending = self.pending_flows.pop(uid, None)
            if pending is not None:
                if self._should_skip_flow(meta):
                    continue

                event = self._predict_one(pending, meta)
                if event is not None:
                    self._write_event(event)
                    logging.info(
                        "Predicted pending flow uid=%s label=%s",
                        uid,
                        event["ml.predicted_label"],
                    )

    def _handle_flow_records(self, records: List[Dict[str, Any]]) -> None:
        for record in records:
            uid = safe_str(record.get("uid"))
            if not uid:
                continue

            record["_seen_at"] = now_epoch()

            conn_meta = self.conn_cache.get(uid)
            if conn_meta is None:
                self.pending_flows[uid] = record
                continue

            if self._should_skip_flow(conn_meta):
                continue

            event = self._predict_one(record, conn_meta)
            if event is not None:
                self._write_event(event)
                logging.info("Predicted flow uid=%s label=%s", uid, event["ml.predicted_label"])

    # --------------------------------------------------------
    # Main loop
    # --------------------------------------------------------

    def run(self) -> None:
        logging.info("Inference worker started.")
        while self.running:
            try:
                conn_records = self.conn_tailer.read_available(max_lines=self.batch_size)
                if conn_records:
                    self._handle_conn_records(conn_records)

                flow_records = self.flow_tailer.read_available(max_lines=self.batch_size)
                if flow_records:
                    self._handle_flow_records(flow_records)

                self._cleanup_caches()

                if not conn_records and not flow_records:
                    time.sleep(self.poll_interval_seconds)

            except KeyboardInterrupt:
                self.running = False
                break
            except Exception as e:
                logging.exception("Unhandled error in worker loop: %s", e)
                time.sleep(self.poll_interval_seconds)

        logging.info("Inference worker stopped.")


# ============================================================
# Entrypoint
# ============================================================

def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} /path/to/config.json")
        return 1

    config_path = Path(sys.argv[1])
    cfg = load_json(config_path)

    setup_logging(
        log_path=Path(cfg["worker_log_path"]),
        level=cfg.get("log_level", "INFO"),
    )

    worker = WebIDSInferenceWorker(cfg)

    def _stop_handler(signum, frame):  # noqa: ARG001
        worker.running = False

    signal.signal(signal.SIGINT, _stop_handler)
    signal.signal(signal.SIGTERM, _stop_handler)

    worker.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

