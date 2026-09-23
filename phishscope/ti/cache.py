import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path

from .models import IOCType, TIResult, TIStatus


class TICache:
    def __init__(self, cache_file: Path | None = None, ttl_seconds: int = 86400):
        if cache_file is None:
            self.cache_file = Path.home() / ".phishscope" / "ti_cache.json"
        else:
            self.cache_file = Path(cache_file)
        self.ttl_seconds = ttl_seconds

    def _get_key(self, provider: str, ioc_type: IOCType, ioc_value: str) -> str:
        raw = f"{provider}:{ioc_type.value}:{ioc_value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _load(self) -> dict:
        if not self.cache_file.exists():
            return {}
        try:
            return json.loads(self.cache_file.read_text())
        except (OSError, json.JSONDecodeError):
            return {}

    def _save(self, data: dict):
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.cache_file.write_text(json.dumps(data))
            self.cache_file.chmod(0o600)
        except OSError:
            pass

    def get(self, provider: str, ioc_type: IOCType, ioc_value: str) -> TIResult | None:
        key = self._get_key(provider, ioc_type, ioc_value)
        data = self._load()
        if key in data:
            entry = data[key]
            if time.time() - entry.get("timestamp", 0) <= self.ttl_seconds:
                try:
                    return TIResult(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        provider_name=provider,
                        status=TIStatus(entry["status"]),
                        timestamp=entry["timestamp"],
                        cache_hit=True,
                        malicious=entry.get("malicious"),
                        suspicious=entry.get("suspicious"),
                        harmless=entry.get("harmless"),
                        timeout=entry.get("timeout"),
                        undetected=entry.get("undetected"),
                        total_engines=entry.get("total_engines")
                    )
                except (ValueError, KeyError):
                    return None
        return None

    def set(self, result: TIResult):
        if result.status not in (TIStatus.LOOKUP_SUCCESS, TIStatus.NO_RESULT):
            return

        key = self._get_key(result.provider_name, result.ioc_type, result.ioc_value)
        data = self._load()

        res_dict = asdict(result)
        # Remove ioc_value to prevent plaintext exposure
        res_dict.pop("ioc_value", None)
        # Also remove provider and ioc_type since they are part of the key definition
        res_dict.pop("provider_name", None)
        res_dict.pop("ioc_type", None)
        res_dict.pop("cache_hit", None)

        res_dict["status"] = result.status.value

        data[key] = res_dict
        self._save(data)
