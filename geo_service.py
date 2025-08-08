import os
import time
import json
from urllib import request, error
from typing import Dict, List, Tuple

class GeoService:
    def __init__(self, enabled: bool | None = None, timeout: float | None = None, cache_ttl: int | None = None):
        self.enabled = (enabled if enabled is not None else os.getenv("GEO_ENABLED", "1").lower() in ("1","true","yes"))
        self.timeout = timeout if timeout is not None else float(os.getenv("GEO_TIMEOUT", "3"))
        self.cache_ttl = cache_ttl if cache_ttl is not None else int(os.getenv("GEO_CACHE_TTL", "86400"))
        self.cache: Dict[str, Tuple[float, Dict]] = {}

    def _get_cached(self, ip: str) -> Dict | None:
        if ip in self.cache:
            ts, data = self.cache[ip]
            if (time.time() - ts) < self.cache_ttl:
                return data
        return None

    def _set_cache(self, ip: str, data: Dict):
        self.cache[ip] = (time.time(), data)

    def geolocate_ip(self, ip: str) -> Dict:
        if not self.enabled:
            return {"ip": ip}
        cached = self._get_cached(ip)
        if cached:
            return cached
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,lat,lon,query"
        try:
            with request.urlopen(url, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                data = json.loads(raw)
                if data.get("status") == "success":
                    out = {
                        "ip": data.get("query"),
                        "country": data.get("country"),
                        "countryCode": data.get("countryCode"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                    }
                else:
                    out = {"ip": ip}
        except Exception:
            out = {"ip": ip}
        self._set_cache(ip, out)
        return out

    def geolocate_many(self, ips: List[Tuple[str, int]]) -> Dict:
        points: List[Dict] = []
        countries: Dict[str, int] = {}
        for ip, count in ips:
            info = self.geolocate_ip(ip)
            info["count"] = count
            points.append(info)
            c = info.get("country") or "Unknown"
            countries[c] = countries.get(c, 0) + count
        countries_list = sorted(countries.items(), key=lambda x: x[1], reverse=True)
        return {"points": points, "countries": countries_list}
