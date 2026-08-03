#!/usr/bin/env python3
from __future__ import annotations

import contextlib
import json
import mimetypes
import io
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import lead_hunter_geo

ROOT = Path(__file__).resolve().parent
FRONTEND_DIR = ROOT / "frontend"
LEADS_FILE = ROOT / "leads.json"
HOST = "127.0.0.1"
PORT = 8000

SECTOR_KEYWORDS = {
    "oil and gas": ["oil", "gas", "offshore", "refinery", "petroleum", "rig", "energy"],
    "energy": ["energy", "power", "utilities", "electric", "renewable", "grid"],
    "petrochemical": ["petrochemical", "chemical", "refinery", "process"],
    "mining": ["mining", "mine", "minerals", "quarry"],
    "steel": ["steel", "metals", "metal", "steelworks"],
    "heavy manufacturing": ["manufacturing", "industrial", "factory", "fabrication", "plant"],
    "industrial engineering": ["engineering", "industrial", "process", "automation"],
    "shipbuilding": ["ship", "shipbuilding", "shipyard", "marine", "dock"],
    "defence": ["defence", "defense", "military", "systems", "aerospace"],
    "aerospace": ["aerospace", "aviation", "aircraft", "aero"],
    "offshore": ["offshore", "marine", "subsea", "rig", "platform"],
    "ports & logistics": ["port", "logistics", "freight", "shipping", "terminal"],
    "fabrication": ["fabrication", "fab", "metalwork", "welding"],
    "machinery": ["machinery", "machine", "equipment", "plant"],
    "transport infrastructure": ["transport", "infrastructure", "rail", "road", "civil engineering"],
    "utilities": ["utilities", "water", "electricity", "gas", "power"],
}

CONSUMER_BLACKLIST = [
    "restaurant",
    "cafe",
    "coffee",
    "bar",
    "pub",
    "hotel",
    "cinema",
    "salon",
    "beauty",
    "hair",
    "gym",
    "school",
    "restaurant",
    "pizza",
    "burger",
    "kebab",
    "shop",
    "store",
    "boots",
    "starbucks",
    "wagamama",
    "zizzi",
    "mcdonald",
    "sainsbury",
    "co-op",
    "coop",
    "dfs",
    "jd sports",
    "dreams",
    "halfords",
]


def load_leads() -> list[dict]:
    try:
        return json.loads(LEADS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def normalize_text(value: object) -> str:
    return str(value or "").strip().lower()


def lead_text(lead: dict) -> str:
    geo = lead.get("geo") or {}
    findings = lead.get("findings") or []
    pieces = [
        lead.get("name"),
        lead.get("domain"),
        lead.get("url"),
        geo.get("name"),
        geo.get("address"),
        geo.get("city"),
        geo.get("county"),
        geo.get("postcode"),
        geo.get("country"),
        geo.get("category"),
        geo.get("phone"),
        lead.get("priority"),
    ]
    for finding in findings:
        pieces.extend([finding.get("category"), finding.get("type"), finding.get("message")])
    return " ".join(normalize_text(piece) for piece in pieces if piece)


def score_value(lead: dict) -> int:
    try:
        return int(lead.get("total_score") or 0)
    except Exception:
        return 0


def business_to_result(business: object, source: str) -> dict:
    geo = {
        "name": getattr(business, "name", ""),
        "url": getattr(business, "url", ""),
        "address": getattr(business, "address", ""),
        "city": getattr(business, "city", ""),
        "county": getattr(business, "county", ""),
        "postcode": getattr(business, "postcode", ""),
        "country": getattr(business, "country", "UK"),
        "phone": getattr(business, "phone", ""),
        "lat": getattr(business, "lat", None),
        "lon": getattr(business, "lon", None),
        "source": getattr(business, "source", source),
        "category": getattr(business, "category", ""),
        "distance_km": getattr(business, "distance_km", None),
    }
    url = getattr(business, "url", "") or ""
    return {
        "url": url,
        "domain": lead_hunter_geo.get_domain(url) if url else "",
        "geo": geo,
        "total_score": 0,
        "priority": "low",
        "is_obsolete": False,
        "is_hot_lead": False,
        "source": source,
    }


def normalize_query(value: str) -> str:
    return normalize_text(value).replace("&", " and ")


def lead_matches_sector(lead: dict, sector: str) -> bool:
    if not sector:
        return True
    haystack = lead_text(lead)
    sector_norm = normalize_query(sector)
    keywords = [sector_norm, *SECTOR_KEYWORDS.get(sector_norm, [])]
    return any(normalize_text(keyword) in haystack for keyword in keywords)


def is_consumer_lead(lead: dict) -> bool:
    haystack = lead_text(lead)
    return any(keyword in haystack for keyword in CONSUMER_BLACKLIST)


def discover_live_leads(location: str, sector: str, radius_miles: float) -> list[dict]:
    location = location.strip()
    sector = sector.strip()
    if not location:
        return []

    radius_km = max(1.0, radius_miles) * 1.60934
    base_args = SimpleNamespace(
        csv_input=None,
        source="osm",
        city=location,
        county="",
        country="UK",
        postcode="",
        radius=radius_km,
        category="",
        max_results=20,
        threshold=0,
        hot_threshold=0,
        verbose=False,
        discover_only=True,
        output=None,
        csv=None,
        geojson=None,
    )

    with contextlib.redirect_stdout(io.StringIO()):
        businesses = lead_hunter_geo.discover_businesses(base_args)

    results = [business_to_result(business, "osm") for business in businesses]
    if sector:
        filtered = [lead for lead in results if lead_matches_sector(lead, sector)]
    else:
        filtered = results

    if filtered:
        filtered.sort(key=lambda lead: (lead.get("geo", {}).get("distance_km") is None, lead.get("geo", {}).get("distance_km") or 999999))
        return filtered
    return []


def search_leads(location: str, sector: str, radius_miles: float) -> list[dict]:
    return discover_live_leads(location, sector, radius_miles)


class LeadHunterHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: Path) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content_type, _ = mimetypes.guess_type(str(path))
        content_type = content_type or "application/octet-stream"
        body = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send_file(FRONTEND_DIR / "index.html")
        if parsed.path == "/app.js":
            return self._send_file(FRONTEND_DIR / "app.js")
        if parsed.path == "/styles.css":
            return self._send_file(FRONTEND_DIR / "styles.css")
        if parsed.path == "/api/search":
            query = parse_qs(parsed.query)
            location = query.get("location", [query.get("city", [""])[0]])[0]
            sector = query.get("sector", [query.get("industry", [""])[0]])[0]
            try:
                radius_miles = float(query.get("radius_miles", ["10"])[0] or 10)
            except Exception:
                radius_miles = 10.0
            results = search_leads(location, sector, radius_miles)
            return self._send_json({
                "location": location,
                "sector": sector,
                "radius_miles": radius_miles,
                "count": len(results),
                "results": results,
            })
        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), LeadHunterHandler)
    print(f"Serving on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
