#!/usr/bin/env python3
"""
================================================================================
LEAD HUNTER GEO — Wyszukiwarka Przestarzałych Stron WWW z Geolokalizacją
================================================================================
Generator leadów z filtrowaniem po: mieście, okolicy, województwie, hrabstwie,
kraju, kodzie pocztowym. Główny target: rynek UK.

Autor: Forsa Design (https://forsadesign.co.uk)
Wersja: 2.0.0

Instalacja zależności:
    pip install requests beautifulsoup4 lxml python-whois dnspython

Przykłady UK:
    python lead_hunter_geo.py --city "London" --country "UK" --radius 5 --category restaurant --max-results 25
    python lead_hunter_geo.py --city "Manchester" --source yell --max-results 30
    python lead_hunter_geo.py --csv-input firms.csv --city "Birmingham" --output leads.json
    python lead_hunter_geo.py --city "Glasgow" --country "UK" --discover-only --output firms.json
================================================================================
"""

import argparse
import csv
import json
import math
import random
import re
import socket
import ssl
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

VERSION = "2.0.0"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.0 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.0"
)
TIMEOUT = 15
NOMINATIM_URL = "https://nominatim.openstreetmap.org"
OVERPASS_URLS = [
    "https://overpass-api.de/api/interpreter",
    "https://lz4.overpass-api.de/api/interpreter",
    "https://overpass.openstreetmap.fr/api/interpreter",
]

OBSOLETE_THRESHOLD = 55
HOT_LEAD_THRESHOLD = 75

WEIGHTS = {
    "ssl": 10, "responsive": 15, "tech_stack": 20, "performance": 15,
    "seo": 10, "design_age": 15, "security": 10, "cms_age": 5,
}

OBSOLETE_TECH_SIGNATURES = [
    ("jquery_1x", r'jquery[/-]?1\.[0-9]', 15),
    ("jquery_2x", r'jquery[/-]?2\.[0-9]', 10),
    ("flash", r'\.swf|flash|shockwave', 20),
    ("ie_hacks", r'\[if IE\]|ie=edge|x-ua-compatible', 10),
    ("vbscript", r'vbscript', 15),
    ("applet", r'<applet', 15),
    ("marquee", r'<marquee', 10),
    ("blink", r'<blink', 10),
    ("frameset", r'<frameset', 15),
    ("font_tag", r'<font\s', 5),
    ("center_tag", r'<center\s*>', 5),
    ("table_layout", r'<table[^>]*>.*?(?:width|height)\s*=\s*"\d+%?"', 8),
    ("inline_styles", r'style\s*=\s*"[^"]*"', 3),
    ("old_bootstrap", r'bootstrap[/-]?2\.|bootstrap[/-]?3\.0', 10),
    ("mootools", r'mootools', 12),
    ("prototype", r'prototype\.js', 12),
    ("scriptaculous", r'scriptaculous', 10),
    ("dojo", r'dojo\.js|dojo/', 10),
    ("yui", r'yui', 10),
    ("modernizr_old", r'modernizr[/-]?2\.', 5),
]

MODERN_TECH_SIGNATURES = [
    ("nextjs", r'__NEXT_DATA__|_next/', -10),
    ("nuxtjs", r'__NUXT__|_nuxt/', -10),
    ("react", r'react\.js|react-dom', -8),
    ("vue", r'vue\.js|__VUE__', -8),
    ("angular", r'angular', -8),
    ("tailwind", r'tailwind', -8),
    ("astro", r'astro', -8),
    ("svelte", r'svelte', -8),
    ("webp", r'\.webp', -5),
    ("avif", r'\.avif', -5),
    ("lazy_loading", r'loading\s*=\s*"lazy"', -5),
    ("service_worker", r'service-worker|navigator\.serviceWorker', -5),
    ("webmanifest", r'\.webmanifest', -3),
    ("http3", r'h3-|quic', -5),
]


@dataclass
class GeoBusiness:
    name: str
    url: str
    address: str = ""
    city: str = ""
    county: str = ""
    postcode: str = ""
    country: str = ""
    phone: str = ""
    lat: Optional[float] = None
    lon: Optional[float] = None
    source: str = ""
    category: str = ""
    distance_km: Optional[float] = None


@dataclass
class ScanResult:
    url: str
    domain: str
    timestamp: str
    geo: Optional[GeoBusiness] = None
    status_code: Optional[int] = None
    ssl_score: int = 0
    responsive_score: int = 0
    tech_stack_score: int = 0
    performance_score: int = 0
    seo_score: int = 0
    design_age_score: int = 0
    security_score: int = 0
    cms_age_score: int = 0
    total_score: int = 0
    is_obsolete: bool = False
    is_hot_lead: bool = False
    priority: str = "low"
    findings: List[Dict] = field(default_factory=list)
    tech_detected: List[str] = field(default_factory=list)
    modern_tech_detected: List[str] = field(default_factory=list)
    headers: Dict = field(default_factory=dict)
    page_size_kb: float = 0.0
    load_time_ms: float = 0.0
    ssl_info: Dict = field(default_factory=dict)
    dns_info: Dict = field(default_factory=dict)
    whois_info: Dict = field(default_factory=dict)
    error: Optional[str] = None


class NominatimClient:
    """Darmowy geokoder OpenStreetMap. Rate limit: ~1 req/s."""
    def __init__(self):
        self.last_request = 0

    def _rate_limit(self):
        elapsed = time.time() - self.last_request
        if elapsed < 1.1:
            time.sleep(1.1 - elapsed)
        self.last_request = time.time()

    def geocode(self, query: str, country: str = "") -> Optional[Dict]:
        self._rate_limit()
        q = urllib.parse.quote(query)
        # Nominatim uses ISO-3166 alpha-2: UK must be mapped to GB
        if country and country.upper() == "UK":
            country = "GB"
        url = NOMINATIM_URL + "/search?q=" + q + "&format=json&limit=1&addressdetails=1"
        if country:
            url += "&countrycodes=" + country
        try:
            headers = {
                "User-Agent": f"LeadHunterGeo/{VERSION} (lead research tool; contact: hello@forsadesign.co.uk)",
                "Accept": "application/json",
                "Accept-Language": "en-US,en;q=0.9",
            }
            if REQUESTS_AVAILABLE:
                resp = requests.get(url, headers=headers, timeout=TIMEOUT)
                data = resp.json() if resp.status_code == 200 else []
            else:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
            if data:
                r = data[0]
                bb = r.get("boundingbox", [])
                return {
                    "lat": float(r["lat"]),
                    "lon": float(r["lon"]),
                    "boundingbox": [float(x) for x in bb] if bb else None,
                    "display_name": r.get("display_name", ""),
                    "type": r.get("type", ""),
                    "address": r.get("address", {}),
                }
        except Exception as e:
            print("  [!] Nominatim error:", e)
        return None


class OverpassFinder:
    def __init__(self, nominatim: NominatimClient):
        self.nominatim = nominatim

    def _build_query(self, s, w, n, e, category: str = "") -> str:
        # Wąskie bbox + limit 100 elementów przyspiesza zapytanie i zmniejsza ryzyko 504
        cat_map = {
            "restaurant": '["amenity"="restaurant"]',
            "cafe": '["amenity"="cafe"]',
            "bar": '["amenity"="bar"]',
            "hotel": '["tourism"="hotel"]',
            "shop": '["shop"]',
            "doctor": '["amenity"="doctors"]',
            "dentist": '["amenity"="dentist"]',
            "lawyer": '["office"="lawyer"]',
            "accountant": '["office"="accountant"]',
            "hairdresser": '["shop"="hairdresser"]',
            "car_repair": '["shop"="car_repair"]',
            "plumber": '["craft"="plumber"]',
            "electrician": '["craft"="electrician"]',
            "estate_agent": '["office"="estate_agent"]',
            "beauty": '["shop"="beauty"]',
        }
        cf = cat_map.get(category.lower(), "") if category else ""
        template = """[out:json][timeout:120][maxsize:104857600];
(
  node["website"]CF(S,W,N,E);
  way["website"]CF(S,W,N,E);
  relation["website"]CF(S,W,N,E);
);
out body 100;
>;
out skel qt;"""
        return template.replace("CF", cf).replace("S", str(s)).replace("W", str(w)).replace("N", str(n)).replace("E", str(e))

    def search(self, city: str, country: str = "", radius_km: float = 10.0,
               category: str = "", max_results: int = 50) -> List[GeoBusiness]:
        print("\n[🌍] Geokodowanie:", city + ",", country, "...")
        geo = self.nominatim.geocode(city, country)
        if not geo:
            print("  [✗] Nie udało się zgeokodować:", city)
            return []

        clat, clon = geo["lat"], geo["lon"]
        print("  [✓] Współrzędne: %.4f, %.4f" % (clat, clon))

        dlat = radius_km / 111.0
        dlon = radius_km / (111.0 * math.cos(math.radians(clat)))
        s, n = clat - dlat, clat + dlat
        w, e = clon - dlon, clon + dlon

        print("  [🌐] Zapytanie Overpass (bbox: %.3f,%.3f,%.3f,%.3f)..." % (s, w, n, e))

        query = self._build_query(s, w, n, e, category)
        data = None
        last_error = None
        for overpass_url in OVERPASS_URLS:
            for attempt in range(2):
                try:
                    req = urllib.request.Request(
                        overpass_url,
                        data=query.encode("utf-8"),
                        headers={
                            "User-Agent": "LeadHunter/" + VERSION,
                            "Content-Type": "application/x-www-form-urlencoded"
                        }
                    )
                    # Krótki timeout po stronie klienta — nie czekamy bez sensu na 504
                    with urllib.request.urlopen(req, timeout=30) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                        break
                except Exception as e:
                    last_error = e
                    print("  [!] %s (próba %d): %s" % (overpass_url, attempt + 1, e))
                    time.sleep(1.5)
            if data:
                break
        if not data:
            print("  [✗] Overpass API error:", last_error)
            return []

        businesses = []
        for elem in data.get("elements", []):
            if elem.get("type") not in ("node", "way", "relation"):
                continue
            tags = elem.get("tags", {})
            website = tags.get("website", "").strip()
            if not website:
                continue
            if not website.startswith(("http://", "https://")):
                website = "http://" + website
            skip_domains = ["facebook.com", "instagram.com", "twitter.com",
                            "linkedin.com", "youtube.com", "tiktok.com",
                            "google.com", "amazon.", "ebay."]
            if any(x in website.lower() for x in skip_domains):
                continue

            name = tags.get("name", tags.get("brand", "Unknown"))
            lat = elem.get("lat")
            lon = elem.get("lon")
            if lat is None or lon is None:
                center = elem.get("center", {})
                lat = center.get("lat")
                lon = center.get("lon")

            addr_parts = []
            for k in ["addr:street", "addr:housenumber", "addr:city", "addr:postcode"]:
                if k in tags:
                    addr_parts.append(tags[k])
            address = ", ".join(addr_parts)
            city_val = tags.get("addr:city", "")
            postcode = tags.get("addr:postcode", "")

            distance = None
            if lat and lon:
                distance = haversine(clat, clon, lat, lon)

            businesses.append(GeoBusiness(
                name=name, url=website, address=address, city=city_val,
                postcode=postcode, country=country, lat=lat, lon=lon,
                source="osm", category=category,
                distance_km=round(distance, 2) if distance else None
            ))

        businesses.sort(key=lambda x: (x.distance_km or 99999))
        businesses = businesses[:max_results]
        print("  [✓] Po filtracji:", len(businesses), "unikalnych firm z website")
        return businesses


class YellFinder:
    def __init__(self):
        self.session = requests.Session() if REQUESTS_AVAILABLE else None
        if self.session:
            self.session.headers.update({
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-GB,en;q=0.9",
            })

    def search(self, location: str, category: str = "", max_results: int = 50) -> List[GeoBusiness]:
        if not REQUESTS_AVAILABLE or not BS4_AVAILABLE:
            print("  [!] Yell.com wymaga: pip install requests beautifulsoup4")
            return []

        print("\n[🇬🇧] Yell.com: szukam '" + (category or "businesses") + "' w", location, "...")
        businesses = []
        page = 1

        while len(businesses) < max_results and page <= 5:
            url = self._build_url(location, category, page)
            try:
                resp = self.session.get(url, timeout=TIMEOUT)
                if resp.status_code != 200:
                    break
                soup = BeautifulSoup(resp.text, "lxml")
                listings = soup.find_all("div", class_=re.compile(r"result-\d+|listing"))
                if not listings:
                    listings = soup.select("[data-testid='result-item'], .resultItem")
                if not listings:
                    break

                for listing in listings:
                    biz = self._parse(listing, location)
                    if biz and biz.url and not any(b.url == biz.url for b in businesses):
                        businesses.append(biz)
                        if len(businesses) >= max_results:
                            break
                page += 1
                time.sleep(random.uniform(1.5, 3.0))
            except Exception as e:
                print("  [!] Yell page", page, "error:", e)
                break

        print("  [✓] Znaleziono", len(businesses), "firm na Yell.com")
        return businesses

    def _build_url(self, location: str, category: str, page: int) -> str:
        loc = urllib.parse.quote(location)
        if category:
            cat = urllib.parse.quote(category)
            return "https://www.yell.com/ucs/UcsSearchAction.do?scrambleSeed=123456789&keywords=" + cat + "&location=" + loc + "&pageNum=" + str(page)
        return "https://www.yell.com/ucs/UcsSearchAction.do?scrambleSeed=123456789&location=" + loc + "&pageNum=" + str(page)

    def _parse(self, listing, default_location: str) -> Optional[GeoBusiness]:
        try:
            name_el = listing.find("h2") or listing.find("h3") or listing.find("a", class_=re.compile(r"title|name"))
            name = name_el.get_text(strip=True) if name_el else "Unknown"

            url = ""
            for a in listing.find_all("a", href=True):
                href = a["href"]
                if href.startswith("http") and "yell.com" not in href:
                    url = href
                    break
                elif href.startswith("/") and "website" in href.lower():
                    url = "https://www.yell.com" + href

            if not url:
                text = listing.get_text()
                m = re.search(r"(https?://[^\s<>\'\"]+)", text)
                if m:
                    url = m.group(1)

            addr_el = listing.find("address") or listing.find(class_=re.compile(r"address|location"))
            address = addr_el.get_text(strip=True) if addr_el else ""

            phone_el = listing.find("a", href=re.compile(r"tel:"))
            phone = phone_el.get_text(strip=True) if phone_el else ""

            postcode = ""
            pc_match = re.search(r"[A-Z]{1,2}[0-9][0-9A-Z]?\s*[0-9][A-Z]{2}", address, re.I)
            if pc_match:
                postcode = pc_match.group(0).replace(" ", "")

            if not url:
                return None

            return GeoBusiness(
                name=name, url=url, address=address, city=default_location,
                postcode=postcode, country="UK", phone=phone, source="yell"
            )
        except Exception:
            return None


class CSVImporter:
    def load(self, path: str) -> List[GeoBusiness]:
        businesses = []
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if not row.get("url"):
                    continue
                url = row["url"].strip()
                if not url.startswith(("http://", "https://")):
                    url = "http://" + url
                businesses.append(GeoBusiness(
                    name=row.get("name", "Unknown").strip(),
                    url=url,
                    address=row.get("address", "").strip(),
                    city=row.get("city", "").strip(),
                    county=row.get("county", "").strip(),
                    postcode=row.get("postcode", "").strip(),
                    country=row.get("country", "").strip(),
                    phone=row.get("phone", "").strip(),
                    category=row.get("category", "").strip(),
                    source="csv"
                ))
        return businesses

    def filter_by_location(self, businesses: List[GeoBusiness],
                           city: str = "", county: str = "", country: str = "",
                           postcode_prefix: str = "") -> List[GeoBusiness]:
        filtered = businesses
        if city:
            filtered = [b for b in filtered if city.lower() in b.city.lower()]
        if county:
            filtered = [b for b in filtered if county.lower() in b.county.lower()]
        if country:
            filtered = [b for b in filtered if country.lower() in b.country.lower()]
        if postcode_prefix:
            prefix = postcode_prefix.upper().replace(" ", "")
            filtered = [b for b in filtered if b.postcode.upper().replace(" ", "").startswith(prefix)]
        return filtered


def haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lon2 - lon1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlambda/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def get_domain(url: str) -> str:
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

# =============================================================================
# SKANER
# =============================================================================

def fetch_page(url: str, verbose: bool = False) -> Tuple[Optional[str], Optional[Dict], float]:
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
    if REQUESTS_AVAILABLE:
        try:
            start = time.time()
            resp = requests.get(url, headers=headers, timeout=TIMEOUT, allow_redirects=True)
            load_time = (time.time() - start) * 1000
            return resp.text, dict(resp.headers), load_time
        except Exception as e:
            if verbose:
                print("  [!] requests failed:", e)
    try:
        req = urllib.request.Request(url, headers=headers)
        start = time.time()
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            load_time = (time.time() - start) * 1000
            return html, dict(resp.headers), load_time
    except Exception as e:
        if verbose:
            print("  [!] urllib failed:", e)
    return None, None, 0.0


def check_ssl(domain: str, verbose: bool = False) -> Tuple[int, Dict]:
    info = {"has_ssl": False, "valid": False, "expiry": None, "issuer": None, "days_left": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["has_ssl"] = True
                info["valid"] = True
                info["issuer"] = cert.get("issuer", [])
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = ssl.cert_time_to_seconds(not_after)
                    info["expiry"] = datetime.fromtimestamp(expiry).isoformat()
                    days_left = (expiry - time.time()) / 86400
                    info["days_left"] = round(days_left, 1)
                    if days_left < 0:
                        return 100, info
                    elif days_left < 30:
                        return 80, info
                    elif days_left < 90:
                        return 30, info
                    else:
                        return 0, info
    except ssl.SSLError as e:
        info["error"] = str(e)
        if "certificate verify failed" in str(e):
            return 100, info
        return 70, info
    except socket.timeout:
        info["error"] = "timeout"
        return 50, info
    except Exception as e:
        info["error"] = str(e)
    return 100, info


def check_responsive(html: str) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    if not re.search(r'<meta[^>]*viewport', html, re.I):
        score += 50
        findings.append({"type": "missing_viewport", "severity": "high", "message": "Brak meta viewport — strona nie jest responsywna"})
    if not re.search(r'@media\s', html, re.I):
        score += 30
        findings.append({"type": "no_media_queries", "severity": "medium", "message": "Brak zapytań @media w kodzie"})
    fixed_width = len(re.findall(r'width\s*:\s*\d+px', html, re.I))
    if fixed_width > 5:
        score += min(fixed_width * 2, 20)
        findings.append({"type": "fixed_width", "severity": "low", "message": str(fixed_width) + " elementów ze stałą szerokością w px"})
    return min(score, 100), findings


def check_tech_stack(html: str, headers: Dict) -> Tuple[int, List[str], List[str], List[Dict]]:
    findings = []
    score = 0
    obsolete = []
    modern = []
    html_lower = html.lower()
    for tech_name, pattern, penalty in OBSOLETE_TECH_SIGNATURES:
        if re.search(pattern, html_lower):
            obsolete.append(tech_name)
            score += penalty
            findings.append({"type": "obsolete_tech", "tech": tech_name, "severity": "high" if penalty >= 15 else "medium", "message": "Wykryto przestarzałą technologię: " + tech_name})
    for tech_name, pattern, bonus in MODERN_TECH_SIGNATURES:
        if re.search(pattern, html_lower):
            modern.append(tech_name)
            score += bonus
    server = headers.get("Server", "")
    if "Apache/2.2" in server or "nginx/1.0" in server or "IIS/6" in server or "IIS/7" in server:
        obsolete.append("old_server: " + server)
        score += 15
        findings.append({"type": "old_server", "severity": "medium", "message": "Przestarzały serwer: " + server})
    x_powered = headers.get("X-Powered-By", "")
    if "PHP/5." in x_powered:
        obsolete.append("old_php: " + x_powered)
        score += 20
        findings.append({"type": "old_php", "severity": "high", "message": "Przestarzała wersja PHP: " + x_powered})
    return min(max(score, 0), 100), obsolete, modern, findings


def check_performance(html: str, headers: Dict, load_time_ms: float, page_size_kb: float) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    if load_time_ms > 5000:
        score += 40
        findings.append({"type": "slow_load", "severity": "high", "message": "Czas ładowania: %.0fms (>5s)" % load_time_ms})
    elif load_time_ms > 3000:
        score += 20
        findings.append({"type": "slow_load", "severity": "medium", "message": "Czas ładowania: %.0fms (>3s)" % load_time_ms})
    elif load_time_ms > 1500:
        score += 10
        findings.append({"type": "slow_load", "severity": "low", "message": "Czas ładowania: %.0fms (>1.5s)" % load_time_ms})
    if page_size_kb > 3000:
        score += 20
        findings.append({"type": "heavy_page", "severity": "medium", "message": "Rozmiar strony: %.0fKB (>3MB)" % page_size_kb})
    elif page_size_kb > 1500:
        score += 10
        findings.append({"type": "heavy_page", "severity": "low", "message": "Rozmiar strony: %.0fKB (>1.5MB)" % page_size_kb})
    encoding = headers.get("Content-Encoding", "")
    if not encoding:
        score += 15
        findings.append({"type": "no_compression", "severity": "medium", "message": "Brak kompresji (gzip/brotli)"})
    cache = headers.get("Cache-Control", "")
    if not cache:
        score += 10
        findings.append({"type": "no_cache", "severity": "low", "message": "Brak nagłówków cache-control"})
    img_count = len(re.findall(r'<img', html, re.I))
    lazy_count = len(re.findall(r'loading\s*=\s*"lazy"', html, re.I))
    if img_count > 5 and lazy_count < img_count * 0.3:
        score += 10
        findings.append({"type": "no_lazy_loading", "severity": "low", "message": "Tylko %d/%d obrazków ma lazy loading" % (lazy_count, img_count)})
    return min(score, 100), findings


def check_seo(html: str, headers: Dict, url: str) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    if not re.search(r'<title>[^<]+</title>', html, re.I):
        score += 25
        findings.append({"type": "missing_title", "severity": "high", "message": "Brak tagu <title>"})
    if not re.search(r'<meta[^>]*name\s*=\s*"description"', html, re.I):
        score += 20
        findings.append({"type": "missing_description", "severity": "high", "message": "Brak meta description"})
    if not re.search(r'<link[^>]*rel\s*=\s*"canonical"', html, re.I):
        score += 10
        findings.append({"type": "missing_canonical", "severity": "low", "message": "Brak linku canonical"})
    if not re.search(r'<meta[^>]*property\s*=\s*"og:', html, re.I):
        score += 10
        findings.append({"type": "missing_og", "severity": "low", "message": "Brak tagów Open Graph"})
    if "schema.org" not in html.lower() and "application/ld+json" not in html.lower():
        score += 15
        findings.append({"type": "missing_schema", "severity": "medium", "message": "Brak danych strukturalnych Schema.org"})
    img_tags = re.findall(r'<img[^>]*>', html, re.I)
    missing_alt = sum(1 for img in img_tags if 'alt=' not in img.lower())
    if img_tags and missing_alt / len(img_tags) > 0.5:
        score += 10
        findings.append({"type": "missing_alt", "severity": "low", "message": "%d/%d obrazków bez atrybutu alt" % (missing_alt, len(img_tags))})
    if "sitemap" not in html.lower():
        score += 5
        findings.append({"type": "no_sitemap_ref", "severity": "low", "message": "Brak odniesienia do sitemap"})
    return min(score, 100), findings


def check_design_age(html: str) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    table_layout = len(re.findall(r'<table', html, re.I))
    if table_layout > 3:
        score += 25
        findings.append({"type": "table_layout", "severity": "high", "message": "%d tabel — prawdopodobny layout tabelowy" % table_layout})
    inline_styles = len(re.findall(r'style\s*=\s*"[^"]*"', html, re.I))
    if inline_styles > 20:
        score += 20
        findings.append({"type": "heavy_inline_styles", "severity": "medium", "message": "%d inline styles" % inline_styles})
    if re.search(r'<marquee', html, re.I):
        score += 20
        findings.append({"type": "marquee", "severity": "high", "message": "Wykryto tag <marquee>"})
    if re.search(r'<blink', html, re.I):
        score += 15
        findings.append({"type": "blink", "severity": "high", "message": "Wykryto tag <blink>"})
    if re.search(r'<frameset', html, re.I):
        score += 30
        findings.append({"type": "frameset", "severity": "critical", "message": "Wykryto <frameset> — strona z lat 90."})
    external_css = len(re.findall(r'<link[^>]*stylesheet', html, re.I))
    if external_css == 0:
        score += 15
        findings.append({"type": "no_external_css", "severity": "medium", "message": "Brak zewnętrznych arkuszy CSS"})
    if re.search(r'gradient\.gif|gradient\.png|bg\.gif|bg\.jpg', html, re.I):
        score += 10
        findings.append({"type": "image_gradients", "severity": "low", "message": "Gradienty z obrazków (stara technika)"})
    if re.search(r'width\s*:\s*800px|width\s*:\s*960px|width\s*:\s*1024px', html, re.I):
        score += 15
        findings.append({"type": "fixed_container", "severity": "medium", "message": "Stała szerokość kontenera (~800-1024px)"})
    return min(score, 100), findings


def check_security(headers: Dict, html: str, url: str) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    security_headers = {
        "Strict-Transport-Security": "Brak HSTS",
        "Content-Security-Policy": "Brak CSP",
        "X-Frame-Options": "Brak X-Frame-Options",
        "X-Content-Type-Options": "Brak X-Content-Type-Options",
        "Referrer-Policy": "Brak Referrer-Policy",
    }
    for header, message in security_headers.items():
        if header not in headers:
            score += 12
            findings.append({"type": "missing_security_header", "severity": "medium", "message": message})
    if not url.startswith("https://"):
        score += 30
        findings.append({"type": "no_https", "severity": "high", "message": "Strona bez HTTPS"})
    return min(score, 100), findings


def check_cms_age(html: str, headers: Dict, domain: str) -> Tuple[int, List[Dict]]:
    findings = []
    score = 0
    wp_version = re.search(r'wp-content.*?/\d+\.\d+\.\d+', html)
    if wp_version:
        ver = wp_version.group(0).split("/")[-1]
        try:
            major = int(ver.split(".")[0])
            if major < 5:
                score += 20
                findings.append({"type": "old_wordpress", "severity": "high", "message": "WordPress %s (bardzo stary)" % ver})
            elif major < 6:
                score += 10
                findings.append({"type": "old_wordpress", "severity": "medium", "message": "WordPress %s (stary)" % ver})
        except:
            pass
    generator = re.search(r'<meta[^>]*name\s*=\s*"generator"[^>]*content\s*=\s*"([^"]*)"', html, re.I)
    if generator:
        gen = generator.group(1)
        if "Joomla" in gen and ("1." in gen or "2." in gen or "3.0" in gen):
            score += 20
            findings.append({"type": "old_cms", "severity": "high", "message": "Przestarzały CMS: " + gen})
        elif "Drupal" in gen and ("6" in gen or "7" in gen):
            score += 20
            findings.append({"type": "old_cms", "severity": "high", "message": "Przestarzały CMS: " + gen})
    return min(score, 100), findings


def get_dns_info(domain: str) -> Dict:
    info = {"mx": [], "a": [], "txt": []}
    if not DNS_AVAILABLE:
        return info
    try:
        for rtype in ["A", "MX", "TXT"]:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                info[rtype.lower()] = [str(r) for r in answers]
            except:
                pass
    except Exception:
        pass
    return info


def get_whois_info(domain: str) -> Dict:
    info = {"creation_date": None, "registrar": None, "name_servers": []}
    if not WHOIS_AVAILABLE:
        return info
    try:
        w = whois.whois(domain)
        info["creation_date"] = str(w.creation_date) if w.creation_date else None
        info["registrar"] = w.registrar
        info["name_servers"] = w.name_servers if w.name_servers else []
    except Exception:
        pass
    return info


def scan_url(url: str, geo: Optional[GeoBusiness] = None, verbose: bool = False) -> ScanResult:
    url = normalize_url(url)
    domain = get_domain(url)
    result = ScanResult(url=url, domain=domain, timestamp=datetime.now().isoformat(), geo=geo)

    if verbose:
        print("\n[🔍] Skanowanie:", url)

    html, headers, load_time = fetch_page(url, verbose)
    result.load_time_ms = load_time
    result.headers = headers or {}

    if html is None:
        result.error = "Nie udało się pobrać strony"
        result.total_score = 100
        result.is_obsolete = True
        result.is_hot_lead = True
        result.priority = "critical"
        if verbose:
            print("  [✗] Błąd pobierania — traktowana jako przestarzała")
        return result

    result.page_size_kb = len(html.encode("utf-8")) / 1024
    if verbose:
        print("  [✓] Pobrano: %.1fKB w %.0fms" % (result.page_size_kb, load_time))

    result.ssl_score, result.ssl_info = check_ssl(domain, verbose)
    if result.ssl_score > 0:
        result.findings.append({"category": "ssl", "score": result.ssl_score, "details": result.ssl_info})

    result.responsive_score, resp_findings = check_responsive(html)
    result.findings.extend([{**f, "category": "responsive"} for f in resp_findings])

    result.tech_stack_score, obsolete_tech, modern_tech, tech_findings = check_tech_stack(html, headers or {})
    result.tech_detected = obsolete_tech
    result.modern_tech_detected = modern_tech
    result.findings.extend([{**f, "category": "tech_stack"} for f in tech_findings])

    result.performance_score, perf_findings = check_performance(html, headers or {}, load_time, result.page_size_kb)
    result.findings.extend([{**f, "category": "performance"} for f in perf_findings])

    result.seo_score, seo_findings = check_seo(html, headers or {}, url)
    result.findings.extend([{**f, "category": "seo"} for f in seo_findings])

    result.design_age_score, design_findings = check_design_age(html)
    result.findings.extend([{**f, "category": "design"} for f in design_findings])

    result.security_score, sec_findings = check_security(headers or {}, html, url)
    result.findings.extend([{**f, "category": "security"} for f in sec_findings])

    result.cms_age_score, cms_findings = check_cms_age(html, headers or {}, domain)
    result.findings.extend([{**f, "category": "cms"} for f in cms_findings])

    result.dns_info = get_dns_info(domain)
    result.whois_info = get_whois_info(domain)

    total = (
        result.ssl_score * WEIGHTS["ssl"] // 100 +
        result.responsive_score * WEIGHTS["responsive"] // 100 +
        result.tech_stack_score * WEIGHTS["tech_stack"] // 100 +
        result.performance_score * WEIGHTS["performance"] // 100 +
        result.seo_score * WEIGHTS["seo"] // 100 +
        result.design_age_score * WEIGHTS["design_age"] // 100 +
        result.security_score * WEIGHTS["security"] // 100 +
        result.cms_age_score * WEIGHTS["cms_age"] // 100
    )

    result.total_score = min(total, 100)
    result.is_obsolete = result.total_score >= OBSOLETE_THRESHOLD
    result.is_hot_lead = result.total_score >= HOT_LEAD_THRESHOLD

    if result.total_score >= 85:
        result.priority = "critical"
    elif result.total_score >= 70:
        result.priority = "high"
    elif result.total_score >= 55:
        result.priority = "medium"
    else:
        result.priority = "low"

    if verbose:
        print("  [📊] TOTAL: %d/100 | Priorytet: %s" % (result.total_score, result.priority.upper()))

    return result

# =============================================================================
# RAPORTOWANIE
# =============================================================================

def print_report(results: List[ScanResult], console: bool = True) -> str:
    lines = []
    obsolete = [r for r in results if r.is_obsolete]
    hot_leads = [r for r in results if r.is_hot_lead]

    lines.append("=" * 80)
    lines.append("        LEAD HUNTER GEO — RAPORT Z SKANOWANIA")
    lines.append("=" * 80)
    lines.append("Data: " + datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    lines.append("Przeskanowano: " + str(len(results)) + " stron")
    lines.append("Przestarzałych: " + str(len(obsolete)) + " (" + "%.1f" % (len(obsolete)/max(len(results),1)*100) + "%)")
    lines.append("Hot leadów: " + str(len(hot_leads)) + " (" + "%.1f" % (len(hot_leads)/max(len(results),1)*100) + "%)")
    lines.append("")

    lines.append("-" * 80)
    lines.append("%-30s %-18s %8s %10s %8s" % ("Domena", "Miasto", "Score", "Priorytet", "Status"))
    lines.append("-" * 80)

    for r in sorted(results, key=lambda x: x.total_score, reverse=True):
        city = r.geo.city if r.geo else ""
        status = "🔥 HOT" if r.is_hot_lead else ("⚠️ OLD" if r.is_obsolete else "✓ OK")
        lines.append("%-30s %-18s %6s/100 %10s %8s" % (r.domain[:29], city[:17], r.total_score, r.priority.upper(), status))

    lines.append("-" * 80)
    lines.append("")

    if hot_leads:
        lines.append("=" * 80)
        lines.append("                    🔥 HOT LEADS — SZCZEGÓŁY")
        lines.append("=" * 80)
        for r in hot_leads:
            geo_info = (r.geo.city + ", " + r.geo.postcode) if r.geo else ""
            lines.append("")
            lines.append("► " + r.domain + "  |  " + geo_info + "  |  Score: " + str(r.total_score) + "/100")
            lines.append("  URL: " + r.url)
            lines.append("  Czas ładowania: %.0fms | Rozmiar: %.1fKB" % (r.load_time_ms, r.page_size_kb))
            lines.append("  Tech (przestarzałe): " + (", ".join(r.tech_detected) if r.tech_detected else "brak"))
            critical = [f for f in r.findings if f.get("severity") in ("high", "critical")]
            lines.append("  Kluczowe problemy:")
            for f in critical[:5]:
                lines.append("    • [" + f.get("severity").upper() + "] " + f.get("message"))
            if len(critical) > 5:
                lines.append("    ... i " + str(len(critical)-5) + " więcej")

    report = "\n".join(lines)
    if console:
        print(report)
    return report


def export_json(results: List[ScanResult], path: str):
    data = []
    for r in results:
        d = asdict(r)
        d["timestamp"] = str(d["timestamp"])
        data.append(d)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print("\n[✓] Zapisano JSON: " + path)


def export_csv(results: List[ScanResult], path: str):
    fieldnames = [
        "name", "domain", "url", "city", "county", "postcode", "country",
        "total_score", "priority", "is_hot_lead",
        "ssl_score", "responsive_score", "tech_stack_score",
        "performance_score", "seo_score", "design_age_score",
        "security_score", "cms_age_score", "load_time_ms", "page_size_kb",
        "tech_detected", "modern_tech_detected", "findings", "error"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            row = {
                "name": r.geo.name if r.geo else "",
                "domain": r.domain,
                "url": r.url,
                "city": r.geo.city if r.geo else "",
                "county": r.geo.county if r.geo else "",
                "postcode": r.geo.postcode if r.geo else "",
                "country": r.geo.country if r.geo else "",
                "total_score": r.total_score,
                "priority": r.priority,
                "is_hot_lead": r.is_hot_lead,
                "ssl_score": r.ssl_score,
                "responsive_score": r.responsive_score,
                "tech_stack_score": r.tech_stack_score,
                "performance_score": r.performance_score,
                "seo_score": r.seo_score,
                "design_age_score": r.design_age_score,
                "security_score": r.security_score,
                "cms_age_score": r.cms_age_score,
                "load_time_ms": r.load_time_ms,
                "page_size_kb": r.page_size_kb,
                "tech_detected": ", ".join(r.tech_detected),
                "modern_tech_detected": ", ".join(r.modern_tech_detected),
                "findings": " | ".join([f.get("message", "") for f in r.findings if f.get("severity") in ("high", "critical", "medium")]),
                "error": r.error or "",
            }
            writer.writerow(row)
    print("[✓] Zapisano CSV: " + path)


def export_geojson(results: List[ScanResult], path: str):
    features = []
    for r in results:
        if not r.geo or r.geo.lat is None or r.geo.lon is None:
            continue
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [r.geo.lon, r.geo.lat]},
            "properties": {
                "name": r.geo.name,
                "domain": r.domain,
                "url": r.url,
                "score": r.total_score,
                "priority": r.priority,
                "city": r.geo.city,
                "is_hot_lead": r.is_hot_lead,
            }
        })
    geojson = {"type": "FeatureCollection", "features": features}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(geojson, f, indent=2, ensure_ascii=False)
    print("[✓] Zapisano GeoJSON: " + path)


# =============================================================================
# GŁÓWNA LOGIKA
# =============================================================================

def discover_businesses(args) -> List[GeoBusiness]:
    businesses = []

    if args.csv_input:
        importer = CSVImporter()
        all_biz = importer.load(args.csv_input)
        businesses = importer.filter_by_location(
            all_biz, city=args.city, county=args.county,
            country=args.country, postcode_prefix=args.postcode
        )
        print("[📁] Wczytano " + str(len(all_biz)) + " firm z CSV, po filtrze: " + str(len(businesses)))

    elif args.source == "yell":
        if not args.city:
            print("[✗] Yell.com wymaga --city")
            sys.exit(1)
        finder = YellFinder()
        businesses = finder.search(location=args.city, category=args.category or "", max_results=args.max_results)

    else:
        if not args.city:
            print("[✗] Wymagane --city (lub użyj --csv-input)")
            sys.exit(1)
        nominatim = NominatimClient()
        finder = OverpassFinder(nominatim)
        businesses = finder.search(
            city=args.city, country=args.country or "",
            radius_km=args.radius, category=args.category or "",
            max_results=args.max_results
        )

    if args.county:
        county_lower = args.county.lower()
        businesses = [b for b in businesses if county_lower in b.county.lower()]

    if args.postcode:
        prefix = args.postcode.upper().replace(" ", "")
        businesses = [b for b in businesses if b.postcode.upper().replace(" ", "").startswith(prefix)]

    return businesses


def main():
    global OBSOLETE_THRESHOLD, HOT_LEAD_THRESHOLD
    parser = argparse.ArgumentParser(
        description="LeadHunter GEO — wyszukiwarka przestarzałych stron WWW z geolokalizacją",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
PRZYKŁADY UK:
  # Restauracje w Londynie (promień 5km, max 25 wyników)
  python lead_hunter_geo.py --city "London" --country "UK" --radius 5 --category restaurant --max-results 25

  # Wszystkie firmy w Manchesterze przez Yell.com
  python lead_hunter_geo.py --city "Manchester" --source yell --max-results 30

  # Hrabstwo Yorkshire — tylko kody pocztowe zaczynające się na YO
  python lead_hunter_geo.py --city "York" --country "UK" --radius 15 --postcode "YO"

  # Własna lista firm z CSV
  python lead_hunter_geo.py --csv-input firms.csv --city "Birmingham" --output leads.json

  # Tylko wyszukaj firmy (bez skanowania stron)
  python lead_hunter_geo.py --city "Glasgow" --country "UK" --discover-only --output firms.json

  # Pełny pipeline: znajdź → przeskanuj → zapisz CSV + GeoJSON
  python lead_hunter_geo.py --city "Edinburgh" --country "UK" --radius 8 \
      --output leads.json --csv leads.csv --geojson leads.geojson
        """
    )

    # Lokalizacja
    parser.add_argument("--city", help="Miasto (np. London, Manchester, Birmingham)")
    parser.add_argument("--country", help="Kraj (np. UK, PL, DE)")
    parser.add_argument("--county", help="Hrabstwo / województwo (np. Yorkshire, Greater London)")
    parser.add_argument("--postcode", help="Prefiks kodu pocztowego (np. SW1, M1, YO)")
    parser.add_argument("--radius", type=float, default=10.0, help="Promień wyszukiwania w km (domyślnie 10)")

    # Źródło danych
    parser.add_argument("--source", choices=["osm", "yell", "csv"], default="osm",
                        help="Źródło danych: osm (OpenStreetMap), yell (Yell.com UK), csv (własny plik)")
    parser.add_argument("--csv-input", help="Ścieżka do CSV z firmami (kolumny: name, url, city, postcode...)")
    parser.add_argument("--category", help="Kategoria biznesu (np. restaurant, hotel, plumber)")
    parser.add_argument("--max-results", type=int, default=50, help="Maksymalna liczba firm do przeskanowania")

    # Skanowanie
    parser.add_argument("--threshold", type=int, default=OBSOLETE_THRESHOLD, help="Próg przestarzałości (domyślnie " + str(OBSOLETE_THRESHOLD) + ")")
    parser.add_argument("--hot-threshold", type=int, default=HOT_LEAD_THRESHOLD, help="Próg hot leadu (domyślnie " + str(HOT_LEAD_THRESHOLD) + ")")
    parser.add_argument("--verbose", "-v", action="store_true", help="Szczegółowe logowanie")
    parser.add_argument("--discover-only", action="store_true", help="Tylko wyszukaj firmy, nie skanuj stron")

    # Eksport
    parser.add_argument("--output", "-o", help="Ścieżka do pliku JSON z wynikami")
    parser.add_argument("--csv", help="Ścieżka do pliku CSV z wynikami")
    parser.add_argument("--geojson", help="Ścieżka do pliku GeoJSON (mapa)")
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)

    args = parser.parse_args()

    OBSOLETE_THRESHOLD = args.threshold
    HOT_LEAD_THRESHOLD = args.hot_threshold

    print("\n" + "=" * 70)
    print("        🤖 LEAD HUNTER GEO v" + VERSION)
    print("        Wyszukiwarka przestarzałych stron WWW + Geolokalizacja")
    print("=" * 70)
    print("Źródło: " + args.source.upper() + " | Próg: " + str(args.threshold) + " | Hot lead: " + str(args.hot_threshold))
    if args.city:
        print("Lokalizacja: " + args.city + (", " + args.country if args.country else ""))
    if args.radius and args.source == "osm":
        print("Promień: " + str(args.radius) + " km")
    if args.category:
        print("Kategoria: " + args.category)
    print("")

    # Faza 1: Discovery
    businesses = discover_businesses(args)

    if args.discover_only:
        print("\n[📋] Tylko discovery — zapisuję listę firm...")
        data = [asdict(b) for b in businesses]
        out_path = args.output or "firms.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)
        print("[✓] Zapisano " + str(len(data)) + " firm do: " + out_path)
        sys.exit(0)

    if not businesses:
        print("[✗] Nie znaleziono żadnych firm. Sprawdź parametry lokalizacji.")
        sys.exit(1)

    # Faza 2: Skanowanie
    print("\n" + "=" * 70)
    print("        🔍 FAZA 2: SKANOWANIE STRON")
    print("=" * 70)

    results = []
    for idx, biz in enumerate(businesses, 1):
        print("\n[" + str(idx) + "/" + str(len(businesses)) + "] " + biz.name + " (" + biz.city + ")")
        try:
            result = scan_url(biz.url, geo=biz, verbose=args.verbose)
            results.append(result)
        except Exception as e:
            print("  Błąd podczas skanowania " + biz.url + ": " + str(e))
            err_result = ScanResult(
                url=biz.url, domain=get_domain(biz.url),
                timestamp=datetime.now().isoformat(), geo=biz,
                error=str(e), total_score=100,
                is_obsolete=True, is_hot_lead=True, priority="critical"
            )
            results.append(err_result)

    # Raport
    print_report(results)

    # Eksport
    if args.output:
        export_json(results, args.output)
    if args.csv:
        export_csv(results, args.csv)
    if args.geojson:
        export_geojson(results, args.geojson)

    obsolete_count = sum(1 for r in results if r.is_obsolete)
    hot_count = sum(1 for r in results if r.is_hot_lead)
    print("\n" + "=" * 70)
    print("PODSUMOWANIE: " + str(obsolete_count) + "/" + str(len(results)) + " przestarzałych, " + str(hot_count) + " hot leadów")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
