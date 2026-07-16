#!/usr/bin/env python3
"""
CyberBrief RSS Scraper with Item Aging & Archive System  (v2 — 9 sections)

WHAT IT DOES (each run):
1. Pulls fresh items from real cybersecurity RSS feeds (working article links)
2. Classifies each item into one primary section by keyword
3. Pulls authoritative KEV entries from the CISA Known Exploited Vulns feed
4. Adds NEW items (deduped against active + archive) at age 0
5. Ages every existing item by +1; moves items past max_age into archive.json
6. Caps each active section to MAX_PER_SECTION (newest kept)
7. Rebuilds the cross-cutting SECTOR and AWARENESS views from the active set

Primary (scraped + aged) sections:  kev, breach, cve, patch, threat, ransomware, news
Derived (rebuilt every run, not aged): sector, awareness

The GitHub Actions workflow handles the git commit/push after this runs.
"""

import json
import os
import re
import html
from datetime import datetime, timedelta
import logging

import feedparser  # pip install feedparser
import requests    # pip install requests

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ---- RSS feeds (all publish real, working article links) -------------------
FEEDS = [
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News",  "https://feeds.feedburner.com/TheHackersNews"),
    ("SecurityWeek",     "https://www.securityweek.com/feed/"),
    ("Dark Reading",     "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security","https://krebsonsecurity.com/feed/"),
]

# CISA Known Exploited Vulnerabilities catalog (authoritative, JSON)
KEV_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Primary sections that are scraped, deduped, aged and archived
PRIMARY = ['kev', 'breach', 'cve', 'patch', 'threat', 'ransomware', 'news']
# Derived views rebuilt from the active set each run (not aged, not archived)
DERIVED = ['sector', 'awareness']
SECTIONS = PRIMARY + DERIVED

MAX_PER_SECTION = 12          # cap active items per section
MAX_NEW_PER_RUN = 8           # cap new items pulled per section per run
MAX_KEV          = 12         # most-recent KEV entries to surface

# Keyword banks for the two cross-cutting views ------------------------------
SECTOR_KW = ['government', 'county', 'municipal', 'city of', 'state of',
             'public sector', 'federal', 'agency', 'school', 'university',
             'k-12', 'education', 'election', 'healthcare', 'hospital',
             'health system', 'patient', 'utility', 'water system',
             'power grid', 'court', 'police', 'sheriff', 'sled', 'cisa']
AWARE_KW  = ['phishing', 'scam', 'smishing', 'vishing', 'mfa', 'multi-factor',
             'passkey', 'password', 'social engineering', 'impersonat',
             'credential', '2fa', 'fraud', 'fake login', 'malicious email']


class CyberBriefScraper:
    def __init__(self):
        self.data_file = 'data.json'
        self.archive_file = 'archive.json'
        self.max_age = 4       # archive after 4 refreshes (~2 days at 2x daily)

    # ---- file IO -----------------------------------------------------------
    def _blank(self):
        return {s: [] for s in SECTIONS}

    def _load(self, path):
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    d = json.load(f)
                    for s in SECTIONS:
                        d.setdefault(s, [])
                    return d
            except Exception as e:
                logger.warning(f"Could not parse {path}: {e}")
        return self._blank()

    def load_data(self):    return self._load(self.data_file)
    def load_archive(self): return self._load(self.archive_file)

    def save_data(self, data):
        with open(self.data_file, 'w') as f:
            json.dump(data, f, indent=2)

    def save_archive(self, archive):
        with open(self.archive_file, 'w') as f:
            json.dump(archive, f, indent=2)

    # ---- classification ----------------------------------------------------
    @staticmethod
    def classify(title, summary):
        text = f"{title} {summary}".lower()
        has_cve = bool(re.search(r'cve-\d{4}-\d+', text))
        # most specific first
        if any(k in text for k in
                ['ransomware', 'ransom gang', 'ransom demand', 'lockbit', 'clop',
                 'blackcat', 'alphv', 'akira', 'rhysida', 'encrypts files',
                 'encrypts victim', 'data encrypted', 'double extortion']):
            return 'ransomware'
        # BREACH before CVE: exposed data / stolen records is a breach, not a vuln
        if any(k in text for k in
                ['data breach', 'breached', 'data leak', 'leaked data',
                 'stolen data', 'data theft', 'records exposed',
                 'database exposed', 'exposed data', 'customer data', 'exfiltrat',
                 'personal information', 'stole ', 'hacked and stole']):
            return 'breach'
        # PATCH: explicit patch-release language (tightened — no bare 'fixes ')
        if 'patch tuesday' in text or any(k in text for k in
                ['security update', 'patches critical', 'patches multiple',
                 'patches high', 'has patched', 'releases patch', 'issues patch',
                 'security advisory', 'out-of-band update', 'patch now',
                 'patches flaw', 'patches vulnerab', 'rolls out fixes']):
            return 'patch'
        # CVE: require a real CVE id OR strong single-vuln language
        if has_cve or any(k in text for k in
                ['zero-day', 'zero day', 'remote code execution', ' rce ',
                 'buffer overflow', 'privilege escalation', 'sql injection',
                 'authentication bypass', 'arbitrary code']):
            return 'cve'
        if any(k in text for k in
                ['apt', 'threat actor', 'hacking group', 'botnet', 'malware',
                 'phishing campaign', 'nation-state', 'trojan', 'backdoor',
                 'infostealer', 'stealer', 'rat ', 'spyware', 'campaign']):
            return 'threat'
        return 'news'

    @staticmethod
    def severity_from(text):
        t = text.lower()
        if any(k in t for k in ['critical', 'actively exploited', 'zero-day', 'emergency']):
            return 'Critical'
        if any(k in t for k in ['high', 'severe', 'widespread']):
            return 'High'
        if any(k in t for k in ['medium', 'moderate']):
            return 'Medium'
        return 'High'

    @staticmethod
    def clean(text):
        text = re.sub(r'<[^>]+>', '', text or '')      # strip HTML tags
        text = html.unescape(text).strip()
        return re.sub(r'\s+', ' ', text)

    def build_item(self, section, title, link, summary, source_name):
        title = self.clean(title)
        summary = self.clean(summary)
        if len(summary) > 320:
            summary = summary[:317].rsplit(' ', 1)[0] + '...'
        sources = [{"label": source_name, "url": link}]
        base = {"summary": summary or title, "age": 0, "sources": sources,
                "date": datetime.now().strftime('%b %d, %Y')}
        sev = self.severity_from(title + summary)

        if section == 'breach':
            return {**base, "org": title, "severity": sev, "records": "See source"}
        if section == 'cve':
            m = re.search(r'cve-\d{4}-\d+', (title + ' ' + summary).lower())
            cve_id = m.group(0).upper() if m else ''
            return {**base, "cve_id": cve_id, "title": title,
                    "product": self.extract_product(title, summary),
                    "vendor": source_name, "severity": sev}
        if section == 'patch':
            return {**base, "title": title, "vendor": source_name, "severity": sev}
        if section == 'threat':
            return {**base, "actor": title, "severity": sev}
        if section == 'ransomware':
            return {**base, "group": title, "victim": "", "sector": "",
                    "severity": sev}
        return {**base, "title": title, "category": "news"}

    # vendor/product guess from the headline for the CVE tracker label
    _VENDORS = ['Microsoft', 'Windows', 'Oracle', 'Adobe', 'SAP', 'Cisco',
                'Fortinet', 'Ivanti', 'SonicWall', 'Citrix', 'VMware', 'Zoom',
                'Splunk', 'Apache', 'Atlassian', 'GitLab', 'Google', 'Chrome',
                'Firefox', 'Mozilla', 'Apple', 'Linux', 'F5', 'Juniper',
                'Palo Alto', 'Zimbra', 'MOVEit', 'ColdFusion', 'NetWeaver',
                'SharePoint', 'Exchange', 'RabbitMQ', 'Cursor']

    def extract_product(self, title, summary):
        text = title + ' ' + summary
        for v in self._VENDORS:
            if re.search(r'\b' + re.escape(v) + r'\b', text, re.I):
                return v
        return ''

    # ---- CISA KEV ----------------------------------------------------------
    def fetch_kev(self, existing_keys):
        """Authoritative exploited-in-the-wild entries from CISA."""
        items = []
        try:
            logger.info("Fetching CISA KEV catalog ...")
            r = requests.get(KEV_FEED, timeout=20)
            r.raise_for_status()
            vulns = r.json().get('vulnerabilities', [])
            vulns.sort(key=lambda v: v.get('dateAdded', ''), reverse=True)
            for v in vulns[:MAX_KEV]:
                cid = v.get('cveID', '')
                url = f"https://nvd.nist.gov/vuln/detail/{cid}"
                if url.lower() in existing_keys:
                    continue
                existing_keys.add(url.lower())
                due = v.get('dueDate', '')
                try:
                    due = datetime.strptime(due, '%Y-%m-%d').strftime('%b %d, %Y') if due else ''
                except Exception:
                    pass
                added = v.get('dateAdded', '')
                items.append({
                    "cve_id": cid,
                    "product": v.get('product', ''),
                    "vendor": v.get('vendorProject', ''),
                    "severity": "Critical",
                    "date_added": added,
                    "due_date": due,
                    "action": v.get('requiredAction', 'Apply mitigations'),
                    "summary": self.clean(v.get('shortDescription', '')),
                    "age": 0,
                    "date": datetime.now().strftime('%b %d, %Y'),
                    "sources": [{"label": "CISA KEV", "url": url}],
                })
            logger.info(f"  KEV: {len(items)} new entries")
        except Exception as e:
            logger.warning(f"  KEV fetch failed: {e}")
        return items

    # ---- RSS fetch ---------------------------------------------------------
    def fetch_new(self, existing_keys):
        new = {s: [] for s in PRIMARY}
        for source_name, url in FEEDS:
            try:
                logger.info(f"Fetching {source_name} ...")
                feed = feedparser.parse(url)
                if not feed.entries:
                    logger.warning(f"  no entries from {source_name}")
                    continue
                for entry in feed.entries[:25]:
                    title = entry.get('title', '')
                    link = entry.get('link', '')
                    summary = entry.get('summary', entry.get('description', ''))
                    if not title or not link:
                        continue
                    key = link.strip().lower()
                    if key in existing_keys:
                        continue
                    section = self.classify(title, summary)
                    if len(new[section]) >= MAX_NEW_PER_RUN:
                        continue
                    existing_keys.add(key)
                    new[section].append(
                        self.build_item(section, title, link, summary, source_name))
                logger.info(f"  ok ({len(feed.entries)} entries scanned)")
            except Exception as e:
                logger.warning(f"  failed {source_name}: {e}")
        new['kev'] = self.fetch_kev(existing_keys)
        total = sum(len(v) for v in new.values())
        logger.info("New items: " + ", ".join(f"{s} {len(new[s])}" for s in PRIMARY))
        logger.info(f"New items pulled: {total}")
        return new

    # ---- aging (primary sections only) ------------------------------------
    def age_items(self, data, archive):
        for section in PRIMARY:
            keep = []
            for item in data.get(section, []):
                item['age'] = item.get('age', 0) + 1
                if item['age'] > self.max_age:
                    archive.setdefault(section, []).append(item)
                else:
                    keep.append(item)
            data[section] = keep
        return data, archive

    # ---- derived views -----------------------------------------------------
    @staticmethod
    def _text_of(it):
        return (str(it.get('org', '')) + ' ' + str(it.get('cve_id', '')) + ' ' +
                str(it.get('actor', '')) + ' ' + str(it.get('group', '')) + ' ' +
                str(it.get('title', '')) + ' ' + str(it.get('summary', ''))).lower()

    def rebuild_views(self, data):
        """SECTOR + AWARENESS are keyword views over the active primary set."""
        pool = []
        for section in PRIMARY:
            for it in data.get(section, []):
                pool.append((section, it))

        def name_of(it):
            return it.get('title') or it.get('org') or it.get('cve_id') \
                or it.get('actor') or it.get('group') or ''

        sector, aware = [], []
        for section, it in pool:
            text = self._text_of(it)
            if any(k in text for k in SECTOR_KW) and len(sector) < MAX_PER_SECTION:
                sector.append({
                    "title": name_of(it),
                    "org": it.get('vendor') or (it.get('sources', [{}])[0].get('label', '')),
                    "sector": "PUBLIC SECTOR",
                    "severity": it.get('severity', 'High'),
                    "summary": it.get('summary', ''),
                    "age": it.get('age', 0),
                    "date": it.get('date', ''),
                    "sources": it.get('sources', []),
                })
            if any(k in text for k in AWARE_KW) and len(aware) < MAX_PER_SECTION:
                aware.append({
                    "title": name_of(it),
                    "topic": "AWARENESS",
                    "severity": it.get('severity', 'Medium'),
                    "summary": it.get('summary', ''),
                    "source": it.get('sources', [{}])[0].get('label', ''),
                    "age": it.get('age', 0),
                    "date": it.get('date', ''),
                    "sources": it.get('sources', []),
                })
        data['sector'] = sector
        data['awareness'] = aware
        return data

    @staticmethod
    def existing_keys(data, archive):
        keys = set()
        for store in (data, archive):
            for section in PRIMARY:
                for item in store.get(section, []):
                    for s in item.get('sources', []):
                        if s.get('url'):
                            keys.add(s['url'].strip().lower())
        return keys

    # ---- main --------------------------------------------------------------
    def run(self):
        logger.info("=" * 70)
        logger.info(f"CyberBrief RSS Scraper (v2) started {datetime.now():%Y-%m-%d %H:%M:%S}")
        logger.info("=" * 70)
        try:
            data = self.load_data()
            archive = self.load_archive()

            data, archive = self.age_items(data, archive)
            keys = self.existing_keys(data, archive)
            new = self.fetch_new(keys)

            for section in PRIMARY:
                data[section] = (new.get(section, []) + data.get(section, []))[:MAX_PER_SECTION]

            data = self.rebuild_views(data)   # sector + awareness

            self.save_data(data)
            self.save_archive(archive)

            counts = {s: len(data[s]) for s in SECTIONS}
            logger.info(f"Active now: {counts}")
            logger.info("\u2713 CyberBrief update complete")
            return 0
        except Exception as e:
            logger.error(f"ERROR: {e}")
            logger.error("Keeping existing data files unchanged")
            return 1


if __name__ == '__main__':
    raise SystemExit(CyberBriefScraper().run())
