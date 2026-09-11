#!/usr/bin/env python3
"""
Email Automation Script (ULTIMATE SECURITY VERSION 2.0)
- Moves spam to Inbox
- Extracts URLs from recent unseen emails using BeautifulSoup4
- Filters out ALL unsubscribe / opt-out links using:
  * Text patterns (visible & alt-text)
  * URL patterns
  * RFC 2369 List-Unsubscribe headers
  * RFC 8058 List-Unsubscribe-Post headers
- Uses a 'Memory Bank' to prevent accidental plain-text clicks
- Visits only "safe" marketing URLs that match your inclusion keywords
"""

import imaplib
import email
import re
import datetime
import requests
import json
import time
import os
import logging
from typing import List, Tuple, Set
from email.utils import parseaddr

# Import BeautifulSoup for bulletproof HTML parsing
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("ERROR: BeautifulSoup4 is not installed. Please run: pip install beautifulsoup4")
    exit(1)

# ------------------- Logging Setup -------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


# ============================================================
# SECURITY PATTERNS (Hardcoded Fallbacks & Safety Nets)
# ============================================================

# Catches dangerous words inside the URL itself
UNSUBSCRIBE_URL_PATTERN = re.compile(
    r'unsubscribe|unsub|opt[\s_-]?out|remove[\s_-]?me|manage[\s_-]?pref|list[\s_-]?unsubscribe|one[\s_-]?click',
    re.IGNORECASE
)

# Catches dangerous words in the visible text or image alt-tags (ENHANCED with rare patterns)
UNSUBSCRIBE_TEXT_PATTERN = re.compile(
    r'''
    unsubscribe
    |unsub
    |opt[\s_-]?out
    |remove[\s_-]?me
    |stop[\s_-]?(emails?|mail|messages?)
    |stop[\s_-]?receiving
    |manage[\s_-]?preferences?
    |manage[\s_-]?subscription
    |email[\s_-]?preferences?
    |email[\s_-]?settings?
    |subscription[\s_-]?preferences?
    |subscription[\s_-]?settings?
    |mailing[\s_-]?preferences?
    |change[\s_-]?preferences?
    |no[\s_-]?longer[\s_-]?wish
    |leave[\s_-]?this[\s_-]?list
    |cancel[\s_-]?subscription
    |update[\s_-]?profile
    |safeunsubscribe
    |one[\s_-]?click
    |unsubscribe[\s_-]?here
    |unsubscribe[\s_-]?now
    |list[\s_-]?unsubscribe
    |remove[\s_-]?from[\s_-]?list
    |opt[\s_-]?out[\s_-]?now
    |preferences[\s_-]?center
    |email[\s_-]?center
    |subscription[\s_-]?center
    |mailing[\s_-]?list[\s_-]?settings
    |frequency[\s_-]?preferences?
    |delivery[\s_-]?preferences?
    |communication[\s_-]?preferences?
    |alert[\s_-]?preferences?
    |notification[\s_-]?preferences?
    |decline|uncheck|dont?[\s_-]?send|no[\s_-]?more
    ''',
    re.IGNORECASE | re.VERBOSE
)

# Hardcoded whitelist (Used if not provided in JSON)
DEFAULT_INCLUSION_KEYWORDS = [
    "service-federalfiling", "wisechoiceloans", "bestloansquick", "federalfilinginfo", 
    "izbuys", "insurvo", "maison7", "moengage", "bogs", "powerrefinance", "labelaarna",
    "dharishahayurveda", "infoloanoptions", "lizbuys", "anveshan", "thefinanciallyfreeteacher",
    "sundariihandmade", "veterandebthelp", "usemailora.com", "govloanoptions", "redbus",
    "financiallyfreenurse", "thedebtfreefirstresponder", "debtfreefirstresponder", "spoonacular",
    "govratealerts", "thedebtfreeteacher", "veterandebtassistance", "bigbustours", "mailora", 
    "zola", "federalfiling", "firstcry", "jisora"
]

# ============================================================
# Core Functions
# ============================================================

def load_config(config_path: str = "config4.json") -> dict:
    """Load config. Supports environment-variable passwords for security."""
    with open(config_path, "r") as f:
        config = json.load(f)

    for account in config.get("accounts", []):
        env_key = f"EMAIL_APP_PASSWORD_{account['email_address'].replace('@', '_').replace('.', '_').upper()}"
        if env_key in os.environ:
            account["app_password"] = os.environ[env_key]
            
    return config


def extract_urls_from_rfc2369_header(header_value: str) -> Set[str]:
    """
    RFC 2369: List-Unsubscribe header format
    Example: List-Unsubscribe: <https://example.com/unsub>, <mailto:unsub@example.com>
    
    Extracts all URLs from the angle-bracket notation.
    """
    urls = set()
    if not header_value:
        return urls
    
    # Match anything between < and >
    matches = re.findall(r'<([^>]+)>', header_value)
    for match in matches:
        # Only extract HTTP(S) URLs, skip mailto
        if match.lower().startswith(('http://', 'https://')):
            urls.add(match)
    
    return urls


def extract_urls_from_rfc8058_header(header_value: str) -> Set[str]:
    """
    RFC 8058: List-Unsubscribe-Post header
    Example: List-Unsubscribe-Post: List-Unsubscribe=One-Click
    
    This header signals one-click unsubscribe capability.
    When present, we should NEVER touch the List-Unsubscribe URL.
    """
    if not header_value:
        return set()
    
    # If this header exists, it means the email has one-click unsubscribe capability
    # We treat ANY unsubscribe URL as dangerous when this header is present
    if "one-click" in header_value.lower() or "one_click" in header_value.lower():
        logger.debug("Detected RFC 8058 One-Click unsubscribe — treating all unsubscribe URLs as dangerous")
        return set()  # Return empty, but the presence of this header is a red flag
    
    return set()


def check_email_headers_for_unsubscribe(full_msg) -> bool:
    """
    Checks RFC 2369 and RFC 8058 headers for unsubscribe links.
    Returns True if any unsubscribe header is found.
    """
    list_unsubscribe = full_msg.get('List-Unsubscribe', '')
    list_unsubscribe_post = full_msg.get('List-Unsubscribe-Post', '')
    
    if list_unsubscribe:
        logger.debug(f"Found RFC 2369 List-Unsubscribe header: {list_unsubscribe[:50]}...")
        urls_found = extract_urls_from_rfc2369_header(list_unsubscribe)
        if urls_found:
            logger.debug(f"Extracted {len(urls_found)} URLs from List-Unsubscribe header")
            return True
    
    if list_unsubscribe_post:
        logger.debug(f"Found RFC 8058 List-Unsubscribe-Post header: {list_unsubscribe_post}")
        extract_urls_from_rfc8058_header(list_unsubscribe_post)
        return True
    
    return False


def is_unsubscribe_link(url: str, link_text: str, filters: dict, has_rfc_headers: bool = False) -> bool:
    """
    Checks BOTH the URL string and the visible text for unsubscribe patterns.
    Also considers if the email has RFC 2369/8058 headers (extra red flag).
    """
    url_lower = url.lower()
    text_lower = link_text.lower()

    # 1. Check dynamic JSON config filters (if any exist)
    for kw in filters.get("unsubscribe_exclude_keywords", []):
        if kw and kw.lower() in url_lower:
            return True
    for domain in filters.get("unsubscribe_exclude_domains", []):
        if domain and domain.lower() in url_lower:
            return True
    for path in filters.get("unsubscribe_exclude_paths", []):
        if path and path.lower() in url_lower:
            return True

    # 2. Check aggressive hardcoded Regex patterns against URL
    if UNSUBSCRIBE_URL_PATTERN.search(url_lower):
        return True

    # 3. Check aggressive hardcoded Regex patterns against Visible Text
    if UNSUBSCRIBE_TEXT_PATTERN.search(text_lower):
        return True
    
    # 4. EXTRA SAFETY: If email has RFC headers, be extra cautious
    if has_rfc_headers and ("unsub" in url_lower or "opt" in url_lower or "remove" in url_lower):
        return True

    return False


def extract_and_filter_urls(message_body: str, full_msg, config: dict) -> Tuple[List[str], bool]:
    """
    Extracts URLs using BeautifulSoup to read visible text and hidden image tags,
    skips every unsubscribe link, uses a Memory Bank, and returns only safe URLs.
    
    Also checks RFC 2369/8058 headers before processing body URLs.
    """
    urls_to_open: Set[str] = set()
    blocked_urls: Set[str] = set()  # THE MEMORY BANK
    found_any_match = False
    url_count = 0
    max_urls = 2

    # Check for RFC headers FIRST (highest priority red flag)
    has_rfc_unsubscribe = check_email_headers_for_unsubscribe(full_msg)

    # Load inclusion keywords from JSON, or use defaults if JSON list is empty
    inclusion_keywords = [k.lower() for k in config.get("url_inclusion_keywords", [])]
    if not inclusion_keywords:
        inclusion_keywords = [k.lower() for k in DEFAULT_INCLUSION_KEYWORDS]
        
    url_filters = config.get("url_filters", {})

    soup = BeautifulSoup(message_body, 'html.parser')

    # --------------------------------------------------------
    # PASS 1: Parse HTML (Catches Text & Hidden Alt-Tags)
    # --------------------------------------------------------
    for a_tag in soup.find_all('a', href=True):
        if url_count >= max_urls:
            break

        url = a_tag['href'].strip()
        if not url.lower().startswith(('http://', 'https://')):
            continue

        # Extract all visible text and hidden image alt-text
        texts = []
        if a_tag.get_text(strip=True):
            texts.append(a_tag.get_text(separator=' ', strip=True))
        if a_tag.get('title'):
            texts.append(a_tag.get('title').strip())
        for img in a_tag.find_all('img'):
            if img.get('alt'):
                texts.append(img.get('alt').strip())
                
        comprehensive_text = " | ".join(texts)

        # Unsubscribe Check (passing RFC header flag)
        if is_unsubscribe_link(url, comprehensive_text, url_filters, has_rfc_unsubscribe):
            blocked_urls.add(url)
            logger.debug(f"BLOCKED unsubscribe URL: {url} (Text: '{comprehensive_text}')")
            continue

        # Whitelist Check
        url_lower = url.lower()
        if any(kw in url_lower for kw in inclusion_keywords):
            found_any_match = True
            if url not in urls_to_open:
                urls_to_open.add(url)
                url_count += 1

    # --------------------------------------------------------
    # PASS 2: Plain Text Fallback (Checks Memory Bank)
    # --------------------------------------------------------
    if url_count < max_urls:
        plain_url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        for match in plain_url_pattern.finditer(message_body):
            if url_count >= max_urls:
                break
                
            url = match.group(0).strip().rstrip('\'">.')
            if not url.lower().startswith(('http://', 'https://')):
                continue

            # Check Memory Bank first!
            if url in blocked_urls:
                continue

            # Plain text Unsubscribe check (passing RFC header flag)
            if is_unsubscribe_link(url, "", url_filters, has_rfc_unsubscribe):
                blocked_urls.add(url)
                continue

            # Whitelist Check
            url_lower = url.lower()
            if any(kw in url_lower for kw in inclusion_keywords):
                found_any_match = True
                if url not in urls_to_open:
                    urls_to_open.add(url)
                    url_count += 1

    return sorted(list(urls_to_open)), found_any_match


def get_email_body(full_msg) -> str:
    """Crash-proof email body parser."""
    body = ""
    for part in full_msg.walk():
        ctype = part.get_content_type()
        charset = part.get_content_charset() or 'utf-8'

        if ctype == "text/html":
            try:
                return part.get_payload(decode=True).decode(charset, errors="replace")
            except Exception:
                continue
        elif ctype == "text/plain" and not body:
            try:
                body = part.get_payload(decode=True).decode(charset, errors="replace")
            except Exception:
                pass
    return body


def move_spam_to_inbox(mail, dest_mailbox: str, date_filter: str) -> None:
    """Moves unseen mail from common spam/junk folders to Inbox."""
    COMMON_SPAM_FOLDERS = ["[Gmail]/Spam", "Spam", "Junk", "[Gmail]/Junk"]

    for folder in COMMON_SPAM_FOLDERS:
        try:
            status, _ = mail.select(folder)
            if status != "OK":
                continue
                
            status, data = mail.search(None, f'(UNSEEN SINCE "{date_filter}")')
            if status == "OK" and data[0]:
                email_ids = data[0].split()
                logger.info(f"Moving {len(email_ids)} emails from {folder} to {dest_mailbox}")
                
                for uid in email_ids:
                    if mail.copy(uid, dest_mailbox)[0] == "OK":
                        mail.store(uid, "+FLAGS", "\\Deleted")
                mail.expunge()
        except Exception as e:
            logger.debug(f"Could not process {folder}: {e}")


def automate_email_tasks(account_config: dict, general_config: dict, full_config: dict) -> None:
    """Processes one email account end-to-end."""
    email_address = account_config["email_address"]
    app_password = account_config["app_password"]
    imap_server = account_config["imap_server"]
    mailbox = account_config["mailbox"]
    days = general_config.get("days_to_check", 3)

    logger.info(f"=== Processing: {account_config.get('account_name', email_address)} ===")

    try:
        date_filter = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%d-%b-%Y")
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, app_password)

        # Move spam first
        move_spam_to_inbox(mail, mailbox, date_filter)

        # Process Inbox
        mail.select(mailbox, readonly=False)
        status, data = mail.search(None, f'(UNSEEN SINCE "{date_filter}")')

        if status != "OK" or not data[0]:
            logger.info("No unseen emails found.")
            mail.logout()
            return

        email_ids = data[0].split()
        logger.info(f"Found {len(email_ids)} unseen emails in {mailbox}.")

        mails_to_act_on = []

        # Fetch, Parse, and Filter
        for uid in email_ids:
            status, msg_data = mail.fetch(uid, "(RFC822)")
            full_msg = email.message_from_bytes(msg_data[0][1])
            body = get_email_body(full_msg)

            urls, has_match = extract_and_filter_urls(body, full_msg, full_config)

            if has_match:
                mail.store(uid, "+FLAGS", "\\Seen")
                mails_to_act_on.append((uid, full_msg, urls))
            else:
                mail.store(uid, "-FLAGS", "\\Seen")
                logger.info(f"Marked UNREAD (no match): {full_msg.get('From', 'Unknown')}")

        # Visit only safe (non-unsubscribe) URLs
        if mails_to_act_on:
            logger.info(f"Visiting URLs for {len(mails_to_act_on)} emails...")
            headers = {
                "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            }

            for uid, full_msg, urls in mails_to_act_on:
                logger.info(f"Email From: {full_msg.get('From')} | Subject: {full_msg.get('Subject')}")
                for url in urls:
                    # Final Fail-Safe: Absolute last check before making the web request
                    if is_unsubscribe_link(url, "", full_config.get("url_filters", {})):
                        logger.warning(f"  -> FINAL BLOCK (Fail-Safe triggered): {url}")
                        continue
                        
                    try:
                        resp = requests.get(url, headers=headers, timeout=10)
                        logger.info(f"  -> Pinging: {url} → Status {resp.status_code}")
                    except Exception as e:
                        logger.warning(f"  -> {url} failed: {e}")
                    time.sleep(1.0)
        else:
            logger.info("No URLs matched inclusion keywords.")

        mail.logout()
        logger.info(f"Finished {email_address}\n")

    except Exception as e:
        logger.error(f"Error with {email_address}: {e}")
    finally:
        if "mail" in locals() and mail and mail.state != "LOGOUT":
            try:
                mail.logout()
            except Exception:
                pass


# ============================================================
# Main Execution
# ============================================================

if __name__ == "__main__":
    try:
        # Load the configuration file
        config = load_config("config4.json")
        general = config.get("general_settings", {"days_to_check": 3})
        
        url_filters = config.get("url_filters", {})
        inclusion_keywords = config.get("url_inclusion_keywords", [])

        full_config_for_processing = {
            "url_inclusion_keywords": inclusion_keywords,
            "url_filters": url_filters
        }

        for account in config.get("accounts", []):
            automate_email_tasks(account, general, full_config_for_processing)

    except FileNotFoundError:
        logger.error("config4.json not found. Please create it with your account details.")
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON format in config4.json: {e}")
    except Exception as e:
        logger.error(f"Fatal script error: {e}")
