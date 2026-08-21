import imaplib
import email
import re
import datetime
import requests
import json
import time

# URL Regex: Finds standard URLs (http/https) OR links inside href="..."
URL_PATTERN = re.compile(
    r'(https?://\S+)'
    r'|'
    r'<a\s+href=[\'"]?([^\'" >]+)',
    re.IGNORECASE
)

# Unsubscribe Exclusion Pattern: Matches common unsubscribe/opt-out keywords in a URL
UNSUBSCRIBE_PATTERN = re.compile(
    r'unsubscribe|optout|remove|manage|mailing_list|no_email|preferences',
    re.IGNORECASE
)

# List of common Spam folder names to check
COMMON_SPAM_FOLDERS = [
    "[Gmail]/Spam",  # Gmail
    "Spam",          # General
]

# --- URL Inclusion Keywords ---
URL_INCLUSION_KEYWORDS = [
    "service-federalfiling", "wisechoiceloans", "bestloansquick", "federalfilinginfo","izbuys","insurvo","maison7",
    "moengage", "bogs", "powerrefinance", "labelaarna", "dharishahayurveda","infoloanoptions","lizbuys","anveshan",
    "thefinanciallyfreeteacher", "sundariihandmade", "veterandebthelp","usemailora.com","govloanoptions","redbus",
    "financiallyfreenurse", "thedebtfreefirstresponder", "debtfreefirstresponder","spoonacular","govratealerts",
    "thedebtfreeteacher", "veterandebtassistance", "bigbustours", "infoquickenloans","mailora","mail","govloanoptions",   
    "sendibm3", "getagovtloan", "expresshomes", "purpawse", "swtantra","usemailora","use","quick","insurvo","famyo",
    "businesstodayplus", "felloauth", "zola", "iffcourbangardens", "principalnews","mailora","9ugks.r.sp1-brevo",
    "federalfiling", "federal-filing", "thefederalfiling", "accountancybreakdowninfo","useme","govratealerts",
    "barrettfinancial", "marketingnewsdesk", "charleskeith", "usnews","executivebreakdownnews","bonfino","edition",
    "industryslice", "usemailora", "pymnts", "communications.pymnts", "economy","govloanoptions","firstcry",
    "labor-economy", "spending", "martech", "usnews", "latimes", "marketscreener","inshot","outlookbusiness",
    "summit", "russell", "ferrari", "letstalk", "bummer", "indianexpress","imbaglobal","updates.quicklly","vaprassociates",
    "financesolutions", "linkedin", "sendibm", "tokyopens", "yplayz", "ryze","meet5","loandepot","rytbank","mail",
    "houseofekam", "nature4nature", "legalpracticepulse", "indiatimes","charleskeith","offers","servicelive",
    "outlookindia", "openai", "googleplay", "sendclean", "charleskeith", "intoday","allidhealth","getmychoices",
    "instagram", "letter", "okhai", "alltimeoffers", "anveshan", "infodaily","smebreakdown","vperfumes","mwgzwaycuddbhald",
    "dispatch","sj-r","slice","menewsdigest","marketingnewsbrief","retailbreakdown","firstcry","dailyinfo",
    "dappunk", "goodwins", "dictionary", "jisora", "theater", "govratealerts","redirect.usemailora.com",
    "arushafoods", "primawellness", "boga", "uniondebtassistance", "cor2ed","otrack","elink.getdailyhomeinfo"
]
# Pre-process keywords for case-insensitive matching
URL_INCLUSION_KEYWORDS_LOWER = [k.lower() for k in URL_INCLUSION_KEYWORDS]

# ------------------- Helper Functions -------------------

def extract_and_filter_urls(message_body):
    """
    Extracts unique URLs, filters them by exclusion/inclusion lists, 
    and returns a tuple: (list_of_urls_to_open, boolean_if_any_url_matched)
    """
    urls_to_open = set()
    found_any_match = False 
    matches = URL_PATTERN.findall(message_body)
    url_count = 0

    for match in matches:
        if url_count >= 2:
            break

        url = match[0] if match[0] else match[1]
        url = url.rstrip('\'">.')

        if url.startswith('http'):
            url_lower = url.lower()

            if UNSUBSCRIBE_PATTERN.search(url_lower):
                continue

            found_inclusion_match = any(
                keyword in url_lower for keyword in URL_INCLUSION_KEYWORDS_LOWER
            )

            if found_inclusion_match:
                found_any_match = True 
                if url_count < 2 and url not in urls_to_open:
                    urls_to_open.add(url)
                    url_count += 1 

    return sorted(list(urls_to_open)), found_any_match

def get_email_body(full_msg):
    """Parses a full email message object to get the text or HTML body."""
    body = ""
    for part in full_msg.walk():
        ctype = part.get_content_type()
        if ctype == 'text/html':
            try:
                return part.get_payload(decode=True).decode()
            except:
                continue
        elif ctype == 'text/plain' and not body:
            try:
                body = part.get_payload(decode=True).decode()
            except:
                pass
    return body

def move_spam_to_inbox(mail, dest_mailbox, date_filter):
    """
    Iterates through common spam folder names. If found, moves UNSEEN mails
    to the destination mailbox (usually INBOX).
    """
    print("  -> Checking Spam/Junk folders to move emails...")
    
    for folder in COMMON_SPAM_FOLDERS:
        try:
            # Try to select the spam folder
            status, _ = mail.select(folder)
            if status != 'OK':
                continue # Folder doesn't exist on this server, try next

            # Search for unseen emails in this spam folder
            search_criteria = f'(UNSEEN SINCE "{date_filter}")'
            status, data = mail.search(None, search_criteria)
            
            if status == 'OK' and data[0]:
                email_ids = data[0].split()
                count = len(email_ids)
                print(f"     Found {count} emails in '{folder}'. Moving to '{dest_mailbox}'...")

                for uid in email_ids:
                    # 1. Copy to Inbox
                    res = mail.copy(uid, dest_mailbox)
                    if res[0] == 'OK':
                        # 2. Mark as Deleted in Spam (only if copy succeeded)
                        mail.store(uid, '+FLAGS', '\\Deleted')
                
                # 3. Permanently remove deleted emails from Spam
                mail.expunge()
            
        except Exception as e:
            # Just continue to the next folder if something fails
            continue

# ------------------- Core Automation Logic -------------------

def automate_email_tasks(account_config, general_config):
    """Connects to one email account, MOVES SPAM, then filters and processes."""

    email_address = account_config['email_address']
    app_password = account_config['app_password']
    imap_server = account_config['imap_server']
    mailbox = account_config['mailbox'] # Usually "INBOX"
    days = general_config['days_to_check']

    print(f"\n--- Processing Account: {account_config.get('account_name', email_address)} ---")

    try:
        date_filter = (datetime.date.today() - datetime.timedelta(days=days)).strftime("%d-%b-%Y")
        mail = imaplib.IMAP4_SSL(imap_server)
        mail.login(email_address, app_password)

        # --- STEP 1: Move Spam to Inbox ---
        move_spam_to_inbox(mail, mailbox, date_filter)

        # --- STEP 2: Select Inbox and Process ---
        mail.select(mailbox, readonly=False)

        search_criteria = f'(UNSEEN SINCE "{date_filter}")'
        status, data = mail.search(None, search_criteria)

        if status != 'OK' or not data[0]:
            print(f"[{email_address}] No UNSEEN emails found in {mailbox} since {date_filter}.")
            mail.logout()
            return

        email_ids = data[0].split()
        print(f"[{email_address}] Found {len(email_ids)} UNSEEN emails to process in {mailbox}.")

        mails_to_act_on = []

        # Fetch, Filter, and Set Flags
        for uid in email_ids:
            status, msg_data_full = mail.fetch(uid, '(RFC822)')
            full_msg = email.message_from_bytes(msg_data_full[0][1])

            email_body = get_email_body(full_msg)
            
            urls_to_open, found_any_match = extract_and_filter_urls(email_body)
            
            if found_any_match:
                mail.store(uid, '+FLAGS', '\\Seen')
                mails_to_act_on.append((uid, full_msg, urls_to_open))
            else:
                mail.store(uid, '-FLAGS', '\\Seen')
                print(f"  -> Email from {full_msg.get('From', 'Unknown')}. Marking as UNREAD (No keyword match).")


        # Visit URLs silently in the background
        if mails_to_act_on:
            print(f"\n[{email_address}] Visiting URLs in background for {len(mails_to_act_on)} emails.")
            
            for uid, full_msg, urls_to_open in mails_to_act_on:
                print(f"  -> Email from {full_msg.get('From', 'Unknown')}, Subject: {full_msg.get('Subject', 'No Subject')}")

                for url in urls_to_open:
                    print(f"     -> Pinging URL: {url}")
                    try:
                        # Uses a custom header to look like a normal Mac browser
                        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
                        
                        # Visits the link silently. Timeout prevents hanging on bad links.
                        response = requests.get(url, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            print("        [Success]")
                        else:
                            print(f"        [Warning: Status {response.status_code}]")
                            
                    except Exception as e:
                        print(f"        [Failed to visit URL: {e}]")
                    
                    time.sleep(1) # Brief pause so we don't spam the servers too fast

        else:
            print(f"[{email_address}] No URLs matched the inclusion keywords.")

        mail.logout()
        print(f"\n[{email_address}] Task completed successfully.")

    except Exception as e:
        print(f"An error occurred with {email_address}: {e}")
    finally:
        if 'mail' in locals() and mail and mail.state != 'LOGOUT':
            try:
                mail.logout()
            except:
                pass

if __name__ == "__main__":
    try:
        with open('config4.json', 'r') as f:
            config = json.load(f)

        general_settings = config['general_settings']
        for account in config['accounts']:
            automate_email_tasks(account, general_settings)

    except FileNotFoundError:
        print("ERROR: config4.json not found. Please create the file with your account details.")
    except KeyError as e:
        print(f"ERROR: Missing required key in config4.json: {e}. Check that all required settings are present.")
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON syntax in config4.json: {e}. Use an online JSON validator to check your file.")
    except Exception as e:
        print(f"A general script error occurred: {e}")
