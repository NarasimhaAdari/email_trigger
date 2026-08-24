import imaplib
import email
import re
import datetime
import requests
import json
import time
from html import unescape


# ============================================================
# URL Regex
# ============================================================

URL_PATTERN = re.compile(
    r'(https?://\S+)'
    r'|'
    r'<a\s+href=[\'"]?([^\'" >]+)',
    re.IGNORECASE
)


# ============================================================
# CHANGE 1:
# Expanded unsubscribe exclusion pattern.
#
# Your original pattern only checked a limited number of words.
# We now check more variations commonly used in unsubscribe URLs.
# ============================================================

UNSUBSCRIBE_PATTERN = re.compile(
    r'''
    unsubscribe
    |opt[\s_-]?out
    |opt[\s_-]?out[\s_-]?of
    |remove
    |remove[\s_-]?me
    |remove[\s_-]?email
    |remove[\s_-]?emails
    |mailing[\s_-]?list
    |email[\s_-]?list
    |no[\s_-]?email
    |manage[\s_-]?preferences?
    |manage[\s_-]?subscription
    |email[\s_-]?preferences?
    |email[\s_-]?settings?
    |subscription[\s_-]?preferences?
    |subscription[\s_-]?settings?
    |preferences?
    ''',
    re.IGNORECASE | re.VERBOSE
)


# ============================================================
# CHANGE 2:
# New pattern for VISIBLE LINK TEXT.
#
# This catches cases like:
#
# <a href="https://random-domain.com/abc123">
#     Unsubscribe
# </a>
#
# The URL doesn't contain "unsubscribe", but the visible text does.
# ============================================================

UNSUBSCRIBE_TEXT_PATTERN = re.compile(
    r'''
    unsubscribe
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
    ''',
    re.IGNORECASE | re.VERBOSE
)


# ============================================================
# CHANGE 3:
# New regex to extract BOTH:
#
#     href URL
#     visible link text
#
# This is more reliable than only extracting the URL.
# ============================================================

ANCHOR_PATTERN = re.compile(
    r'<a\s+[^>]*href=[\'"]([^\'"]+)[\'"][^>]*>(.*?)</a>',
    re.IGNORECASE | re.DOTALL
)


# ============================================================
# List of common Spam folder names to check
# ============================================================

COMMON_SPAM_FOLDERS = [
    "[Gmail]/Spam",
    "Spam",
]


# ============================================================
# URL Inclusion Keywords
# ============================================================

URL_INCLUSION_KEYWORDS = [
    "service-federalfiling", "wisechoiceloans", "bestloansquick",
    "federalfilinginfo", "izbuys", "insurvo", "maison7",
    "moengage", "bogs", "powerrefinance", "labelaarna",
    "dharishahayurveda", "infoloanoptions", "lizbuys",
    "anveshan", "thefinanciallyfreeteacher", "sundariihandmade",
    "veterandebthelp", "usemailora.com", "govloanoptions",
    "redbus", "financiallyfreenurse", "thedebtfreefirstresponder",
    "debtfreefirstresponder", "spoonacular", "govratealerts",
    "thedebtfreeteacher", "veterandebtassistance", "bigbustours",
    "infoquickenloans", "mailora", "mail", "govloanoptions",
    "sendibm3", "getagovtloan", "expresshomes", "purpawse",
    "swtantra", "usemailora", "use", "quick", "insurvo",
    "famyo", "businesstodayplus", "felloauth", "zola",
    "iffcourbangardens", "principalnews", "mailora",
    "9ugks.r.sp1-brevo", "federalfiling", "federal-filing",
    "thefederalfiling", "accountancybreakdowninfo", "useme",
    "govratealerts", "barrettfinancial", "marketingnewsdesk",
    "charleskeith", "usnews", "executivebreakdownnews",
    "bonfino", "edition", "industryslice", "usemailora",
    "pymnts", "communications.pymnts", "economy", "govloanoptions",
    "firstcry", "labor-economy", "spending", "martech",
    "usnews", "latimes", "marketscreener", "inshot",
    "outlookbusiness", "summit", "russell", "ferrari",
    "letstalk", "bummer", "indianexpress", "imbaglobal",
    "updates.quicklly", "vaprassociates", "financesolutions",
    "linkedin", "sendibm", "tokyopens", "yplayz", "ryze",
    "meet5", "loandepot", "rytbank", "mail", "houseofekam",
    "nature4nature", "legalpracticepulse", "indiatimes",
    "charleskeith", "offers", "servicelive", "outlookindia",
    "openai", "googleplay", "sendclean", "charleskeith",
    "intoday", "allidhealth", "getmychoices", "instagram",
    "letter", "okhai", "alltimeoffers", "anveshan",
    "infodaily", "smebreakdown", "vperfumes",
    "mwgzwaycuddbhald", "dispatch", "sj-r", "slice",
    "menewsdigest", "marketingnewsbrief", "retailbreakdown",
    "firstcry", "dailyinfo", "dappunk", "goodwins",
    "dictionary", "jisora", "theater", "govratealerts",
    "redirect.usemailora.com", "arushafoods", "primawellness",
    "boga", "uniondebtassistance", "cor2ed", "otrack",
    "elink.getdailyhomeinfo"
]


# Pre-process keywords for case-insensitive matching
URL_INCLUSION_KEYWORDS_LOWER = [
    k.lower() for k in URL_INCLUSION_KEYWORDS
]


# ============================================================
# CHANGE 4:
# New helper function to clean HTML from link text.
# ============================================================

def clean_link_text(text):

    # Remove HTML tags inside the anchor
    text = re.sub(r'<[^>]+>', ' ', text)

    # Decode HTML entities
    text = unescape(text)

    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)

    return text.strip()


# ============================================================
# CHANGE 5:
# Central unsubscribe checker.
#
# It checks BOTH:
#
#   1. URL
#   2. Visible link text
#
# ============================================================

def is_unsubscribe_link(url, link_text=""):

    url_lower = url.lower()
    text_lower = link_text.lower()

    # Check URL
    if UNSUBSCRIBE_PATTERN.search(url_lower):
        return True

    # CHANGE:
    # Check visible text of the hyperlink.
    if UNSUBSCRIBE_TEXT_PATTERN.search(text_lower):
        return True

    return False


# ============================================================
# CHANGE 6:
# Completely updated URL extraction/filtering function.
#
# Your inclusion keyword logic is retained.
# ============================================================

def extract_and_filter_urls(message_body):

    """
    Extracts unique URLs, filters them by:
        1. Unsubscribe rules
        2. Inclusion keywords

    Returns:
        (list_of_urls_to_open, boolean_if_any_url_matched)
    """

    urls_to_open = set()
    found_any_match = False
    url_count = 0


    # ========================================================
    # CHANGE:
    # First inspect HTML <a> elements.
    #
    # This gives us:
    #
    #     URL
    #     Visible text
    #
    # so tracking unsubscribe URLs can be detected.
    # ========================================================

    for match in ANCHOR_PATTERN.finditer(message_body):

        if url_count >= 2:
            break

        url = match.group(1)
        raw_link_text = match.group(2)

        link_text = clean_link_text(raw_link_text)

        url = url.strip().rstrip('\'">.')

        if not url.lower().startswith(("http://", "https://")):
            continue


        # ====================================================
        # CHANGE:
        # Check unsubscribe BEFORE inclusion keywords.
        #
        # This is important because an unsubscribe URL should
        # NEVER be opened even if its domain happens to appear
        # in your inclusion keyword list.
        # ====================================================

        if is_unsubscribe_link(url, link_text):

            print(
                f"     -> BLOCKED unsubscribe link: "
                f"'{link_text}' -> {url}"
            )

            continue


        # ====================================================
        # Existing inclusion keyword logic
        # ====================================================

        url_lower = url.lower()

        found_inclusion_match = any(
            keyword in url_lower
            for keyword in URL_INCLUSION_KEYWORDS_LOWER
        )


        if found_inclusion_match:

            found_any_match = True

            if url not in urls_to_open:

                urls_to_open.add(url)
                url_count += 1


    # ========================================================
    # CHANGE:
    # Second pass for plain-text URLs.
    #
    # These don't have an <a> tag or visible link text.
    # ========================================================

    if url_count < 2:

        plain_url_pattern = re.compile(
            r'https?://[^\s<>"\']+',
            re.IGNORECASE
        )

        for match in plain_url_pattern.finditer(message_body):

            if url_count >= 2:
                break

            url = match.group(0)

            url = url.strip().rstrip('\'">.')

            if not url.lower().startswith(("http://", "https://")):
                continue


            # =================================================
            # CHANGE:
            # Unsubscribe check for plain URLs.
            # =================================================

            if is_unsubscribe_link(url):

                print(
                    f"     -> BLOCKED unsubscribe URL: {url}"
                )

                continue


            url_lower = url.lower()

            found_inclusion_match = any(
                keyword in url_lower
                for keyword in URL_INCLUSION_KEYWORDS_LOWER
            )


            if found_inclusion_match:

                found_any_match = True

                if url not in urls_to_open:

                    urls_to_open.add(url)
                    url_count += 1


    return sorted(list(urls_to_open)), found_any_match


# ============================================================
# Email Body
# ============================================================

def get_email_body(full_msg):

    """Parses a full email message object to get the text or HTML body."""

    body = ""

    for part in full_msg.walk():

        ctype = part.get_content_type()

        if ctype == 'text/html':

            try:

                return part.get_payload(
                    decode=True
                ).decode()

            except:

                continue


        elif ctype == 'text/plain' and not body:

            try:

                body = part.get_payload(
                    decode=True
                ).decode()

            except:

                pass


    return body


# ============================================================
# Spam → Inbox
# ============================================================

def move_spam_to_inbox(mail, dest_mailbox, date_filter):

    """
    Iterates through common spam folder names to move UNSEEN mails
    to the destination mailbox.
    """

    print(
        "  -> Checking Spam/Junk folders to move emails..."
    )


    for folder in COMMON_SPAM_FOLDERS:

        try:

            status, _ = mail.select(folder)

            if status != 'OK':
                continue


            search_criteria = (
                f'(UNSEEN SINCE "{date_filter}")'
            )

            status, data = mail.search(
                None,
                search_criteria
            )


            if status == 'OK' and data[0]:

                email_ids = data[0].split()

                count = len(email_ids)

                print(
                    f"     Found {count} emails in "
                    f"'{folder}'. Moving to '{dest_mailbox}'..."
                )


                for uid in email_ids:

                    res = mail.copy(
                        uid,
                        dest_mailbox
                    )


                    if res[0] == 'OK':

                        mail.store(
                            uid,
                            '+FLAGS',
                            '\\Deleted'
                        )


                mail.expunge()


        except Exception:

            continue


# ============================================================
# Core Automation Logic
# ============================================================

def automate_email_tasks(account_config, general_config):

    """
    Connects to one email account, moves spam,
    filters emails and processes URLs.
    """

    email_address = account_config['email_address']
    app_password = account_config['app_password']
    imap_server = account_config['imap_server']
    mailbox = account_config['mailbox']

    days = general_config['days_to_check']


    print(
        f"\n--- Processing Account: "
        f"{account_config.get('account_name', email_address)} ---"
    )


    try:

        date_filter = (
            datetime.date.today()
            - datetime.timedelta(days=days)
        ).strftime("%d-%b-%Y")


        mail = imaplib.IMAP4_SSL(
            imap_server
        )

        mail.login(
            email_address,
            app_password
        )


        # ====================================================
        # STEP 1: Move Spam to Inbox
        # ====================================================

        move_spam_to_inbox(
            mail,
            mailbox,
            date_filter
        )


        # ====================================================
        # STEP 2: Select Inbox
        # ====================================================

        mail.select(
            mailbox,
            readonly=False
        )


        search_criteria = (
            f'(UNSEEN SINCE "{date_filter}")'
        )


        status, data = mail.search(
            None,
            search_criteria
        )


        if status != 'OK' or not data[0]:

            print(
                f"[{email_address}] "
                f"No UNSEEN emails found in {mailbox} "
                f"since {date_filter}."
            )

            mail.logout()

            return


        email_ids = data[0].split()


        print(
            f"[{email_address}] Found "
            f"{len(email_ids)} UNSEEN emails to process."
        )


        mails_to_act_on = []


        # ====================================================
        # Fetch, Filter, Set Flags
        # ====================================================

        for uid in email_ids:

            status, msg_data_full = mail.fetch(
                uid,
                '(RFC822)'
            )


            full_msg = email.message_from_bytes(
                msg_data_full[0][1]
            )


            email_body = get_email_body(
                full_msg
            )


            urls_to_open, found_any_match = (
                extract_and_filter_urls(
                    email_body
                )
            )


            if found_any_match:

                mail.store(
                    uid,
                    '+FLAGS',
                    '\\Seen'
                )


                mails_to_act_on.append(
                    (
                        uid,
                        full_msg,
                        urls_to_open
                    )
                )


            else:

                mail.store(
                    uid,
                    '-FLAGS',
                    '\\Seen'
                )


                print(
                    f"  -> Email from "
                    f"{full_msg.get('From', 'Unknown')}. "
                    f"Marking as UNREAD "
                    f"(No keyword match)."
                )


        # ====================================================
        # Visit URLs silently
        # ====================================================

        if mails_to_act_on:

            print(
                f"\n[{email_address}] "
                f"Visiting URLs in background for "
                f"{len(mails_to_act_on)} emails."
            )


            for uid, full_msg, urls_to_open in mails_to_act_on:

                print(
                    f"  -> Email from "
                    f"{full_msg.get('From', 'Unknown')}, "
                    f"Subject: "
                    f"{full_msg.get('Subject', 'No Subject')}"
                )


                for url in urls_to_open:

                    # =================================================
                    # CHANGE 7:
                    # FINAL SAFETY CHECK immediately before GET.
                    #
                    # Even if something accidentally passes through
                    # extract_and_filter_urls(), we check one more time
                    # immediately before making the HTTP request.
                    # =================================================

                    if is_unsubscribe_link(url):

                        print(
                            f"     -> FINAL BLOCK: "
                            f"unsubscribe URL: {url}"
                        )

                        continue


                    print(
                        f"     -> Pinging URL: {url}"
                    )


                    try:

                        headers = {
                            'User-Agent':
                            'Mozilla/5.0 '
                            '(Macintosh; Intel Mac OS X 10_15_7) '
                            'AppleWebKit/537.36 '
                            '(KHTML, like Gecko) '
                            'Chrome/120.0.0.0 '
                            'Safari/537.36'
                        }


                        response = requests.get(
                            url,
                            headers=headers,
                            timeout=10
                        )


                        if response.status_code == 200:

                            print(
                                "        [Success]"
                            )

                        else:

                            print(
                                f"        "
                                f"[Warning: Status "
                                f"{response.status_code}]"
                            )


                    except Exception as e:

                        print(
                            f"        "
                            f"[Failed to visit URL: {e}]"
                        )


                    time.sleep(1)


        else:

            print(
                f"[{email_address}] "
                f"No URLs matched the inclusion keywords."
            )


        mail.logout()


        print(
            f"\n[{email_address}] "
            f"Task completed successfully."
        )


    except Exception as e:

        print(
            f"An error occurred with "
            f"{email_address}: {e}"
        )


    finally:

        if (
            'mail' in locals()
            and mail
            and mail.state != 'LOGOUT'
        ):

            try:

                mail.logout()

            except:

                pass


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    try:

        with open(
            'config4.json',
            'r'
        ) as f:

            config = json.load(f)


        general_settings = (
            config['general_settings']
        )


        for account in config['accounts']:

            automate_email_tasks(
                account,
                general_settings
            )


    except FileNotFoundError:

        print(
            "ERROR: config4.json not found. "
            "Please create the file with your account details."
        )


    except KeyError as e:

        print(
            f"ERROR: Missing required key "
            f"in config4.json: {e}. "
            f"Check that all required settings are present."
        )


    except json.JSONDecodeError as e:

        print(
            f"ERROR: Invalid JSON syntax "
            f"in config4.json: {e}. "
            f"Use an online JSON validator "
            f"to check that the JSON is valid."
        )


    except Exception as e:

        print(
            f"A general script error occurred: {e}"
        )
