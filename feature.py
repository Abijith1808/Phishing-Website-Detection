import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date
from urllib.parse import urlparse

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self.features = []

        self.extract_features()

    def extract_features(self):
        try:
            self.response = requests.get(self.url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            self.whois_response = whois.whois(self.domain)

            # Extract features
            self.features = [
                self.UsingIp(),
                self.longUrl(),
                self.shortUrl(),
                self.symbol(),
                self.redirecting(),
                self.prefixSuffix(),
                self.SubDomains(),
                self.Hppts(),
                self.DomainRegLen(),
                self.Favicon(),
                self.NonStdPort(),
                self.HTTPSDomainURL(),
                self.RequestURL(),
                self.AnchorURL(),
                self.LinksInScriptTags(),
                self.ServerFormHandler(),
                self.InfoEmail(),
                self.AbnormalURL(),
                self.WebsiteForwarding(),
                self.StatusBarCust(),
                self.DisableRightClick(),
                self.UsingPopupWindow(),
                self.IframeRedirection(),
                self.AgeofDomain(),
                self.DNSRecording(),
                self.WebsiteTraffic(),
                self.PageRank(),
                self.GoogleIndex(),
                self.LinksPointingToPage(),
                self.StatsReport()
            ]
        except Exception as e:
            print(f"Error during feature extraction: {e}")

    # 1. UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except ValueError:
            return 1

    # 2. longUrl
    def longUrl(self):
        length = len(self.url)
        if length < 54:
            return 1
        elif length <= 75:
            return 0
        return -1

    # 3. shortUrl
    def shortUrl(self):
        match = re.search(r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                           r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                           r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                           r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                           r'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                           r'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                           r'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', 
                           self.url)
        return -1 if match else 1

    # 4. Symbol@
    def symbol(self):
        return -1 if "@" in self.url else 1

    # 5. Redirecting//
    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    # 6. prefixSuffix
    def prefixSuffix(self):
        return -1 if '-' in self.domain else 1

    # 7. SubDomains
    def SubDomains(self):
        dot_count = self.url.count('.')
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8. HTTPS
    def Hppts(self):
        return 1 if self.urlparse.scheme == 'https' else -1

    # 9. DomainRegLen
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except Exception as e:
            return -1

    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for link in head.find_all('link', href=True):
                    if self.url in link['href'] or self.domain in link['href']:
                        return 1
            return -1
        except Exception as e:
            return -1

    # 11. NonStdPort
    def NonStdPort(self):
        return -1 if ':' in self.domain else 1

    # 12. HTTPSDomainURL
    def HTTPSDomainURL(self):
        return -1 if 'https' in self.domain else 1

    # 13. RequestURL
    def RequestURL(self):
        try:
            success = 0
            total = 0

            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.url in element['src'] or self.domain in element['src'] or len(re.findall(r'\.', element['src'])) == 1:
                        success += 1

            percentage = success / float(total) * 100 if total > 0 else 0
            if percentage < 22.0:
                return 1
            elif 22.0 <= percentage < 61.0:
                return 0
            return -1
        except Exception as e:
            return -1

    # 14. AnchorURL
    def AnchorURL(self):
        try:
            total, unsafe = 0, 0
            for a in self.soup.find_all('a', href=True):
                total += 1
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe += 1

            percentage = unsafe / float(total) * 100 if total > 0 else 0
            if percentage < 31.0:
                return 1
            elif 31.0 <= percentage < 67.0:
                return 0
            return -1
        except Exception as e:
            return -1

    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            total, success = 0, 0

            for tag in ['link', 'script']:
                for element in self.soup.find_all(tag, src=True):
                    total += 1
                    if self.url in element['src'] or self.domain in element['src']:
                        success += 1

            percentage = success / float(total) * 100 if total > 0 else 0
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            return -1
        except Exception as e:
            return -1

    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            forms = self.soup.find_all('form')
            return 1 if len(forms) > 0 else -1
        except Exception as e:
            return -1

    # 17. InfoEmail
    def InfoEmail(self):
        try:
            email_patterns = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
            for script in self.soup.find_all('script'):
                if re.search(email_patterns, script.string or ''):
                    return -1
            return 1
        except Exception as e:
            return -1

    # 18. AbnormalURL
    def AbnormalURL(self):
        abnormal_patterns = [r"(\w+)\.\w+\.(\w+)\.(\w+)", r"(\w+)\.(\w+)\.\w+\.\w+", r"(\w+)-(\w+)\.(\w+)"]
        return -1 if any(re.search(pattern, self.url) for pattern in abnormal_patterns) else 1

    # 19. WebsiteForwarding
    def WebsiteForwarding(self):
        try:
            status = requests.get(self.url, allow_redirects=False)
            return -1 if status.is_redirect else 1
        except Exception as e:
            return -1

    # 20. StatusBarCust
    def StatusBarCust(self):
        return -1 if 'status' in self.response.text.lower() else 1

    # 21. DisableRightClick
    def DisableRightClick(self):
        return -1 if 'oncontextmenu' in self.response.text.lower() else 1

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        return -1 if 'window.open' in self.response.text.lower() else 1

    # 23. IframeRedirection
    def IframeRedirection(self):
        return -1 if len(self.soup.find_all('iframe')) > 0 else 1

    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date

            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 6 else -1
        except Exception as e:
            return -1

    # 25. DNSRecording
    def DNSRecording(self):
        try:
            return 1 if self.whois_response.domain_name else -1
        except Exception as e:
            return -1

    # 26. WebsiteTraffic
    def WebsiteTraffic(self):
        try:
            return 1 if self.whois_response.domain_name else -1
        except Exception as e:
            return -1

    # 27. PageRank
    def PageRank(self):
        try:
            total = len(list(search(self.url)))
            return 1 if total > 0 else -1
        except Exception as e:
            return -1

    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            total = len(list(search(self.url)))
            return 1 if total > 0 else -1
        except Exception as e:
            return -1

    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            return 1 if self.soup.find_all('a') else -1
        except Exception as e:
            return -1

    # 30. StatsReport
    def StatsReport(self):
        try:
            return 1 if 'stats' in self.response.text.lower() else -1
        except Exception as e:
            return -1
