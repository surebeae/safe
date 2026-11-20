#!/usr/bin/env python3
"""mkprofile.py DIR [PRIMARY_PASSWORD]: create an NSS key4.db in DIR (via the
system libnss3) and a Firefox-format logins.json whose usernames and
passwords are encrypted with PK11SDR_Encrypt, as Firefox does."""
import base64, ctypes as C, json, os, sys

d = sys.argv[1]; pw = sys.argv[2].encode() if len(sys.argv) > 2 else b""
os.makedirs(d, exist_ok=True)
nss = C.CDLL("libnss3.so")
class SECItem(C.Structure):
    _fields_ = [("type", C.c_int), ("data", C.POINTER(C.c_ubyte)), ("len", C.c_uint)]
nss.NSS_Initialize.argtypes = [C.c_char_p]*4 + [C.c_uint32]
nss.PK11_GetInternalKeySlot.restype = C.c_void_p
nss.PK11_NeedUserInit.argtypes = [C.c_void_p]
nss.PK11_InitPin.argtypes = [C.c_void_p, C.c_char_p, C.c_char_p]
nss.PK11_CheckUserPassword.argtypes = [C.c_void_p, C.c_char_p]
nss.PK11SDR_Encrypt.argtypes = [C.POINTER(SECItem)]*3 + [C.c_void_p]
nss.PK11_FreeSlot.argtypes = [C.c_void_p]

assert nss.NSS_Initialize(("sql:" + d).encode(), b"", b"", b"secmod.db", 0) == 0, "NSS_Initialize"
slot = nss.PK11_GetInternalKeySlot()
if nss.PK11_NeedUserInit(slot):
    assert nss.PK11_InitPin(slot, None, pw) == 0, "InitPin"
assert nss.PK11_CheckUserPassword(slot, pw) == 0, "login"

def sdr(b):
    buf = (C.c_ubyte * len(b)).from_buffer_copy(b) if b else (C.c_ubyte * 1)()
    data = SECItem(0, C.cast(buf, C.POINTER(C.c_ubyte)), len(b))
    keyid = SECItem(0, None, 0); out = SECItem(0, None, 0)
    assert nss.PK11SDR_Encrypt(C.byref(keyid), C.byref(data), C.byref(out), None) == 0, "SDR"
    return base64.b64encode(C.string_at(out.data, out.len)).decode()

entries = [
    ("https://discord.com", "azulbeae@icloud.com", "disc-pass-1"),
    ("https://accounts.google.com", "azulbeae@icloud.com", "goog\\pass\"2 ünïcode"),
    ("https://Example.ORG:443", "alice", "x" * 300),          # canonicalised, >256 bytes
    ("https://example.org:8443", "bob", "port-pass"),         # non-default port kept
    ("http://plain.example", "carol", "should-skip"),         # plain http: skipped
    ("https://noname.example", "", "pw-without-user"),        # empty username: skipped
    ("https://slash.example", "a/b", "pw"),                   # not representable: skipped
]
logins = []
for i, (host, user, pw_) in enumerate(entries, 1):
    logins.append({"id": i, "hostname": host, "httpRealm": None,
        "formSubmitURL": host, "usernameField": "u", "passwordField": "p",
        "encryptedUsername": sdr(user.encode()), "encryptedPassword": sdr(pw_.encode()),
        "guid": "{%08d-0000-0000-0000-000000000000}" % i, "encType": 1,
        "timeCreated": 1, "timeLastUsed": 1, "timePasswordChanged": 1, "timesUsed": 1})
logins.append({"id": 99, "hostname": "https://weird.example", "encryptedUsername": "AAAA",
               "encryptedPassword": "AAAA", "encType": 0})           # unsupported encType
with open(os.path.join(d, "logins.json"), "w") as f:
    json.dump({"nextId": 100, "logins": logins, "potentiallyVulnerablePasswords": [],
               "dismissedBreachAlertsByLoginGUID": {}, "version": 3}, f)
nss.PK11_FreeSlot(slot); nss.NSS_Shutdown()
print("ok", d)
