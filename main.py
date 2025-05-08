import requests
import time


api_key=("Enter your VirusTotal API key: ")


def check_url_virustotal(url):
    headers = {
        "x-apikey": api_key
    }

    # Step 1: Send URL to VirusTotal
    scan_response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if scan_response.status_code != 200:
        print("❌ Failed to send URL for scanning.")
        return

    scan_result = scan_response.json()
    url_id = scan_result["data"]["id"]

    # Step 2: Get report (may take time, wait until completed)
    report_url = f"https://www.virustotal.com/api/v3/analyses/{url_id}"
    
    while True:
        report_response = requests.get(report_url, headers=headers)
        if report_response.status_code != 200:
            print("❌ Failed to get scan report.")
            return

        report_result = report_response.json()
        status = report_result["data"]["attributes"]["status"]
        if status == "completed":
            break
        print("⏳ Waiting for analysis to complete...")
        time.sleep(2)

    stats = report_result["data"]["attributes"]["stats"]

    print(f"\n🔍 Result for: {url}")
    print(f"✅ Harmless: {stats['harmless']}")
    print(f"❗ Malicious: {stats['malicious']}")
    print(f"⚠️ Suspicious: {stats['suspicious']}")
    print(f"🕵️ Undetected: {stats['undetected']}")
    print(f"💀 Timeout: {stats['timeout']}")

user_url = input("Enter a URL to scan with VirusTotal: ")
check_url_virustotal(user_url)
