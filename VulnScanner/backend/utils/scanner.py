import os
import subprocess
import json
import requests
import datetime
import time
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
from dotenv import load_dotenv
import argparse

load_dotenv()

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client["vulnscanner"]
scans = db["results"]

def fetch_cve(service_name, version):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service_name} {version}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        cves = []

        if "vulnerabilities" in data:
            for item in data["vulnerabilities"]:
                cve_id = item["cve"]["id"]
                descriptions = item["cve"]["descriptions"]
                description = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description available.")
                cvss_data = item["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity = cvss_data.get("baseSeverity", "Unknown")

                cves.append({
                    "id": cve_id,
                    "description": description,
                    "cvss": cvss_score,
                    "severity": severity
                })
        return cves
    except Exception as e:
        print(f"⚠️ Error fetching CVEs: {e}")
        return []

def run_nikto_scan(port=80, target_url="host.docker.internal"):
    try:
        output_path = os.path.join(os.getcwd(), "nikto_output.json")

        command = [
            "docker", "run", "--rm",
            "-v", f"{os.getcwd()}:/data",
            "nikto/nikto", "-h", target_url,
            "-Format", "json", "-output", "/data/nikto_output.json"
        ]

        if "://" not in target_url:
            command.insert(4, "-p")
            command.insert(5, str(port))

        if port == 443 or "https" in target_url.lower():
            command.append("-ssl")

        subprocess.run(command, check=True)

        with open(output_path, "r") as f:
            result = json.load(f)

        os.remove(output_path)
        return result

    except Exception as e:
        print(f"❌ Nikto scan error: {e}")
        return [{"error": str(e)}]

def run_nmap_scan(target):
    import nmap
    scanner = nmap.PortScanner()
    try:
        print("🕵️‍♂️ Running Nmap scan...")
        scanner.scan(target, arguments="-p 1-1000 -sV --version-intensity 9 -Pn")
        return scanner
    except Exception as e:
        print(f"❌ Nmap scan failed: {e}")
        return None

def scan_target(target, save_to_db=True):
    original_target = target
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://")[1].split("/")[0]

    print(f"🔍 Scanning target: {target}")

    scanner = None
    for _ in range(3):
        scanner = run_nmap_scan(target)
        if scanner:
            break
        print("⚠️ Retrying Nmap scan...")
        time.sleep(5)

    scan_time = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if not scanner:
        result = {
            "host": original_target,
            "scan_time": scan_time,
            "services": [],
            "nikto_scans": [],
            "error": "Nmap scan failed after retries"
        }
        if save_to_db:
            try:
                scans.insert_one(result)
            except DuplicateKeyError:
                print(f"🚨 Duplicate scan for {original_target} at {scan_time}. Skipping.")
        return result

    results = []
    nikto_results = []

    for host in scanner.all_hosts():
        print(f"📡 Host: {host}")
        for port, service in scanner[host]['tcp'].items():
            service_name = service['name']
            service_version = service.get('version', 'Unknown')
            service_banner = service.get('product', '')

            cves = fetch_cve(service_name, service_version)

            results.append({
                "port": port,
                "service": service_name,
                "version": service_version,
                "banner": service_banner,
                "cves": cves
            })

            if port in [80, 443] or "http" in service_name.lower():
                scheme = "https" if port == 443 or "https" in service_name.lower() else "http"
                target_url = f"{scheme}://{target}:{port}"
                nikto_scan = run_nikto_scan(port, target_url)
                nikto_results.append(nikto_scan)

    result = {
        "host": original_target,
        "scan_time": scan_time,
        "services": results,
        "nikto_scans": nikto_results
    }

    if save_to_db:
        try:
            scans.insert_one(result)
        except DuplicateKeyError:
            print(f"🚨 Duplicate scan for {original_target} at {scan_time}. Skipping.")

    return result

# CLI usage for testing or offline scanning
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a vulnerability scan on a target.")
    parser.add_argument("target", help="Target IP or domain")
    parser.add_argument("--no-db", action="store_true", help="Do not save result to MongoDB")
    parser.add_argument("--export", help="Export result to JSON file")

    args = parser.parse_args()
    result = scan_target(args.target, save_to_db=not args.no_db)

    print(json.dumps(result, indent=2))

    if args.export:
        with open(args.export, "w") as f:
            json.dump(result, f, indent=2)
        print(f"📁 Exported to {args.export}")
