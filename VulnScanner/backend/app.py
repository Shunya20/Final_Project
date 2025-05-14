import os
import json
import subprocess
import requests
import datetime
import time
from flask import Flask, jsonify, request
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from bson.objectid import ObjectId
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client["vulnscanner"]
scans = db["results"]

# CVE fetching function
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
                metrics = item["cve"].get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
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

# Nikto scan using Docker
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

# Nmap scan
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

# Main scan function
def scan_target(target):
    original_target = target
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://")[1].split("/")[0]

    print(f"🔍 Scanning target: {target}")
    retries = 3
    scanner = None
    for _ in range(retries):
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
        try:
            scans.insert_one(result)
        except DuplicateKeyError:
            print(f"🚨 Duplicate scan for {original_target} at {scan_time}. Skipping.")
        return result

    results = []
    nikto_results = []

    for host in scanner.all_hosts():
        print(f"📡 Host found: {host}")
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

    try:
        scans.insert_one(result)
    except DuplicateKeyError:
        print(f"🚨 Duplicate scan for {original_target} at {scan_time}. Skipping.")

    return result

# API Routes

@app.route("/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target = data.get("target")
    if not target:
        return jsonify({"error": "No target provided"}), 400

    try:
        result = scan_target(target)
        result_id = result.get("_id") or scans.find_one(sort=[("_id", -1)])["_id"]
        return jsonify({"message": "Scan complete", "scan_id": str(result_id)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/history", methods=["GET"])
def get_history():
    try:
        all_scans = scans.find({}, {"_id": 1, "host": 1, "scan_time": 1})
        history = [{"scan_id": str(doc["_id"]), **{k: v for k, v in doc.items() if k != "_id"}} for doc in all_scans]
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": f"Error retrieving history: {e}"}), 500

@app.route("/report/<scan_id>", methods=["GET"])
def get_report(scan_id):
    try:
        result = scans.find_one({"_id": ObjectId(scan_id)})
        if not result:
            return jsonify({"error": "Scan not found"}), 404
        result["_id"] = str(result["_id"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Invalid ID or server error: {e}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
