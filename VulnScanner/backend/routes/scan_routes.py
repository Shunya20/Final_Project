from flask import Blueprint, request, jsonify, current_app
from utils.scanner import scan_target
from bson.objectid import ObjectId
import datetime

scan_bp = Blueprint('scan', __name__)

@scan_bp.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    targets = data.get("targets", [])

    if not targets or not isinstance(targets, list):
        return jsonify({"error": "No valid targets provided"}), 400

    scan_results = []
    scans_collection = current_app.config["SCANS_COLLECTION"]

    for target in targets:
        result = scan_target(target)
        result["timestamp"] = datetime.datetime.utcnow().isoformat()
        inserted = scans_collection.insert_one(result)

        scan_results.append({
            "target": target,
            "scan_id": str(inserted.inserted_id),
            "result": result
        })

    return jsonify(scan_results)

@scan_bp.route("/history", methods=["GET"])
def get_history():
    scans_collection = current_app.config["SCANS_COLLECTION"]
    all_scans = scans_collection.find({}, {"_id": 1, "host": 1, "scan_time": 1, "timestamp": 1})
    history = [{"scan_id": str(doc["_id"]), **{k: v for k, v in doc.items() if k != "_id"}} for doc in all_scans]
    return jsonify(history)

@scan_bp.route("/report/<scan_id>", methods=["GET"])
def get_report(scan_id):
    scans_collection = current_app.config["SCANS_COLLECTION"]
    try:
        result = scans_collection.find_one({"_id": ObjectId(scan_id)})
        if not result:
            return jsonify({"error": "Scan not found"}), 404
        result["_id"] = str(result["_id"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Invalid ID or server error: {e}"}), 500
