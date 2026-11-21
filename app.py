from flask import Flask, render_template, request, session
from flask import send_file, redirect, url_for
from io import BytesIO
import ipaddress
from datetime import datetime

app = Flask(__name__)
app.secret_key = "cyber_security_analyzer_key"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

THRESHOLD = 3          # failed attempts before an IP is "suspicious"
HIGH_THRESHOLD = 5     # failed attempts that make the overall risk HIGH


def fail(message):
    return render_template("index.html", error=message)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "logfile" not in request.files:
        return fail("Please select a log file.")

    uploaded_file = request.files["logfile"]

    if uploaded_file.filename == "":
        return fail("No file selected. Please choose a file.")

    if not uploaded_file.filename.lower().endswith(".txt"):
        return fail("Invalid file type. Please upload a .txt file.")

    file_content = uploaded_file.read()

    if not file_content.strip():
        return fail("The uploaded file is empty. Please upload a file containing log records.")

    try:
        logs = file_content.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        return fail("Unable to read the file. Please upload a valid UTF-8 text file.")

    success_count = failed_count = invalid_count = total_count = 0
    failed_attempts = {}
    hourly = {}   # hour -> {"success": n, "failed": n}

    for log in logs:
        if not log.strip():
            continue

        total_count += 1
        parts = log.split()

        if len(parts) != 3:
            invalid_count += 1
            continue

        ip, event, timestamp = parts

        try:
            ipaddress.ip_address(ip)
            datetime.strptime(timestamp, "%H:%M:%S")
        except ValueError:
            invalid_count += 1
            continue

        if event not in ("LOGIN_SUCCESS", "LOGIN_FAILED"):
            invalid_count += 1
            continue

        hour = int(timestamp[:2])
        bucket = hourly.setdefault(hour, {"success": 0, "failed": 0})

        if event == "LOGIN_SUCCESS":
            success_count += 1
            bucket["success"] += 1
        else:
            failed_count += 1
            bucket["failed"] += 1
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # ---- Most targeted IP ----
    if failed_attempts:
        most_targeted_ip = max(failed_attempts, key=failed_attempts.get)
        maximum_failed_attempts = failed_attempts[most_targeted_ip]
    else:
        most_targeted_ip = "None"
        maximum_failed_attempts = 0

    # ---- Suspicious IPs (sorted, worst first) ----
    suspicious_ips = dict(
        sorted(
            ((ip, c) for ip, c in failed_attempts.items() if c >= THRESHOLD),
            key=lambda item: item[1],
            reverse=True,
        )
    )

    # ---- Risk level ----
    if any(c >= HIGH_THRESHOLD for c in suspicious_ips.values()):
        risk_level, risk_class = "HIGH RISK", "high"
    elif suspicious_ips:
        risk_level, risk_class = "MEDIUM RISK", "medium"
    else:
        risk_level, risk_class = "LOW RISK", "low"

    # ---- Percentages ----
    valid_records = total_count - invalid_count
    if valid_records > 0:
        success_percentage = round(success_count / valid_records * 100, 2)
        failed_percentage = round(failed_count / valid_records * 100, 2)
    else:
        success_percentage = failed_percentage = 0

    # ---- Recommendations ----
    if risk_level == "HIGH RISK":
        recommendations = [
            "Investigate the suspicious IP address immediately.",
            "Consider temporarily blocking the suspicious IP.",
            "Review login activity for possible unauthorized access.",
        ]
    elif risk_level == "MEDIUM RISK":
        recommendations = [
            "Monitor suspicious IP addresses.",
            "Investigate repeated failed login attempts.",
            "Consider strengthening account authentication.",
        ]
    else:
        recommendations = [
            "No suspicious activity detected.",
            "Continue monitoring login activities.",
            "Maintain regular security checks.",
        ]

    # ---- Chart data ----
    top_ips = sorted(failed_attempts.items(), key=lambda i: i[1], reverse=True)[:8]
    ip_labels = [ip for ip, _ in top_ips]
    ip_values = [c for _, c in top_ips]

    if hourly:
        hours = range(min(hourly), max(hourly) + 1)
        hour_labels = [f"{h:02d}:00" for h in hours]
        hour_success = [hourly.get(h, {}).get("success", 0) for h in hours]
        hour_failed = [hourly.get(h, {}).get("failed", 0) for h in hours]
    else:
        hour_labels, hour_success, hour_failed = [], [], []

    # ---- Downloadable text report ----
    lines = [
        "========== SECURITY REPORT ==========",
        "",
        f"Total Records: {total_count}",
        f"Successful Logins: {success_count}",
        f"Failed Logins: {failed_count}",
        f"Invalid Records: {invalid_count}",
        "",
        "Most Targeted IP Address:",
        most_targeted_ip,
        f"Maximum Failed Attempts: {maximum_failed_attempts}",
        "",
        f"Total Suspicious IPs: {len(suspicious_ips)}",
        f"Successful Login Percentage: {success_percentage}%",
        f"Failed Login Percentage: {failed_percentage}%",
        "",
        "Suspicious IP Addresses:",
    ]
    if suspicious_ips:
        lines += [f"{ip} - Failed Attempts: {c}" for ip, c in suspicious_ips.items()]
    else:
        lines.append("None found.")
    lines += ["", "Security Risk Level:", risk_level, "", "Security Recommendations:"]
    lines += ["- " + r for r in recommendations]
    lines += ["", "====================================="]
    session["report_text"] = "\n".join(lines)

    return render_template(
        "index.html",
        total=total_count,
        invalid=invalid_count,
        success=success_count,
        failed=failed_count,
        suspicious=suspicious_ips,
        risk=risk_level,
        risk_class=risk_class,
        recommendations=recommendations,
        success_percentage=success_percentage,
        failed_percentage=failed_percentage,
        most_targeted_ip=most_targeted_ip,
        maximum_failed_attempts=maximum_failed_attempts,
        threshold=THRESHOLD,
        filename=uploaded_file.filename,
        ip_labels=ip_labels,
        ip_values=ip_values,
        hour_labels=hour_labels,
        hour_success=hour_success,
        hour_failed=hour_failed,
    )


@app.route("/download")
def download_report():
    report_text = session.get("report_text")
    if not report_text:
        return redirect(url_for("home"))

    return send_file(
        BytesIO(report_text.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name="security_report.txt",
    )


if __name__ == "__main__":
    app.run(debug=True)
