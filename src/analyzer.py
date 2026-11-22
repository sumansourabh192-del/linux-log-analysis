import re
import csv
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_FILE = "data/sample_auth.log"
failed_attempts = Counter()
successful_attempts = Counter()
failed_usernames = Counter()
try:
    FAILED_THRESHOLD = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    if FAILED_THRESHOLD < 1:
        raise ValueError
except ValueError:
    print("Error: Threshold must be a positive integer.")
    raise SystemExit(1)
with open(LOG_FILE, "r") as file:
    for line in file:
        failed_match = re.search(
            r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        success_match = re.search(
            r"Accepted password for (\S+) from (\d+\.\d+\.\d+\.\d+)",
            line
        )

        if failed_match:
            username = failed_match.group(1)
            ip_address = failed_match.group(2)
            failed_attempts[ip_address] += 1
            failed_usernames[username] += 1

        elif success_match:
            username = success_match.group(1)
            ip_address = success_match.group(2)
            successful_attempts[ip_address] += 1

print("===== LINUX AUTHENTICATION LOG ANALYSER =====")
print("Total failed attempts:", sum(failed_attempts.values()))
print("Total successful attempts:", sum(successful_attempts.values()))

print("\n===== TARGETED USERNAMES =====")
for username, count in failed_usernames.items():
    print(f"Username: {username} | Failed attempts: {count}")

print("\n===== ALL FAILED LOGIN IP ADDRESSES =====")
for ip, count in failed_attempts.items():
    print(f"IP: {ip} | Failed attempts: {count}")

print("\n===== SUSPICIOUS IP ADDRESSES =====")
for ip, count in failed_attempts.items():
    if count >= FAILED_THRESHOLD:
        print(f"WARNING: {ip} has {count} failed login attempts")

print("\n===== ANALYSIS COMPLETED =====")


Path("reports").mkdir(parents=True, exist_ok=True)
report_file = "reports/analysis_report.txt"

with open(report_file, "w") as report:
    report.write("===== LINUX AUTHENTICATION LOG ANALYSIS REPORT =====\n")
    report.write(f"Report generated: {datetime.now()}\n\n")

    report.write(f"Total failed attempts: {sum(failed_attempts.values())}\n")
    report.write(f"Total successful attempts: {sum(successful_attempts.values())}\n\n")

    report.write("FAILED LOGIN USERNAMES:\n")
    for username, count in failed_usernames.items():
        report.write(f"{username}: {count}\n")

    report.write("\nFAILED LOGIN IP ADDRESSES:\n")
    for ip, count in failed_attempts.items():
        report.write(f"{ip}: {count}\n")

    report.write("\nSUSPICIOUS IP ADDRESSES:\n")
    for ip, count in failed_attempts.items():
        if count >= FAILED_THRESHOLD:
            report.write(f"WARNING: {ip} has {count} failed attempts\n")

print(f"\nReport saved successfully: {report_file}")
csv_file = "reports/analysis_report.csv"

with open(csv_file, "w", newline="") as file:
    writer = csv.writer(file)

    writer.writerow(["Category", "Username/IP Address", "Count", "Status"])

    for username, count in failed_usernames.items():
        writer.writerow(["Failed Login Username", username, count, "Recorded"])

    for ip, count in failed_attempts.items():
        status = "Suspicious" if count >= FAILED_THRESHOLD else "Normal"
        writer.writerow(["Failed Login IP", ip, count, status])

    for ip, count in successful_attempts.items():
        writer.writerow(["Successful Login IP", ip, count, "Recorded"])

print(f"CSV report saved successfully: {csv_file}")
