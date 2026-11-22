
import re
import csv
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path


LOG_FILE = "data/sample_auth.log"
REPORT_DIR = Path("reports")


def analyze_log(log_file, threshold):
    failed_attempts = Counter()
    successful_attempts = Counter()
    failed_usernames = Counter()

    with open(log_file, "r") as file:
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
                ip_address = success_match.group(2)
                successful_attempts[ip_address] += 1

    return {
        "failed_attempts": failed_attempts,
        "successful_attempts": successful_attempts,
        "failed_usernames": failed_usernames,
        "threshold": threshold
    }


def generate_txt_report(results, report_file):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    failed = results["failed_attempts"]
    successful = results["successful_attempts"]
    usernames = results["failed_usernames"]
    threshold = results["threshold"]

    with open(report_file, "w") as report:
        report.write("===== LINUX AUTHENTICATION LOG ANALYSIS REPORT =====\n")
        report.write(f"Report generated: {datetime.now()}\n\n")

        report.write(f"Total failed attempts: {sum(failed.values())}\n")
        report.write(f"Total successful attempts: {sum(successful.values())}\n\n")

        report.write("FAILED LOGIN USERNAMES:\n")
        for username, count in usernames.items():
            report.write(f"{username}: {count}\n")

        report.write("\nFAILED LOGIN IP ADDRESSES:\n")
        for ip, count in failed.items():
            report.write(f"{ip}: {count}\n")

        report.write("\nSUSPICIOUS IP ADDRESSES:\n")
        for ip, count in failed.items():
            if count >= threshold:
                report.write(f"WARNING: {ip} has {count} failed attempts\n")


def generate_csv_report(results, csv_file):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    failed = results["failed_attempts"]
    successful = results["successful_attempts"]
    usernames = results["failed_usernames"]
    threshold = results["threshold"]

    with open(csv_file, "w", newline="") as file:
        writer = csv.writer(file)

        writer.writerow(["Category", "Username/IP Address", "Count", "Status"])

        for username, count in usernames.items():
            writer.writerow(["Failed Login Username", username, count, "Recorded"])

        for ip, count in failed.items():
            status = "Suspicious" if count >= threshold else "Normal"
            writer.writerow(["Failed Login IP", ip, count, status])

        for ip, count in successful.items():
            writer.writerow(["Successful Login IP", ip, count, "Recorded"])


def main():
    try:
        threshold = int(sys.argv[1]) if len(sys.argv) > 1 else 3

        if threshold < 1:
            raise ValueError

    except ValueError:
        print("Error: Threshold must be a positive integer.")
        return 1

    try:
        results = analyze_log(LOG_FILE, threshold)

    except FileNotFoundError:
        print(f"Error: Log file not found: {LOG_FILE}")

        return 1

    failed = results["failed_attempts"]
    successful = results["successful_attempts"]
    usernames = results["failed_usernames"]

    print("===== LINUX AUTHENTICATION LOG ANALYSER =====")
    print("Total failed attempts:", sum(failed.values()))
    print("Total successful attempts:", sum(successful.values()))

    print("\n===== TARGETED USERNAMES =====")
    for username, count in usernames.items():
        print(f"Username: {username} | Failed attempts: {count}")

    print("\n===== ALL FAILED LOGIN IP ADDRESSES =====")
    for ip, count in failed.items():
        print(f"IP: {ip} | Failed attempts: {count}")

    print("\n===== SUSPICIOUS IP ADDRESSES =====")
    for ip, count in failed.items():
        if count >= threshold:
            print(f"WARNING: {ip} has {count} failed login attempts")

    print("\n===== ANALYSIS COMPLETED =====")

    txt_file = REPORT_DIR / "analysis_report.txt"
    csv_file = REPORT_DIR / "analysis_report.csv"

    generate_txt_report(results, txt_file)
    generate_csv_report(results, csv_file)

    print(f"\nReport saved successfully: {txt_file}")
    print(f"CSV report saved successfully: {csv_file}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
