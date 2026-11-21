# Read the log file
with open("sample_logs.txt", "r") as file:
    logs = [line.strip() for line in file if line.strip()]

# Initialize counters
success_count = 0
failed_count = 0
failed_attempts = {}

# Analyze each log record
for log in logs:

    parts = log.split()

    ip = parts[0]
    event = parts[1]

    if event == "LOGIN_SUCCESS":
        success_count += 1

    elif event == "LOGIN_FAILED":
        failed_count += 1

        if ip in failed_attempts:
            failed_attempts[ip] += 1
        else:
            failed_attempts[ip] = 1

# Generate security report
print("\n========== SECURITY REPORT ==========")

print("Total log records:", len(logs))
print("Successful logins:", success_count)
print("Failed logins:", failed_count)

print("\nSuspicious IP Addresses")
print("-------------------------------------")

threshold = 3
suspicious_found = False

for ip, count in failed_attempts.items():

    if count >= threshold:
        print(ip, "- Failed attempts:", count)
        suspicious_found = True

if not suspicious_found:
    print("No suspicious IP addresses found.")

print("=====================================")