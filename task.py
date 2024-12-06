import csv
from collections import defaultdict

# Function to analyze logs
def analyze_logs(log_file, failed_attempt_threshold=10):
    ip_requests = defaultdict(int)
    endpoint_access_count = defaultdict(int)
    failed_login_attempts = defaultdict(int)

    with open(log_file, 'r') as file:
        for line in file:
            parts = line.split()
            if len(parts) < 9:
                continue  # Skip malformed lines

            ip_address = parts[0]
            request_method = parts[5][1:]  # Remove the leading quote
            endpoint = parts[6]
            status_code = int(parts[8])

            # Count requests per IP address
            ip_requests[ip_address] += 1

            # Count endpoint accesses
            endpoint_access_count[endpoint] += 1

            # Detect failed login attempts (HTTP status code 401)
            if status_code == 401 or "Invalid credentials" in line:
                failed_login_attempts[ip_address] += 1

    return ip_requests, endpoint_access_count, failed_login_attempts

# Function to save results to CSV
def save_results(ip_requests, endpoint_access_count, failed_login_attempts, threshold):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        fieldnames = ['Category', 'IP Address/Endpoint', 'Count']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()

        # Write IP request counts
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow({'Category': 'Requests per IP', 'IP Address/Endpoint': ip, 'Count': count})

        # Write most accessed endpoint
        most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1])
        writer.writerow({'Category': 'Most Accessed Endpoint', 'IP Address/Endpoint': most_accessed_endpoint[0], 'Count': most_accessed_endpoint[1]})

        # Write suspicious activity
        for ip, count in sorted(failed_login_attempts.items(), key=lambda x: x[1], reverse=True):
            if count > threshold:
                writer.writerow({'Category': 'Suspicious Activity', 'IP Address/Endpoint': ip, 'Count': count})

# Main function to run the analysis
def main():
    log_file = 'sample.log'  # Path to the log file
    failed_attempt_threshold = 10  # Configurable threshold for failed login attempts
    
    ip_requests, endpoint_access_count, failed_login_attempts = analyze_logs(log_file, failed_attempt_threshold)

    print("IP Address           Request Count")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    most_accessed_endpoint = max(endpoint_access_count.items(), key=lambda x: x[1])
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in sorted(failed_login_attempts.items(), key=lambda x: x[1], reverse=True):
        if count > failed_attempt_threshold:
            print(f"{ip:<20} {count}")

    save_results(ip_requests, endpoint_access_count, failed_login_attempts, failed_attempt_threshold)

if __name__ == "__main__":
    main()