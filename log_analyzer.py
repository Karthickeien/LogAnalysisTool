import re
import csv
from collections import Counter
from typing import Dict, List, Tuple

class LogAnalyzer:
    def __init__(self, log_file: str, login_attempt_threshold: int = 10):
        self.log_file = log_file
        self.login_attempt_threshold = login_attempt_threshold
        self.ip_requests: Counter = Counter()
        self.endpoint_requests: Counter = Counter()
        self.failed_logins: Counter = Counter()
        
    def parse_log_line(self, line: str) -> Tuple[str, str, int]:
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        endpoint_match = re.search(r'"[A-Z]+ ([^ ]+)', line)
        status_code = re.search(r'" (\d{3})', line)
        
        ip = ip_match.group(1) if ip_match else ''
        endpoint = endpoint_match.group(1) if endpoint_match else ''
        code = int(status_code.group(1)) if status_code else 0
        
        return ip, endpoint, code
        
    def analyze_logs(self):
        with open(self.log_file, 'r') as f:
            for line in f:
                ip, endpoint, status_code = self.parse_log_line(line)
                if ip:
                    self.ip_requests[ip] += 1
                    if endpoint:
                        self.endpoint_requests[endpoint] += 1
                    if status_code == 401:
                        self.failed_logins[ip] += 1
    
    def get_suspicious_ips(self) -> Dict[str, int]:
        return {ip: count for ip, count in self.failed_logins.items() 
                if count >= self.login_attempt_threshold}
    
    def get_most_accessed_endpoint(self) -> Tuple[str, int]:
        endpoint = self.endpoint_requests.most_common(1)[0]
        return endpoint[0], endpoint[1]
    
    def display_results(self):
        print("\nRequests per IP Address:")
        print("IP Address           Request Count")
        for ip, count in self.ip_requests.most_common():
            print(f"{ip:<18} {count:>8}")
            
        endpoint, count = self.get_most_accessed_endpoint()
        print(f"\nMost Frequently Accessed Endpoint:")
        print(f"{endpoint} (Accessed {count} times)")
            
        suspicious = self.get_suspicious_ips()
        if suspicious:
            print("\nSuspicious Activity Detected:")
            print("IP Address           Failed Login Attempts")
            for ip, count in suspicious.items():
                print(f"{ip:<18} {count:>8}")
    
    def save_to_csv(self, output_file: str = 'log_analysis_results.csv'):
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Requests per IP
            writer.writerow(['Requests per IP'])
            writer.writerow(['IP Address', 'Request Count'])
            for ip, count in self.ip_requests.most_common():
                writer.writerow([ip, count])
                
            # Most accessed endpoint
            writer.writerow([])
            writer.writerow(['Most Accessed Endpoint'])
            writer.writerow(['Endpoint', 'Access Count'])
            endpoint, count = self.get_most_accessed_endpoint()
            writer.writerow([endpoint, count])
            
            # Suspicious activity
            writer.writerow([])
            writer.writerow(['Suspicious Activity'])
            writer.writerow(['IP Address', 'Failed Login Count'])
            for ip, count in self.get_suspicious_ips().items():
                writer.writerow([ip, count])

def main():
    analyzer = LogAnalyzer('sample.log')
    analyzer.analyze_logs()
    analyzer.display_results()
    analyzer.save_to_csv()

if __name__ == '__main__':
    main()