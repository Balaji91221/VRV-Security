# VRV-Security
VRV Security’s to Detect Suspicious Activity of different web addresses.

# Log File Analyzer

## Description

The **Log File Analyzer** is a Python script designed to process and analyze log files, extracting key insights such as request counts, popular endpoints, and detecting suspicious activities. This tool is tailored for cybersecurity-related tasks, leveraging file handling, string manipulation, and data analysis.

---

## Features

1. **Count Requests per IP Address**  
   - Parses the log file to extract IP addresses.  
   - Counts the number of requests made by each IP.  
   - Displays results sorted in descending order of request count.  

2. **Identify the Most Frequently Accessed Endpoint**  
   - Extracts endpoints (URLs or resource paths) from the log file.  
   - Identifies the most frequently accessed endpoint.  

3. **Detect Suspicious Activity**  
   - Searches for failed login attempts (e.g., HTTP 401 errors or "Invalid credentials").  
   - Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10).  

4. **Output Results**  
   - Displays results in the terminal for quick viewing.  
   - Saves results to a CSV file named `log_analysis_results.csv`.  

---

## Example Outputs

### Terminal Output
Requests per IP: 192.168.1.1 6 203.0.113.5 8 10.0.0.2 5 198.51.100.23 7

Most Frequently Accessed Endpoint: /home (Accessed 5 times)

Suspicious Activity Detected: 203.0.113.5 8 192.168.1.100 12

yaml
Copy code

### CSV Output
The results are saved in the following structure:
- **Requests per IP**: IP Address, Request Count  
- **Most Accessed Endpoint**: Endpoint, Access Count  
- **Suspicious Activity**: IP Address, Failed Login Count  

---




