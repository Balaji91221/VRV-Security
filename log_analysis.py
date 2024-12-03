import re
import csv
import logging
from collections import Counter, defaultdict
from typing import List, Dict, Tuple, Optional, Any


class LogAnalyzer:
    """
    A professional log analysis tool for parsing and analyzing web server logs.
    
    This class provides methods to extract insights from log files, including:
    - Counting requests per IP address
    - Identifying most accessed endpoints
    - Detecting suspicious login activities
    """

    def __init__(self, log_file_path: str, failed_login_threshold: int = 3):
        """
        Initialize the LogAnalyzer with configuration parameters.
        
        Args:
            log_file_path (str): Path to the log file to be analyzed
            failed_login_threshold (int): Number of failed logins to flag as suspicious
        """
        self.log_file_path = log_file_path
        self.failed_login_threshold = failed_login_threshold
        self.logger = self._setup_logger()

    def _setup_logger(self) -> logging.Logger:
        """
        Configure a logger for tracking analysis process and potential issues.
        
        Returns:
            logging.Logger: Configured logger instance
        """
        logger = logging.getLogger('LogAnalyzer')
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger

    def parse_log(self) -> List[str]:
        """
        Read and parse the log file.
        
        Returns:
            List[str]: List of log entries
        
        Raises:
            FileNotFoundError: If the log file cannot be found
            IOError: If there are issues reading the file
        """
        try:
            with open(self.log_file_path, 'r') as file:
                logs = file.readlines()
            self.logger.info(f"Successfully parsed log file: {self.log_file_path}")
            return logs
        except FileNotFoundError:
            self.logger.error(f"Log file not found: {self.log_file_path}")
            raise
        except IOError as e:
            self.logger.error(f"Error reading log file: {e}")
            raise

    def count_requests_by_ip(self, logs: List[str]) -> Dict[str, int]:
        """
        Count the number of requests for each unique IP address.
        
        Args:
            logs (List[str]): List of log entries
        
        Returns:
            Dict[str, int]: Dictionary of IP addresses and their request counts
        """
        ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"
        try:
            ip_counter = Counter(
                re.match(ip_pattern, log).group(1) 
                for log in logs 
                if re.match(ip_pattern, log)
            )
            return dict(ip_counter)
        except Exception as e:
            self.logger.warning(f"Error counting requests by IP: {e}")
            return {}

    def most_frequent_endpoint(self, logs: List[str]) -> Tuple[str, int]:
        """
        Identify the most frequently accessed endpoint.
        
        Args:
            logs (List[str]): List of log entries
        
        Returns:
            Tuple[str, int]: Most accessed endpoint and its access count
        """
        endpoint_pattern = r"\"[A-Z]+ (/\S*)"
        try:
            endpoint_counter = Counter(
                re.search(endpoint_pattern, log).group(1) 
                for log in logs 
                if re.search(endpoint_pattern, log)
            )
            most_common = endpoint_counter.most_common(1)
            return most_common[0] if most_common else ("None", 0)
        except Exception as e:
            self.logger.warning(f"Error finding most frequent endpoint: {e}")
            return ("None", 0)

    def detect_suspicious_activity(self, logs: List[str]) -> Dict[str, int]:
        """
        Detect IP addresses with multiple failed login attempts.
        
        Args:
            logs (List[str]): List of log entries
        
        Returns:
            Dict[str, int]: Dictionary of suspicious IP addresses and their failed login counts
        """
        failed_login_pattern = r" (\d{3}) .+\"Invalid credentials\""
        ip_pattern = r"^(\d+\.\d+\.\d+\.\d+)"
        
        failed_attempts = defaultdict(int)
        for log in logs:
            if re.search(failed_login_pattern, log) and re.search(ip_pattern, log):
                ip = re.match(ip_pattern, log).group(1)
                failed_attempts[ip] += 1
        
        suspicious_ips = {
            ip: count for ip, count in failed_attempts.items() 
            if count > self.failed_login_threshold
        }
        
        if suspicious_ips:
            self.logger.warning(f"Suspicious IPs detected: {suspicious_ips}")
        
        return suspicious_ips

    def save_analysis_results(
        self, 
        results: Dict[str, Any], 
        output_file: Optional[str] = None
    ) -> None:
        """
        Save log analysis results to a CSV file.
        
        Args:
            results (Dict): Dictionary containing analysis results
            output_file (str, optional): Path to save the output CSV. 
                                        Defaults to 'log_analysis_results.csv'
        """
        output_file = output_file or 'log_analysis_results.csv'
        
        try:
            with open(output_file, mode="w", newline="") as file:
                writer = csv.writer(file)
                
                # Requests per IP
                writer.writerow(["Requests per IP"])
                writer.writerow(["IP Address", "Request Count"])
                writer.writerows(results['requests_by_ip'].items())
                
                # Most accessed endpoint
                writer.writerow([])
                writer.writerow(["Most Accessed Endpoint"])
                writer.writerow(["Endpoint", "Access Count"])
                writer.writerow(results['most_accessed_endpoint'])
                
                # Suspicious activity
                writer.writerow([])
                writer.writerow(["Suspicious Activity"])
                writer.writerow(["IP Address", "Failed Login Count"])
                writer.writerows(results['suspicious_activity'].items())
            
            self.logger.info(f"Analysis results saved to {output_file}")
        except IOError as e:
            self.logger.error(f"Error saving analysis results: {e}")

    def analyze(self) -> Dict[str, Any]:
        """
        Perform complete log file analysis.
        
        Returns:
            Dict[str, Any]: Comprehensive analysis results
        """
        try:
            logs = self.parse_log()
            
            requests_by_ip = self.count_requests_by_ip(logs)
            most_accessed_endpoint = self.most_frequent_endpoint(logs)
            suspicious_activity = self.detect_suspicious_activity(logs)
            
            results = {
                "requests_by_ip": requests_by_ip,
                "most_accessed_endpoint": most_accessed_endpoint,
                "suspicious_activity": suspicious_activity
            }
            
            return results
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}")
            raise

def main():
    """
    Main entry point for log analysis script.
    """
    try:
        # Configure log file path and analysis parameters
        log_file_path = 'sample.log'
        failed_login_threshold = 3
        
        # Initialize and run log analyzer
        log_analyzer = LogAnalyzer(log_file_path, failed_login_threshold)
        analysis_results = log_analyzer.analyze()
        
        # Print results to console
        print("\n--- Log Analysis Results ---")
        print("\nRequests per IP:")
        for ip, count in analysis_results['requests_by_ip'].items():
            print(f"{ip:<20}{count}")
        
        print("\nMost Frequently Accessed Endpoint:")
        endpoint, count = analysis_results['most_accessed_endpoint']
        print(f"{endpoint} (Accessed {count} times)")
        
        print("\nSuspicious Activity Detected:")
        for ip, failed_count in analysis_results['suspicious_activity'].items():
            print(f"{ip:<20}{failed_count}")
        
        # Save results to CSV
        log_analyzer.save_analysis_results(analysis_results)
        
    except Exception as e:
        logging.error(f"Script execution failed: {e}")

if __name__ == "__main__":
    main()