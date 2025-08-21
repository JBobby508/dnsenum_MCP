#!/usr/bin/env python3

# This script implements a Flask-based API server that runs on a Kali Linux machine.
# It exposes endpoints to execute DNSEnum for DNS enumeration and reconnaissance.
# This server acts as the backend for the DNSEnum MCP Client.

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
import re
from typing import Dict, Any, Optional, List
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
) 
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 300  # 5 minutes default timeout for DNS enumeration

app = Flask(__name__)

class CommandExecutor:
    """
    Handles the execution of shell commands with improved timeout management and non-blocking output reading.
    """
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, workdir: str = None, stdin_input: str = None):
        """
        Initialize the CommandExecutor.

        Args:
            command: The shell command string to be executed.
            timeout: The maximum time (in seconds) to wait for the command to complete.
            workdir: Optional working directory to execute the command in.
            stdin_input: Optional text to pipe into the command's STDIN.
        """
        self.command = command
        self.timeout = timeout
        self.workdir = workdir
        self.stdin_input = stdin_input
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread target function to continuously read lines from the process's stdout."""
        try:
            for line in iter(self.process.stdout.readline, ''):
                self.stdout_data += line
        except Exception as e:
            logger.debug(f"Exception in _read_stdout thread: {e}")
        finally:
            if self.process and self.process.stdout:
                self.process.stdout.close()
    
    def _read_stderr(self):
        """Thread target function to continuously read lines from the process's stderr."""
        try:
            for line in iter(self.process.stderr.readline, ''):
                self.stderr_data += line
        except Exception as e:
            logger.debug(f"Exception in _read_stderr thread: {e}")
        finally:
            if self.process and self.process.stderr:
                self.process.stderr.close()
    
    def execute(self) -> Dict[str, Any]:
        """
        Execute the command and collect its output and status.

        Returns:
            A dictionary containing execution results.
        """
        logger.info(f"Executing command: '{self.command}' with timeout: {self.timeout}s")
        
        try:
            popen_kwargs = {
                "shell": True,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "bufsize": 1
            }
            
            if self.workdir:
                if os.path.isdir(self.workdir):
                    popen_kwargs["cwd"] = self.workdir
                    logger.debug(f"Executing command in working directory: {self.workdir}")
                else:
                    logger.warning(f"Working directory does not exist: {self.workdir}")
            
            if self.stdin_input:
                popen_kwargs["stdin"] = subprocess.PIPE
            
            self.process = subprocess.Popen(self.command, **popen_kwargs)
            
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            if self.stdin_input and self.process.stdin:
                try:
                    self.process.stdin.write(self.stdin_input)
                    self.process.stdin.close()
                    logger.debug(f"Sent {len(self.stdin_input)} characters to stdin")
                except Exception as e:
                    logger.warning(f"Failed to write to stdin: {e}")
            
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command '{self.command}' timed out after {self.timeout} seconds. Terminating process.")
                
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Process for '{self.command}' did not terminate gracefully. Killing.")
                    self.process.kill()
                
                self.return_code = -1
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            
            success = (self.return_code == 0) or (self.timed_out and (self.stdout_data or self.stderr_data))
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command '{self.command}': {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }

def execute_command(command: str, workdir: str = None, stdin_input: str = None, timeout: int = COMMAND_TIMEOUT) -> Dict[str, Any]:
    """
    Wrapper function to execute a shell command using the CommandExecutor class.
    """
    executor = CommandExecutor(command, timeout=timeout, workdir=workdir, stdin_input=stdin_input)
    return executor.execute()

class DNSEnumParser:
    """
    Parser for DNSEnum output to extract structured information.
    """
    
    @staticmethod
    def parse_dnsenum_output(output: str) -> Dict[str, Any]:
        """
        Parse DNSEnum output to extract structured information.
        
        Args:
            output: Raw DNSEnum stdout output
            
        Returns:
            Dictionary containing parsed DNS information
        """
        try:
            parsed_data = {
                "discovered_subdomains": [],
                "dns_records": {
                    "A": [],
                    "AAAA": [],
                    "MX": [],
                    "NS": [],
                    "SOA": [],
                    "TXT": [],
                    "CNAME": []
                },
                "scan_summary": {
                    "total_subdomains": 0,
                    "unique_ips": set(),
                    "zone_transfer_attempted": False,
                    "zone_transfer_successful": False
                }
            }
            
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Parse subdomains and A records
                if 'Host\'s addresses:' in line or re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+A\s+', line):
                    # Extract A records
                    a_match = re.search(r'(\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if a_match:
                        hostname, ip = a_match.groups()
                        parsed_data["dns_records"]["A"].append({"hostname": hostname, "ip": ip})
                        parsed_data["discovered_subdomains"].append(hostname)
                        parsed_data["scan_summary"]["unique_ips"].add(ip)
                
                # Parse AAAA records
                elif re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+AAAA\s+', line):
                    aaaa_match = re.search(r'(\S+)\s+\d+\s+IN\s+AAAA\s+([0-9a-fA-F:]+)', line)
                    if aaaa_match:
                        hostname, ipv6 = aaaa_match.groups()
                        parsed_data["dns_records"]["AAAA"].append({"hostname": hostname, "ipv6": ipv6})
                
                # Parse MX records
                elif re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+MX\s+', line):
                    mx_match = re.search(r'(\S+)\s+\d+\s+IN\s+MX\s+(\d+)\s+(\S+)', line)
                    if mx_match:
                        domain, priority, mx_server = mx_match.groups()
                        parsed_data["dns_records"]["MX"].append({"domain": domain, "priority": int(priority), "mx_server": mx_server})
                
                # Parse NS records
                elif re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+NS\s+', line):
                    ns_match = re.search(r'(\S+)\s+\d+\s+IN\s+NS\s+(\S+)', line)
                    if ns_match:
                        domain, ns_server = ns_match.groups()
                        parsed_data["dns_records"]["NS"].append({"domain": domain, "ns_server": ns_server})
                
                # Parse TXT records
                elif re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+TXT\s+', line):
                    txt_match = re.search(r'(\S+)\s+\d+\s+IN\s+TXT\s+"([^"]+)"', line)
                    if txt_match:
                        domain, txt_data = txt_match.groups()
                        parsed_data["dns_records"]["TXT"].append({"domain": domain, "txt_data": txt_data})
                
                # Parse CNAME records
                elif re.match(r'^[a-zA-Z0-9.-]+\.\s+\d+\s+IN\s+CNAME\s+', line):
                    cname_match = re.search(r'(\S+)\s+\d+\s+IN\s+CNAME\s+(\S+)', line)
                    if cname_match:
                        alias, canonical = cname_match.groups()
                        parsed_data["dns_records"]["CNAME"].append({"alias": alias, "canonical": canonical})
                
                # Detect zone transfer attempts
                elif 'Trying Zone Transfer' in line or 'AXFR' in line:
                    parsed_data["scan_summary"]["zone_transfer_attempted"] = True
                
                # Detect successful zone transfers
                elif 'Zone Transfer was successful' in line or 'Transfer completed' in line:
                    parsed_data["scan_summary"]["zone_transfer_successful"] = True
            
            # Remove duplicates from subdomains list
            parsed_data["discovered_subdomains"] = list(set(parsed_data["discovered_subdomains"]))
            parsed_data["scan_summary"]["total_subdomains"] = len(parsed_data["discovered_subdomains"])
            parsed_data["scan_summary"]["unique_ips"] = list(parsed_data["scan_summary"]["unique_ips"])
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"Error parsing DNSEnum output: {str(e)}")
            return {
                "discovered_subdomains": [],
                "dns_records": {"A": [], "AAAA": [], "MX": [], "NS": [], "SOA": [], "TXT": [], "CNAME": []},
                "scan_summary": {"total_subdomains": 0, "unique_ips": [], "zone_transfer_attempted": False, "zone_transfer_successful": False},
                "parse_error": str(e)
            }

@app.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """
    Flask API endpoint to execute DNSEnum for DNS enumeration.
    """
    try:
        params = request.get_json()
        if not params:
            logger.warning("DNSEnum endpoint called with no JSON payload.")
            return jsonify({"error": "JSON payload required for DNSEnum scan"}), 400

        domain = params.get("domain", "")
        wordlist = params.get("wordlist", "")
        dns_server = params.get("dns_server", "")
        enable_reverse = params.get("enable_reverse", False)
        enable_whois = params.get("enable_whois", False)
        enable_google_scraping = params.get("enable_google_scraping", False)
        threads = params.get("threads", 5)
        timeout = params.get("timeout", COMMAND_TIMEOUT)
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("DNSEnum API called without 'domain' parameter.")
            return jsonify({"error": "'domain' parameter is required for DNSEnum scan"}), 400
        
        # Validate threads parameter
        if not isinstance(threads, int) or threads < 1 or threads > 50:
            threads = 5
            logger.warning(f"Invalid threads parameter, using default: {threads}")
        
        # Build DNSEnum command
        command_parts = ["dnsenum"]
        
        # Add timeout flag if supported
        command_parts.extend(["--timeout", "10"])
        
        # Add threads for brute forcing
        command_parts.extend(["--threads", str(threads)])
        
        # Add custom wordlist if specified
        if wordlist:
            if os.path.isfile(wordlist):
                command_parts.extend(["-f", wordlist])
                logger.info(f"Using custom wordlist: {wordlist}")
            else:
                logger.warning(f"Specified wordlist not found: {wordlist}, using default")
        
        # Add custom DNS server if specified
        if dns_server:
            command_parts.extend(["--dnsserver", dns_server])
            logger.info(f"Using custom DNS server: {dns_server}")
        
        # Add reverse DNS lookup option
        if enable_reverse:
            command_parts.append("-r")
            logger.info("Enabled reverse DNS lookups")
        
        # Add WHOIS lookup option
        if enable_whois:
            command_parts.append("-w")
            logger.info("Enabled WHOIS lookups")
        
        # Add Google scraping option
        if enable_google_scraping:
            command_parts.append("-s")
            logger.info("Enabled Google scraping")
        
        # Add any additional arguments
        if additional_args:
            command_parts.extend(additional_args.split())
        
        # Add the target domain last
        command_parts.append(domain)
        
        command = " ".join(command_parts)
        
        logger.info(f"Executing DNSEnum command: {command}")
        result = execute_command(command, timeout=timeout)
        
        # Parse the DNSEnum output for structured data
        if result["success"] and result["stdout"]:
            parsed_data = DNSEnumParser.parse_dnsenum_output(result["stdout"])
            result.update(parsed_data)
            
            # Add scan statistics to the result
            result["scan_info"] = {
                "domain": domain,
                "command": command,
                "execution_time": "completed" if not result.get("timed_out") else f"timed out after {timeout}s",
                "threads_used": threads,
                "custom_wordlist": bool(wordlist),
                "custom_dns_server": dns_server if dns_server else "system default"
            }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in /api/tools/dnsenum endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error processing DNSEnum request: {str(e)}"}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """
    Flask API endpoint to check the health of the Kali API server.
    """
    logger.info("Health check requested.")
    essential_tools = ["dnsenum"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}", timeout=10)
            tools_status[tool] = result["success"] and bool(result["stdout"])
        except Exception as e:
            logger.error(f"Error checking for tool '{tool}': {e}")
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    status_message = "healthy" if all_essential_tools_available else "degraded"
    if not all_essential_tools_available:
        logger.warning(f"Health check: Server is {status_message} due to missing essential tools.")

    return jsonify({
        "status": status_message,
        "message": f"DNSEnum API Server is running. Tool status: {'Available' if all_essential_tools_available else 'Missing tools'}",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "supported_operations": [
            "DNS enumeration",
            "Subdomain brute forcing", 
            "Zone transfer attempts",
            "Reverse DNS lookups",
            "WHOIS queries",
            "Google scraping"
        ]
    })

def parse_args():
    """
    Parse command line arguments for the Kali API server script.
    """
    parser = argparse.ArgumentParser(description="Run the DNSEnum Kali API Server")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode and verbose logging")
    parser.add_argument("--port", type=int, default=API_PORT, 
                      help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    effective_debug_mode = DEBUG_MODE or args.debug
    effective_api_port = args.port
    
    if effective_debug_mode:
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
        logger.info("Debug mode enabled.")
    else:
        logger.info("Running in production mode (debug disabled).")
    
    if args.port != API_PORT:
        logger.info(f"Using custom API port: {args.port}")
        effective_api_port = args.port

    logger.info(f"Starting DNSEnum API Server on host 0.0.0.0, port {effective_api_port}")
    app.run(host="0.0.0.0", port=effective_api_port, debug=effective_debug_mode)
