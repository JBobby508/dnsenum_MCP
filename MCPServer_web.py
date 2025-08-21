#!/usr/bin/env python3

# This script connects the MCP AI agent to Kali Linux terminal and API Server.
# It allows the AI agent to leverage DNSEnum tool for DNS enumeration and reconnaissance
# by communicating with a corresponding server application (Kaliserver.py).

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import json

from fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://192.168.1.170:5000"
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for DNS enumeration

class KaliToolsClient:
    """
    Client for communicating with the Kali Linux Tools API Server.
    This class handles making HTTP GET and POST requests to the server's API endpoints.
    """
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client.
        
        Args:
            server_url: URL of the Kali Tools API Server.
            timeout: Request timeout in seconds for API calls.
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {self.server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request to a specified endpoint on the Kali API server.
        
        Args:
            endpoint: API endpoint path.
            params: Optional dictionary of query parameters.
            
        Returns:
            A dictionary containing the JSON response from the server, or an error dictionary if the request fails.
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            logger.error(f"JSON decode failed for GET {url}: {str(e)}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for GET {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data to a specified endpoint on the Kali API server.
        
        Args:
            endpoint: API endpoint path.
            json_data: A dictionary containing the JSON payload to send in the request body.
            
        Returns:
            A dictionary containing the JSON response from the server, or an error dictionary if the request fails.
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            logger.error(f"JSON decode failed for POST {url}: {str(e)}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for POST {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server by querying its "/health" endpoint.
        
        Returns:
            A dictionary containing health status information from the server.
        """
        logger.info("Checking Kali API server health.")
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient, log_level: str = "INFO") -> FastMCP:
    """
    Set up and configure the FastMCP server instance with DNSEnum tool.

    Args:
        kali_client: An initialized KaliToolsClient instance for communication with the Kali API server.
        log_level: The logging level for the FastMCP server.

    Returns:
        A configured FastMCP instance with DNSEnum tool registered.
    """
    mcp = FastMCP("dnsenum-mcp", log_level=log_level)
    logger.info(f"Setting up MCP server with log level {log_level} and registering DNSEnum tool.")

    @mcp.tool()
    def dnsenum_scan(domain: str, wordlist: str = "", dns_server: str = "", 
                     enable_reverse: bool = False, enable_whois: bool = False,
                     enable_google_scraping: bool = False, threads: int = 5,
                     timeout: int = 300, additional_args: str = "") -> Dict[str, Any]:
        """
        MCP Tool: Execute DNSEnum for comprehensive DNS enumeration of a domain.
        
        DNSEnum performs DNS record enumeration, subdomain brute forcing, zone transfers,
        reverse DNS lookups, and other DNS reconnaissance techniques.

        Args:
            domain: The target domain to enumerate (e.g., "example.com").
            wordlist: Path to custom wordlist file for subdomain brute forcing. 
                     Common wordlists: "/usr/share/dnsenum/dns.txt" (default), 
                     "/usr/share/wordlists/dirb/small.txt", custom paths.
            dns_server: Specific DNS server to use for queries (e.g., "8.8.8.8", "1.1.1.1"). 
                       If empty, uses system default DNS servers.
            enable_reverse: Enable reverse DNS lookup for discovered IP addresses to find additional hostnames.
            enable_whois: Enable WHOIS lookup for the domain and discovered hosts for registration info.
            enable_google_scraping: Enable Google search scraping for additional subdomains (may be rate limited).
            threads: Number of threads to use for brute forcing (1-50, default: 5). More threads = faster but more aggressive.
            timeout: Maximum time in seconds to run the scan (default: 300 seconds).
            additional_args: Additional dnsenum command line arguments (e.g., "--enum", "-v", "-r").

        Returns:
            Dictionary containing:
            - success: Boolean indicating if the scan completed successfully
            - stdout: DNSEnum output including discovered subdomains, DNS records, IP addresses
            - stderr: Any error messages or warnings
            - return_code: Exit code of the dnsenum command
            - discovered_subdomains: Parsed list of discovered subdomains (if parsing successful)
            - dns_records: Dictionary of DNS record types found (A, AAAA, MX, NS, etc.)
            - scan_summary: Summary statistics of the enumeration
        """
        logger.info(f"DNSEnum tool called: domain={domain}, wordlist='{wordlist}', dns_server='{dns_server}', threads={threads}")
        
        data = {
            "domain": domain,
            "wordlist": wordlist,
            "dns_server": dns_server,
            "enable_reverse": enable_reverse,
            "enable_whois": enable_whois,
            "enable_google_scraping": enable_google_scraping,
            "threads": threads,
            "timeout": timeout,
            "additional_args": additional_args
        }
        
        return kali_client.safe_post("api/tools/dnsenum", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        MCP Tool: Check the health status of the backend Kali API server.
        
        Returns:
            Server health information including available tools and system status.
        """
        logger.info("Server health tool called.")
        return kali_client.check_health()

    logger.info("MCP tools registered: dnsenum_scan, server_health")
    return mcp

def parse_args():
    """
    Parse command line arguments for the MCP client script.
    """
    parser = argparse.ArgumentParser(description="Run the DNSEnum MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging level")
    return parser.parse_args()

def main():
    """
    Main entry point for the DNSEnum MCP client application.
    """
    args = parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.info("Debug logging enabled by command line argument.")
    
    logger.info(f"Initializing KaliToolsClient with server: {args.server}, timeout: {args.timeout}s")
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Perform initial health check
    logger.info("Performing initial health check of Kali API server...")
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP client will start, but tool execution will likely fail until server is available.")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health.get('status', 'N/A')}")
        
        # Check if DNSEnum is available
        tools_status = health.get("tools_status", {})
        if "dnsenum" in tools_status:
            if tools_status["dnsenum"]:
                logger.info("DNSEnum tool is available on the server")
            else:
                logger.warning("DNSEnum tool is not available on the server")
        else:
            logger.info("DNSEnum availability status not reported by server")
    
    # Set up the MCP server
    mcp_log_level = "DEBUG" if args.debug else "INFO"
    mcp = setup_mcp_server(kali_client, log_level=mcp_log_level)
    
    logger.info(f"Starting DNSEnum MCP client server with log level: {mcp_log_level}...")
    mcp.run()

if __name__ == "__main__":
    main()
