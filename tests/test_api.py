#!/usr/bin/env python3
"""
Script to test the IP Threat Check API with mock data
"""
import json
import requests
import time
from datetime import datetime


def send_ioc_check_request(api_url: str, json_file: str):
    """
    Send IOC check request to the API
    
    Args:
        api_url: API endpoint URL
        json_file: Path to JSON file with IOC data
    """
    print(f"[{datetime.now()}] Loading data from {json_file}...")
    
    # Read the mock data
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    print(f"[{datetime.now()}] Loaded {data['total_ips']} IPs")
    print(f"[{datetime.now()}] Sending POST request to {api_url}...")
    
    # Send the request
    start_time = time.time()
    
    try:
        response = requests.post(
            api_url,
            json=data,
            headers={'Content-Type': 'application/json'},
            timeout=180  
        )
        
        elapsed_time = time.time() - start_time
        
        print(f"\n{'='*60}")
        print(f"RESPONSE STATUS: {response.status_code}")
        print(f"ELAPSED TIME: {elapsed_time:.2f} seconds")
        print(f"{'='*60}\n")
        
        if response.status_code == 200:
            result = response.json()
            
            print("SUCCESS!")
            print(f"\nResponse Summary:")
            print(f"  - Processed At: {result.get('processed_at')}")
            print(f"  - Total Requested: {result.get('total_requested')}")
            print(f"  - Cache Hits: {result.get('cache_hits')}")
            print(f"  - Cache Misses: {result.get('cache_misses')}")
            print(f"\nCache Hit Rate: {(result.get('cache_hits', 0) / result.get('total_requested', 1) * 100):.2f}%")
            
            # Show sample of cached IPs 
            if result.get('cached_ips'):
                print(f"\nSample Cached IPs (showing first 5):")
                for i, ip_info in enumerate(result['cached_ips'][:5], 1):
                    print(f"\n  {i}. IP: {ip_info['ip_address']}")
                    print(f"     Log ID: {ip_info['log_id']}")
                    print(f"     Threat Score: {ip_info['threat_score']}")
                    print(f"     Threat Level: {ip_info['threat_level']}")
                    print(f"     Categories: {ip_info['threat_categories']}")
                    print(f"     Source: {ip_info['source_name']}")
                    print(f"     Country: {ip_info.get('country_code', 'N/A')}")
            
            
            if result.get('not_found_ips'):
                print(f"\nSample Not Found IPs (showing first 5):")
                for i, ip_info in enumerate(result['not_found_ips'][:5], 1):
                    print(f"  {i}. IP: {ip_info['ip_address']} (Log ID: {ip_info['log_id']})")
            
            
            output_file = f"api_response_{int(time.time())}.json"
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\null response saved to: {output_file}")
            
        else:
            print(f"ERROR!")
            print(f"Status Code: {response.status_code}")
            print(f"Response: {response.text}")
            
    except requests.exceptions.Timeout:
        print(f"REQUEST TIMEOUT after {time.time() - start_time:.2f} seconds")
    except requests.exceptions.ConnectionError:
        print(f"CONNECTION ERROR - Is the API running?")
    except Exception as e:
        print(f"ERROR: {str(e)}")


if __name__ == "__main__":
    # Configuration
    API_URL = "http://localhost:8000/api/v1/check-iocs"
    JSON_FILE = "test_data/mock_ips.json"
    
    print("="*60)
    print("IOC THREAT CHECK API - TEST SCRIPT")
    print("="*60)
    
    send_ioc_check_request(API_URL, JSON_FILE)

