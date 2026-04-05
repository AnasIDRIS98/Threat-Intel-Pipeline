import requests
import time
import logging


logger = logging.getLogger("ThreatIntel.Enricher")

class VTEnricher:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {"x-apikey": self.api_key}

    def enrich_indicator(self, indicator, ioc_type):
        """فحص المؤشر بناءً على نوعه (IP أو Hash)"""
        
        
        endpoint = ""
        if ioc_type == "IPv4":
            endpoint = f"/ip_addresses/{indicator}"
        elif ioc_type in ["FileHash-SHA256", "FileHash-SHA1", "FileHash-MD5", "Hash"]:
            endpoint = f"/files/{indicator}"
        else:
            logger.warning(f"Unsupported IOC type for enrichment: {ioc_type}")
            return "unknown"

        url = self.base_url + endpoint
        
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            
            
            if response.status_code == 429:
                logger.warning("VirusTotal Rate Limit reached. Sleeping for 60s...")
                time.sleep(60)
                return self.enrich_indicator(indicator, ioc_type) 

            
            if response.status_code == 404:
                return "Not Found"

            response.raise_for_status()
            data = response.json()
            
            
            stats = data['data']['attributes']['last_analysis_stats']
            malicious_count = stats.get('malicious', 0)
            
            
            if malicious_count > 10: return "Critical"
            if malicious_count > 3: return "High"
            if malicious_count > 0: return "Medium"
            return "Low"

        except Exception as e:
            logger.error(f"Failed to enrich {ioc_type} {indicator}: {e}")
            return "error"