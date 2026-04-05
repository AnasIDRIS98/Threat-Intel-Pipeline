import requests
import logging 


logger = logging.getLogger("ThreatIntel.OTX")

class OTXCollector:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://otx.alienvault.com/api/v1"
        self.headers = {"X-OTX-API-KEY": self.api_key}

    def fetch_recent_indicators(self):
        logger.info("Connecting to AlienVault OTX API...")
        try:
            response = requests.get(f"{self.base_url}/pulses/activity", headers=self.headers, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            extracted_iocs = []
            for pulse in data.get('results', []):
                pulse_name = pulse.get('name')
                for ind in pulse.get('indicators', []):
                    extracted_iocs.append({
                        "indicator": ind.get('indicator'),
                        "type": ind.get('type'),
                        "source": f"OTX: {pulse_name}"
                    })
            return extracted_iocs
        except Exception as e:
            logger.error(f"OTX API Connection failed: {e}")
            return []