import os
import time
from dotenv import load_dotenv
from src.utils.db_manager import DatabaseManager
from src.collectors.otx_collector import OTXCollector
from src.utils.logger import setup_logger
from src.enrichment.vt_enricher import VTEnricher
from src.utils.reporter import Reporter


load_dotenv()
OTX_KEY = os.getenv("OTX_API_KEY")
VT_KEY = os.getenv("VT_API_KEY")


logger = setup_logger()

def run_pipeline():
    """الدالة الرئيسية لإدارة تدفق البيانات في النظام"""
    
   
    db = DatabaseManager()
    collector = OTXCollector(OTX_KEY)
    enricher = VTEnricher(VT_KEY)
    reporter = Reporter()

    logger.info("=== Threat Intelligence Pipeline Started ===")

    
    new_data = collector.fetch_recent_indicators()
    
    if new_data:
        added_count = 0
        for ioc in new_data:
            
            if db.add_ioc(ioc['indicator'], ioc['type'], ioc['source']):
                added_count += 1
        logger.info(f"Ingestion Phase: Added {added_count} new unique IOCs to database.")
    else:
        logger.warning("Ingestion Phase: No new data retrieved from OTX.")

    
    logger.info("Enrichment Phase: Checking indicators with VirusTotal...")
    
    
    query = "SELECT indicator, type FROM iocs WHERE severity = 'unknown' LIMIT 5"
    cursor = db.conn.execute(query)
    items_to_check = cursor.fetchall()

    if not items_to_check:
        logger.info("Enrichment Phase: No new indicators found to enrich.")
    else:
        for indicator, ioc_type in items_to_check:
            logger.info(f"Checking {ioc_type}: {indicator}")
            
            
            severity = enricher.enrich_indicator(indicator, ioc_type)
            
            
            db.update_severity(indicator, severity)
            logger.info(f"Result for {indicator}: {severity}")
            
            
            time.sleep(15)

    
    logger.info("Reporting Phase: Generating final summary report...")
    
    
    report_path = reporter.generate_csv_report(db)
    
    if report_path:
        
        print(f"\n[!!!] ALERT: HIGH RISK THREATS IDENTIFIED!")
        print(f"[!!!] Report saved at: {report_path}\n")
    else:
        logger.info("Reporting Phase: No high-risk threats found for this session.")

    logger.info("=== Threat Intelligence Pipeline Execution Finished ===")

if __name__ == "__main__":
   
    if not OTX_KEY or not VT_KEY:
        logger.error("System Failure: API Keys missing in .env file. Pipeline aborted.")
    else:
        try:
            run_pipeline()
        except KeyboardInterrupt:
            logger.warning("Pipeline interrupted by user.")
        except Exception as e:
            logger.critical(f"Critical System Error: {e}")