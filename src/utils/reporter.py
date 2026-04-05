import csv
import os
import logging
from datetime import datetime

logger = logging.getLogger("ThreatIntel.Reporter")

class Reporter:
    def __init__(self, output_dir="reports"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_csv_report(self, db_manager):
        """تصدير التهديدات الخطيرة فقط إلى ملف CSV"""
        
        # استعلام لجلب التهديدات العالية والحرجة فقط
        query = "SELECT indicator, type, source, severity, first_seen FROM iocs WHERE severity IN ('High', 'Critical') ORDER BY first_seen DESC"
        
        try:
            cursor = db_manager.conn.execute(query)
            rows = cursor.fetchall()

            if not rows:
                logger.info("No high-risk threats found to report.")
                return None

            # إنشاء اسم ملف فريد يعتمد على الوقت الحالي
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"high_risk_threats_{timestamp}.csv"
            filepath = os.path.join(self.output_dir, filename)

            # كتابة البيانات في ملف CSV
            with open(filepath, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                # كتابة العناوين (Headers)
                writer.writerow(['Indicator', 'Type', 'Source', 'Severity', 'Detected At'])
                # كتابة البيانات
                writer.writerows(rows)

            logger.info(f"Report generated successfully: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            return None