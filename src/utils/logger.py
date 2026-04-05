import logging
import os

def setup_logger():
    # التأكد من وجود مجلد للسجلات
    os.makedirs("logs", exist_ok=True)

    # إعداد الإعدادات الأساسية
    logging.basicConfig(
        level=logging.INFO, # المستوى الأدنى الذي سيتم تسجيله
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", # تنسيق السجل
        handlers=[
            logging.FileHandler("logs/pipeline.log"), # حفظ في ملف
            logging.StreamHandler() # عرض على الشاشة (الكونسول)
        ]
    )
    return logging.getLogger("ThreatIntel")