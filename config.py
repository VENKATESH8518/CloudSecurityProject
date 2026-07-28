import os

# ==========================================
# BASE DIRECTORY
# ==========================================

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


# ==========================================
# CONFIGURATION CLASS
# ==========================================

class Config:

    # -----------------------------
    # SECRET KEY
    # -----------------------------
    SECRET_KEY = "CloudSecurityProject2026"

    # -----------------------------
    # SQLITE DATABASE
    # -----------------------------
    DATABASE = os.path.join(
        BASE_DIR,
        "cloud_security.db"
    )

    # -----------------------------
    # STORAGE FOLDERS
    # -----------------------------
    UPLOAD_FOLDER = os.path.join(
        BASE_DIR,
        "cloud_storage",
        "uploads"
    )

    ENCRYPTED_FOLDER = os.path.join(
        BASE_DIR,
        "cloud_storage",
        "encrypted"
    )

    KEY_FOLDER = os.path.join(
        BASE_DIR,
        "cloud_storage",
        "keys"
    )

    METADATA_FOLDER = os.path.join(
        BASE_DIR,
        "cloud_storage",
        "metadata"
    )

    LOG_FOLDER = os.path.join(
        BASE_DIR,
        "logs"
    )

    # -----------------------------
    # MAX FILE SIZE
    # -----------------------------
    MAX_CONTENT_LENGTH = 20 * 1024 * 1024

    # ==========================================
    # EMAIL CONFIGURATION
    # ==========================================

    MAIL_SERVER = "smtp.gmail.com"

    MAIL_PORT = 587

    MAIL_USE_TLS = True

    MAIL_USE_SSL = False

    # Replace with your Gmail address
    MAIL_USERNAME = "venkateshkrishnamurthy06@gmail.com"

    # Replace with your Google App Password
    MAIL_PASSWORD = "apvtahdxkokqjqex"

    # Same Gmail address as above
    MAIL_DEFAULT_SENDER = "venkateshkrishnamurthy06@gmail.com"