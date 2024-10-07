class Config:
    SECRET_KEY = 'sdadasdasdasd'
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max-limit
    DATABASE_URI = 'sqlite:///security_scanner.db'  # or your preferred database