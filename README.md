# FileShare

A full-stack cloud file sharing system built with Python Flask.

## Features
- User registration and login with JWT authentication
- File upload with drag and drop support (up to 100 MB)
- File listing, download, and deletion
- Shareable public links with optional expiry (1h / 24h / 3d / 7d)
- Secure — files tied to owner, blocked dangerous extensions (.exe, .bat, etc.)

## Tech Stack
| Layer    | Technology          |
|----------|---------------------|
| Backend  | Python, Flask       |
| Database | SQLite              |
| Auth     | JWT + bcrypt        |
| Frontend | HTML, CSS, JS       |

## Project Structure
```
fileshare/
├── backend/
│   ├── app.py              # Flask app
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── index.html          # Login / Register
│   ├── dashboard.html      # File manager
│   ├── share.html          # Public download page
│   └── css/style.css
├── .gitignore
└── README.md
```

## Quick Start (Local)
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env        # set SECRET_KEY
python app.py
# Open http://localhost:3000
```

## Deploy on AWS EC2
```bash
# On the EC2 instance (Ubuntu 22.04)
git clone https://github.com/Rajesh-ux264/File-sharing-system.git fileshare
cd fileshare/backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt gunicorn
cp .env.example .env        # set SECRET_KEY
gunicorn --bind 0.0.0.0:3000 app:app
```

## API Reference
| Method | Endpoint                      | Auth | Description           |
|--------|-------------------------------|------|-----------------------|
| POST   | /api/auth/register            | No   | Register new user     |
| POST   | /api/auth/login               | No   | Login, get JWT token  |
| GET    | /api/auth/me                  | Yes  | Current user info     |
| GET    | /api/files                    | Yes  | List files            |
| POST   | /api/files/upload             | Yes  | Upload files          |
| GET    | /api/files/:id/download       | Yes  | Download file         |
| DELETE | /api/files/:id                | Yes  | Delete file           |
| POST   | /api/files/:id/share          | Yes  | Create share link     |
| DELETE | /api/files/:id/share          | Yes  | Revoke share link     |
| GET    | /api/files/shared/:token      | No   | Public download       |
| GET    | /api/files/shared/:token/info | No   | Public file info      |
