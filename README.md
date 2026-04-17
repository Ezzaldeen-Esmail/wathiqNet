# Network Intrusion Detection System (WathiqNet)

A comprehensive web-based network security monitoring solution built with Flask, Bootstrap, and PostgreSQL.

## Features

- **Real-time Network Monitoring**: Capture and analyze network traffic in real-time
- **Threat Detection Engine**: Automated detection of:
  - Traffic spikes and DDoS patterns
  - Brute-force attacks
  - Port scanning activities
  - Suspicious IP communications
  - Protocol anomalies
- **Alert Management**: Track, investigate, and resolve security alerts
- **Network Device Tracking**: Monitor connected devices with auto-status updates
- **Daily Log Viewer**: Real-time log viewing with filtering and CSV export
- **PDF Reports**: Automated weekly security reports
- **Role-Based Access Control**: Admin and Viewer roles with different permissions

## Tech Stack

- **Backend**: Python Flask with Flask-SocketIO for real-time updates
- **Frontend**: Bootstrap 5, Chart.js, JavaScript
- **Database**: PostgreSQL
- **Charts**: Chart.js for interactive visualizations

## Installation

### Prerequisites

- Python 3.8+
- PostgreSQL 12+
- pip

### Setup

1. **Clone the repository**
   ```bash
   cd anv-wathiq-project
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Setup PostgreSQL database**
   ```sql
   CREATE DATABASE wathiqnet_db;
   ```

5. **Configure environment** (optional)
   ```bash
   set DATABASE_URL=postgresql://postgres:password@localhost:5432/wathiqnet_db
   set SECRET_KEY=your-secret-key
   ```

6. **Run the application**
   ```bash
   python run.py
   ```

7. **Access the application**
   - URL: http://localhost:5000
   - Default admin: `admin` / `admin123`

## Project Structure

```
anv-wathiq-project/
├── app/
│   ├── __init__.py         # Flask app factory
│   ├── config.py           # Configuration settings
│   ├── models/             # Database models
│   ├── routes/             # Route blueprints
│   ├── detection/          # Detection engine
│   └── utils/              # Utility functions
├── templates/              # HTML templates
├── static/                 # CSS and JavaScript
├── data/                   # Log files and reports
├── requirements.txt
└── run.py                  # Entry point
```

## Usage

### Uploading Log Files

1. Login as admin
2. Go to Admin → Data Management
3. Upload CSV or JSON log files
4. System will process and generate alerts automatically

### Viewing Alerts

1. Navigate to Alerts page
2. Filter by severity, type, or status
3. Click on alert to view details
4. Mark as resolved or add notes

### Generating Reports

1. Go to Reports page
2. Click "Generate New Report"
3. Download PDF report

## Default Users

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |

## Security Notes

- Change default admin password immediately
- Use HTTPS in production
- Set a strong SECRET_KEY
- Regular database backups recommended

## License

MIT License
