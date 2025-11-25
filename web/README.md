# Recon Tool Web Dashboard

HTML/CSS/JS dashboard for the Recon Framework with dark theme.

## Features

- 🎨 **Modern Dark Theme** - Beautiful dark UI matching the original Streamlit design
- 🚀 **Start New Scans** - Launch recon scans for domains or domain lists
- 📊 **Visualization** - View metrics and results
- 📁 **Target Management** - View, download, and delete scan results
- 📄 **Output Viewer** - Browse and view output files
- 🔐 **Authentication** - Secure login system

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Start the API Server

```bash
cd Recon_Framework/recon_framework
python web/api_server.py
```

The server will start on `http://localhost:5000`

### Open the Dashboard

Open `web/index.html` in your web browser, or serve it via the API server:

```
http://localhost:5000/web/index.html
```

Or simply open the file directly:
```bash
# On Linux/Mac
open web/index.html

# On Windows
start web/index.html
```

## Default Password

The default password is `recontool@` (can be changed via `RECON_UI_PASSWORD` environment variable).

## API Endpoints

The API server provides the following endpoints:

- `GET /api/auth/check` - Check authentication status
- `POST /api/auth/login` - Login
- `POST /api/upload` - Upload domain list file
- `POST /api/scan/run` - Run recon scan
- `POST /api/scan/stop` - Stop running scan
- `GET /api/targets` - Get all targets
- `GET /api/targets/<path>/summary` - Get target summary
- `GET /api/targets/<path>/files` - Get target files
- `GET /api/targets/<path>/files/<file>` - Get file content
- `GET /api/targets/<path>/download` - Download target as ZIP
- `DELETE /api/targets/<path>` - Delete target

## File Structure

```
web/
├── index.html      # Main HTML file
├── style.css       # CSS styling
├── app.js          # JavaScript logic
└── README.md       # This file

api_server.py       # Flask API server (in parent directory)
```

## Notes

- The dashboard uses the same authentication system as the Streamlit version
- All scan outputs are saved to `recon_output/` directory
- Uploaded files are saved to `uploads/` directory
- The API server must be running for the dashboard to function

