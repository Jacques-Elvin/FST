# Field Service Tracker

A web application for tracking field service progress across multiple blocks and floors.

## Features

- User authentication (login/register)
- Admin dashboard
- Block and floor progress tracking
- Excel report generation
- Progress visualization

## Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/field-service-tracker.git
cd field-service-tracker
```

2. Create and activate a virtual environment:

```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Run the application:

```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Default Admin Account

- Username: admin
- Password: admin123

## Deployment

This application is deployed using Render. Visit the live site at: [Your Render URL]

## Technologies Used

- Flask
- SQLAlchemy
- Bootstrap
- JavaScript
- HTML/CSS
