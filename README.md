# Firewall Rule Engine

A lightweight firewall rule engine exposing a REST API to manage rules, evaluate packets, and store audit logs.

Badges: Python | Flask | SQLite | pytest

## Features

- Create, list, fetch, and delete firewall rules with priorities
- Evaluate single packets or batches against priority-ordered rules
- Persistent rule storage and audit logging (SQLite)
- REST API built with Flask
- Input validation and sanitization
- Test suite with pytest and coverage

## Tech Stack

- Python
- Flask
- SQLite (sqlite3)
- pytest

## Setup

1. Clone the repository:

```bash
git clone <repo-url>
cd firewall-rule-engine
```

2. Create a virtual environment:

```bash
python -m venv venv
```

3. Activate the virtual environment:

On Windows:

```powershell
venv\Scripts\activate
```

On macOS/Linux:

```bash
source venv/bin/activate
```

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run the application:

```bash
python run.py
```

You should see a startup banner indicating the API and database in use.

## API Endpoints

Base URL: http://localhost:5000/api

- GET /rules
	- Description: List all rules
	- Example:
		```bash
		curl -s http://localhost:5000/api/rules
		```

- GET /rules/<rule_id>
	- Description: Get a rule by ID
	- Example:
		```bash
		curl -s http://localhost:5000/api/rules/<rule_id>
		```

- POST /rules
	- Description: Create a new rule (JSON body)
	- Example:
		```bash
		curl -X POST http://localhost:5000/api/rules \
			-H "Content-Type: application/json" \
			-d '{"name":"Block HTTP","action":"deny","protocol":"TCP","src_ip":"*","dst_ip":"*","dst_port":80,"priority":1}'
		```

- DELETE /rules/<rule_id>
	- Description: Delete a rule
	- Example:
		```bash
		curl -X DELETE http://localhost:5000/api/rules/<rule_id>
		```

- POST /evaluate
	- Description: Evaluate a single packet (JSON body)
	- Example:
		```bash
		curl -X POST http://localhost:5000/api/evaluate \
			-H "Content-Type: application/json" \
			-d '{"src_ip":"192.168.1.1","dst_ip":"10.0.0.5","src_port":5000,"dst_port":80,"protocol":"TCP"}'
		```

- POST /evaluate/batch
	- Description: Evaluate a batch of packets (JSON array)
	- Example:
		```bash
		curl -X POST http://localhost:5000/api/evaluate/batch \
			-H "Content-Type: application/json" \
			-d '[{"src_ip":"192.168.1.1","dst_ip":"10.0.0.5","src_port":5000,"dst_port":80,"protocol":"TCP"}]'
		```

- GET /logs
	- Description: Get audit log entries
	- Example:
		```bash
		curl -s http://localhost:5000/api/logs
		```

- DELETE /logs
	- Description: Clear the audit log
	- Example:
		```bash
		curl -X DELETE http://localhost:5000/api/logs
		```

- GET /stats
	- Description: Get summary statistics
	- Example:
		```bash
		curl -s http://localhost:5000/api/stats
		```

## Running Tests

Run the test suite with coverage:

```bash
pytest --cov=app tests/ --cov-report=term-missing
```

## Architecture Overview

- `app/` - Flask application package
	- `models/` - `Rule` and `Packet` data models with validation and serialization
	- `engine/` - `FirewallEngine` evaluates packets against rules
	- `database/` - SQLite persistence and audit logging
	- `api/` - Flask blueprint exposing REST endpoints
- `tests/` - pytest test suite covering models, engine, API, and database

## Sample Output

![Sample Output Placeholder](docs/sample_output_placeholder.png)

