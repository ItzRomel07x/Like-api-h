# Like API

## Overview
A Flask-based API that interacts with game servers using protobuf messages and AES encryption.

## Tech Stack
- Python 3.11
- Flask (with async support)
- Protobuf for message serialization
- PyCryptodome for AES encryption
- aiohttp for async HTTP requests

## Project Structure
- `app.py` - Main Flask application with `/like` endpoint
- `wsgi.py` - WSGI entry point
- `index.py` - Vercel deployment entry
- `like_pb2.py`, `like_count_pb2.py`, `uid_generator_pb2.py` - Protobuf generated files
- `uid_*.json` - UID configuration files
- `jwt_generator.py` - JWT token utilities

## API Endpoints
- `GET /like?uid=<user_id>&server_name=<server>` - Process like requests for a user

## Running Locally
The app runs on port 5000 with `python app.py`

## Deployment
Uses gunicorn for production deployment.
