# Like API

## Overview
A Flask-based API that interacts with game servers using protobuf messages and AES encryption. Features API key management with daily quotas stored in MongoDB.

## Tech Stack
- Python 3.11
- Flask (with async support)
- Protobuf for message serialization
- PyCryptodome for AES encryption
- aiohttp for async HTTP requests
- MongoDB (via pymongo) for API key and token storage

## Environment Variables Required
- `MONGODB_URI` - MongoDB connection string (required for full functionality)

## Project Structure
- `app.py` - Main Flask application with API endpoints
- `wsgi.py` - WSGI entry point
- `index.py` - Vercel deployment entry
- `like_pb2.py`, `like_count_pb2.py`, `uid_generator_pb2.py` - Protobuf generated files
- `uid_*.json` - UID configuration files
- `jwt_generator.py` - JWT token utilities

## API Endpoints
- `GET /like?uid=<user_id>&server_name=<server>&api_key=<key>` - Process like requests for a user
- `POST /create-api-key` - Create a new API key with optional quota
- `GET /api-key-status?api_key=<key>` - Check API key status and remaining quota
- `GET /health` - Health check endpoint

## Running Locally
The app runs on port 5000 with `python app.py`

## Deployment
Uses gunicorn for production deployment:
```
gunicorn --bind 0.0.0.0:5000 app:app
```
