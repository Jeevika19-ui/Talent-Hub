import uuid
import requests
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from pymongo import MongoClient
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse
from datetime import datetime
from dotenv import load_dotenv
import os

load_dotenv()

class GoogleLoginHandler:
    def __init__(self):
        self.client_id = os.getenv("GOOGLE_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_CLIENT_SECRET")
        self.redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
        self.scopes = os.getenv("GOOGLE_SCOPES").split()  # Split into list, e.g., ['openid', 'email', ...]
        self.mongo_client = MongoClient("mongodb://localhost:27017")
        self.db = self.mongo_client["calendar_app"]
        self.users_collection = self.db["users"]  # Reuse same collection; add a "provider" field to distinguish

    def get_flow(self, state=None):
        # Configure the OAuth flow with client config (no JSON file needed)
        client_config = {
            "web": {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [self.redirect_uri],
            }
        }
        flow = Flow.from_client_config(
            client_config,
            scopes=self.scopes,
            redirect_uri=self.redirect_uri,
            state=state
        )
        return flow

    async def initiate_login(self):
        state = str(uuid.uuid4())
        flow = self.get_flow(state=state)
        authorization_url, _ = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='select_account')
        response = RedirectResponse(authorization_url)
        response.set_cookie("oauth_state", state, httponly=True, secure=False)  # Secure=False for localhost
        return response

    async def handle_callback(self, request: Request):
        incoming_state = request.query_params.get("state")
        stored_state = request.cookies.get("oauth_state")
        if not incoming_state or incoming_state != stored_state:
            raise HTTPException(status_code=400, detail="State mismatch")

        code = request.query_params.get("code")
        if not code:
            raise HTTPException(status_code=400, detail="No code in callback")

        flow = self.get_flow(state=incoming_state)
        flow.fetch_token(code=code)
        credentials = flow.credentials

        # Fetch user details from Google (similar to Microsoft Graph /me)
        user_info_service = build('oauth2', 'v2', credentials=credentials)
        user_info = user_info_service.userinfo().get().execute()
        user_id = user_info.get("id")  # Google's unique user ID

        # Store or update user tokens and details in MongoDB (add "provider" to distinguish from Microsoft users)
        self.users_collection.update_one(
            {"user_id": user_id},
            {"$set": {
                "user_id": user_id,
                "provider": "google",  # Distinguish from Microsoft users
                "access_token": credentials.token,
                "refresh_token": credentials.refresh_token,
                "expires_in": credentials.expiry,
                "display_name": user_info.get("name"),
                "email": user_info.get("email"),
                "given_name": user_info.get("given_name"),
                "surname": user_info.get("family_name"),
                "picture": user_info.get("picture"),  # Extra: profile picture URL
                "last_login": datetime.utcnow()
            }},
            upsert=True
        )
        return RedirectResponse(url=f"http://localhost:8080/dashboard?user_id={user_id}")