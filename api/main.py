from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2AuthorizationCodeBearer
from msal import ConfidentialClientApplication
from dotenv import load_dotenv
import requests
import os
load_dotenv()

app = FastAPI()

# Azure AD Configuration
TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
#REDIRECT_URI = "http://localhost:8000/auth/callback"
SCOPE = ["api://kpn_auth_api/user_impersonation"]

oauth2_scheme = OAuth2AuthorizationCodeBearer(
	authorizationUrl=f"{AUTHORITY}/oauth2/v2.0/authorize",
	tokenUrl=f"{AUTHORITY}/oauth2/v2.0/token"
)

# MSAL Confidential Client
app_client = ConfidentialClientApplication(
	CLIENT_ID,
	authority=AUTHORITY,
	client_credential=CLIENT_SECRET
)

def get_current_user(token: str = Depends(oauth2_scheme)):
	try:
		result = app_client.acquire_token_on_behalf_of(token, SCOPE)
		if "access_token" in result:
			return result
		else:
			raise HTTPException(
				status_code=status.HTTP_401_UNAUTHORIZED,
				detail="Invalid token"
			)
	except Exception as e:
		raise HTTPException(
			status_code=status.HTTP_401_UNAUTHORIZED,
			detail=str(e)
		)

@app.get("/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
	message = "You are authenticated "
	roles = current_user["id_token_claims"].get("roles", [])
	if "api-admins" in roles:
		message += "as an admin"
		
	return {"message" : message }

@app.get("/")
def public_route():
	return {"message": "This is a public route"}

if __name__ == "__main__":
	import uvicorn
	uvicorn.run(app, host="127.0.0.1", port=8000)