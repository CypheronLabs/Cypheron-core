import requests
import json
import os

# --- SECURITY NOTICE ---
# Admin API key is now loaded from environment variable for security.
# Set the ADMIN_API_KEY environment variable before running this script.
# --- END SECURITY NOTICE ---

API_BASE_URL = "https://api.cypheronlabs.com"
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

if not ADMIN_API_KEY:
    print("ERROR: ADMIN_API_KEY environment variable is required.")
    print("Please set it before running this script:")
    print("export ADMIN_API_KEY='your_admin_key_here'")
    exit(1)

# List of API key IDs to delete
api_key_ids_to_delete = [
    "48f03c76-fe5b-49a5-8ee3-dc90982b8cde",
    "b9f03683-40f2-485b-8d87-4110ed6d2f42",
    "e2971d77-390e-4553-94ec-f3eb45537f1c",
    "2be31213-b10c-4bc6-914d-c04c2c8389bd",
    "2dc47eae-4e3b-4b6d-a574-587b9b5e166c",
    "e2111f55-253f-4b13-9603-3349a2e3cdba",
    "d731d4d6-6bf6-4eaa-85a3-3f2b650d4c15",
    "766519af-6ff0-4907-8b9b-f3f0a9dcf99c"
]

headers = {
    "X-API-Key": ADMIN_API_KEY,
    "Content-Type": "application/json"
}

print(f"Attempting to delete {len(api_key_ids_to_delete)} API keys...")

for key_id in api_key_ids_to_delete:
    url = f"{API_BASE_URL}/admin/api-keys/{key_id}"
    print(f"Deleting key: {key_id}...")
    try:
        response = requests.delete(url, headers=headers)
        if response.status_code == 200:
            print(f"Successfully deleted key: {key_id}")
        elif response.status_code == 404:
            print(f"Key not found (already deleted or invalid ID): {key_id}")
        else:
            print(f"Failed to delete key {key_id}. Status: {response.status_code}, Response: {response.text}")
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while deleting key {key_id}: {e}")

print("\nDeletion process complete.")
