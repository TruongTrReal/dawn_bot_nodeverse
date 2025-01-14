import asyncio
import gspread
from google.auth import exceptions
from google.oauth2.service_account import Credentials
from datetime import datetime

# Define the Google Sheets credentials and scope
GOOGLE_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCTJ83pYlCG7rP7\n3PZSQQuqYNtTVr268CuDlfwawpCDHWv5j36SYtQmddWVi5dsCsaa9aMyVZeubruJ\nEcNgHOcR3lAVHqAXRUDRldQFQscO/X616hSR0cEbQ0vDdP+LJ11z3cgn+XC995cg\nq2zkC5Hb+73bmYlVcy6oEcDib74wISRcLVx7YUPpdA+w+HppZvtfbityudWpLDL8\nsrujDJyTUEtbk7p0HPO4dsyazVUgdOms1Q5hG+ts8PLfbleSr7RPhr29GEI3fvHc\n/6O2AoVgi6QJcmj+2Nq5qDPe8kcFEXCxSmXKi27oTqHCbFkGzBORPR7Cn6cn5LBf\nxYoQAiRJAgMBAAECggEAIiU/U2M7ukOTQeMAyQ9MzKkS22CqP8FQ54Sa7f6tl67x\nCgRw4zjJb28yMzQj268YbIaI6roPqysImwKjKh8qwuup+2ySyzOHmdpBS0M2e1T4\n3O9G/JsGSvQvlVgFn91vgt44foYT0hCsYalFaBkDLF9aq6URx+ElN1x/PEuffv0n\nkmNgXrwnlDk0hQ2nps3EM4iZniaMBvgfy0Z79dTpEY2/EAyOObOMpIzMMhIP3Pk8\niKpDs4adFfAISZSaZFTifuQIMXja2T9PwoqP+LtYyF/CiCEfFpfm7wqGnSPz3SIY\nF4Bsv8lFeXdoEUSFaoYK1yEtRBmoSH9k4bIsbrGgsQKBgQDKZqAyHeVQDGTHqscq\nxglJ7jObLC9m5WQZUGc3sIgHg+naxPmNpCD4jyUbcOaDGWNY92QxWU/KxWEUHipB\nFiH3EBNIGywPrZejmFm6HsqH9PIAtJ8bFe2wM8XLMI9ehpr35YAkC836yhDS78V3\nDNYGF4SgmVFBRd3O8M8c2oQ9JQKBgQC6H+yjHblCDX7qDOxlblBcOMUKWHvACEcv\n0f/Or8FJ4w/EJAAaORW/qsjiMAIX2xzJBXU78jGPoldjGKep2wX9bJeEa+IxQe8Z\nlECYPf3EoDtmoOfa/Iwx1H47xdO7YGFohieMb4Aa1UiKCw3L45SgSPOGNBktmmKj\nZbg4tHBLVQKBgQCYtmYYakYi57cCj/BGbbWEep2lbuk1Ec886lV2x1NbmERSNFy2\naigWYqr00XKbaAR1k/Oc6G4z6EkfDMOE6FYoO5DQzu+nxKqtXL4WmDTn8ADIV3/U\nx+7XC7kpXjJOd/FlKVxN1jpMBzo6bX7oHF8/qW8AXa3ZOgXppfgfJSCxoQKBgFdS\nQPgqKs9Ve5SdKY9Q2PzbWX5IEw7+Ez/ZOzWh+YILuEriRPYIkC6TFpofweulTfT1\nzZGpSB1GIc+JMqga7M1/0/o5jy5i66VJi6ChfNxx/Exi80QnNjLuqaarYnHHfwvF\n3OojKavtIpI5K2jbxdAJSc9Nw/5EL0DPqUVZSlHdAoGAOmv2BHvLSAsNHmfXblT8\nhyL0ZnkW9YoSddLz+SQRPQg9li5SDRQgLMYA+36j+vkT5xfaFzmoJendgWsDWcbJ\nPbE5UddnawUVudXr03pOARRREKpfFxMQtng5sUlrP/aK4gCn7FLCU2bpAf4TykHF\ntz26qHfMqtYud46L6CKfLX0=\n-----END PRIVATE KEY-----\n"
GOOGLE_SERVICE_ACCOUNT_EMAIL = "nodepayreporttool@test-nodepay-report.iam.gserviceaccount.com"

scope = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]

# Function to authorize Google Sheets API
async def authorize_spreadsheet():
    creds = Credentials.from_service_account_info(
        {
            "type": "service_account",
            "private_key": GOOGLE_PRIVATE_KEY,
            "client_email": GOOGLE_SERVICE_ACCOUNT_EMAIL,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
        },
        scopes=scope,
    )
    
    # Use asyncio.to_thread to avoid blocking the event loop
    client = await asyncio.to_thread(gspread.authorize, creds)
    return client

# Function to update points by email
async def update_points_by_email(spreadsheet_id="1U6o6jwqR0xqNi1QYDDCJvl9s-BeKxemMRWYuFzEFx8U", 
                                 email='', new_points=0):
    try:
        # Get the spreadsheet client asynchronously
        client = await authorize_spreadsheet()
        sheet = await asyncio.to_thread(client.open_by_key, spreadsheet_id)
        worksheet = await asyncio.to_thread(sheet.worksheet, "Dawn")
        
        # Get headers and current date
        headers = await asyncio.to_thread(worksheet.row_values, 1)
        current_date = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        
        # Ensure required columns exist
        if 'last update' not in headers or 'last update point' not in headers or 'Point total' not in headers:
            print("Error: One or more required columns are missing in the sheet.")
            return
        
        # Get column indices for necessary fields
        email_col = headers.index('Email') + 1
        last_update_col = headers.index('last update') + 1
        last_update_point_col = headers.index('last update point') + 1
        point_total_col = headers.index('Point total') + 1
        
        # Get all rows from the sheet, passing the expected headers to avoid duplicates
        expected_headers = ['Email', 'last update', 'last update point', 'Point total']
        rows = await asyncio.to_thread(worksheet.get_all_records, empty2zero=False, head=1, expected_headers=expected_headers)

        # Iterate through rows to find the matching email
        for i, row in enumerate(rows, start=2):
            if row['Email'] == email:
                existing_points = row['Point total'] if isinstance(row['Point total'], (int, float)) else 0
                
                # Update the fields asynchronously
                await asyncio.to_thread(worksheet.update_cell, i, last_update_col, current_date)
                await asyncio.to_thread(worksheet.update_cell, i, last_update_point_col, existing_points)
                await asyncio.to_thread(worksheet.update_cell, i, point_total_col, new_points)
                return

    except exceptions.GoogleAuthError as error:
        print(f"Authentication failed: {error}")
    except Exception as e:
        print(f"Error: {e}")


