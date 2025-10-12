### hello welcome, i used pytest to automate some testing 
### but didn't have enough time to finish for all test cases =(
### i mean this file works but whats the point if the rest dont
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(__file__)))
import io
import pytest
from app import app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_eml_uploads_and_final_results(client):
    eml_dir = "attachments_test_samples"
    for filename in os.listdir(eml_dir):
        if filename.endswith(".eml"):
            filepath = os.path.join(eml_dir, filename)
            
            # Read the file content first
            with open(filepath, "rb") as f:
                file_content = f.read()
            
            # Create a BytesIO object to simulate file upload
            data = {
                "email_file": (io.BytesIO(file_content), filename)
            }
            
            response = client.post("/", data=data, content_type="multipart/form-data", headers={ "Accept": "application/json" })
            
            # Assert only eml files accepted
            assert response.status_code == 200 if filename.split('.')[1] == "eml" else response.status_code == 304, f"File upload failed for {filename}: {response.data}"
            
            json_data = response.get_json()

            # Assert 'signals' key exists
            assert 'signals' in json_data, f" {filename}: {response.data}"

            # Assert final result matches thresholds set for scores
            if json_data['score'] < 40:
                expected_verdict = 0
            elif json_data['score'] < 100:
                expected_verdict = 1
            else:
                expected_verdict = 2

            assert json_data['verdict'] == expected_verdict, f"Expected {expected_verdict}, got {json_data['verdict']} for score {json_data['score']}"
