import os
import pytest
from app import app  # import your Flask app

@pytest.fixture
def client():
    with app.test_client() as client:
        yield client

def test_eml_uploads(client):
    eml_dir = "eml_samples_multi"  # relative or absolute path to your samples
    for filename in os.listdir(eml_dir):
        if filename.endswith(".eml"):
            filepath = os.path.join(eml_dir, filename)
            with open(filepath, "rb") as f:
                data = {"file": (f, filename)}
                response = client.post("/upload", data=data, content_type="multipart/form-data")

                # Check the server responded OK
                assert response.status_code == 200

                # If your Flask returns JSON, you can check structure
                json_data = response.get_json()
                assert "signals" in json_data  # example expectation
