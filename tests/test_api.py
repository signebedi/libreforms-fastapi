import os, pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker
from sqlalchemy_signing import Signatures
from libreforms_fastapi.utils.sqlalchemy_models import Base, User, Signing, TransactionLog
from libreforms_fastapi.utils.config import yield_config

# os.environ["ENVIRONMENT"] = "testing"
config = yield_config(_env="testing")

# Define a session-scoped fixture for the TestClient and Signatures
@pytest.fixture(scope="session")
def setup_environment():
    # Setup the in-memory SQLite database for testing
    engine = create_engine(
        config.SQLALCHEMY_DATABASE_URI,
        connect_args={"check_same_thread": False},
        isolation_level="READ UNCOMMITTED", 
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    Base.metadata.create_all(bind=engine)

    from libreforms_fastapi.app import app, get_db
    client = TestClient(app)

    # Dependency override for the database
    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    yield client

    Base.metadata.drop_all(bind=engine)

# Individual fixtures for client and signatures to separate concerns and improve readability
@pytest.fixture(scope="session")
def client(setup_environment):
    return setup_environment

@pytest.fixture(scope="session")
def signatures(setup_environment):
    return Signatures(
        config.SQLALCHEMY_DATABASE_URI, byte_len=32, 
        rate_limiting=config.RATE_LIMITS_ENABLED,
        rate_limiting_period=config.RATE_LIMITS_PERIOD, 
        rate_limiting_max_requests=config.RATE_LIMITS_MAX_REQUESTS,
        Base=Base,
        Signing=Signing
    )

@pytest.fixture(scope="module")
def test_api_key(client, signatures):
#     return signatures.write_key(scope=['api_key'])
    response = client.post(
        "/api/auth/create", 
        headers={
            "Content-Type": "application/json"
        },
        json= {
            "username": "testuser",
            "password": "Strongpassword123!",
            "verify_password": "Strongpassword123!",
            "email": "test@example.com",
            "opt_out": False
        }
    )
    data = response.json()
    return data['api_key']



# Test for api_auth_create which should succeed
def test_api_auth_create(client):
    response = client.post(
        "/api/auth/create", 
        headers={
            "Content-Type": "application/json"
        },
        json= {
            "username": "testuser1",
            "password": "Strongpassword123!",
            "verify_password": "Strongpassword123!",
            "email": "test1@example.com",
            "opt_out": False
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "api_key" in data

# Test for api_auth_create which should succeed
def test_api_auth_create_failure(client):
    response = client.post(
        "/api/auth/create", 
        headers={
            "Content-Type": "application/json"
        },
        json= {
            "username": "testuser2",
            "password": "Strongpassword123!",
            "verify_password": "ThisPasswordDoesntMatch",
            "email": "test2@example.com",
            "opt_out": False
        }
    )
    assert response.status_code == 422

# Test for api_form_create
def test_api_form_create(client, test_api_key):
    response = client.post(
        "/api/form/create/example_form", 
        headers={"X-API-Key": test_api_key}, 
        json={
            "text_input": "Sample text",
            "number_input": 99,
            "email_input": "email@example.com",
            "date_input": "2024-01-01",
            "checkbox_input": ["Option1", "Option3"],
            "radio_input": "Option2",
            "select_input": "Option1",
            "textarea_input": "This is a sample textarea content."
        }
    )  
    assert response.status_code == 200
    data = response.json()
    assert "message" in data
    assert data["message"] == "Form submission received and validated"

