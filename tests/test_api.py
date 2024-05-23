import os, pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, StaticPool
from sqlalchemy.orm import sessionmaker
from sqlalchemy_signing import Signatures
from libreforms_fastapi.utils.sqlalchemy_models import Base, get_sqlalchemy_models

from libreforms_fastapi.utils.config import get_config

# os.environ["ENVIRONMENT"] = "testing"
config = get_config(env="testing")

# Define a session-scoped fixture for the TestClient and Signatures
@pytest.fixture(scope="session")
def setup_environment():

    from libreforms_fastapi.app import ( 
        SessionLocal, 
        User,
        Group,
        TransactionLog,
        SignatureRoles,
        Signing,
        signatures,
        engine,
    )

    # Here we create a group with limited permissions to ensure that the API 
    # appropriately constrains access based on group.
    with SessionLocal() as session:
        bad_group = session.query(Group).get(2)

        if not bad_group:
            # If not, create and add the new group
            bad_permissions = [
                "example_form:create",
                "example_form:read_own",
                # "example_form:read_all",
                "example_form:update_own",
                # "example_form:update_all",
                "example_form:delete_own",
                # "example_form:delete_all"
            ]
            bad_group = Group(id=2, name="bad", permissions=bad_permissions)
            session.add(bad_group)
            session.commit()

    from libreforms_fastapi.app import app, get_db
    client = TestClient(app)

    yield client, signatures

    Base.metadata.drop_all(bind=engine)

# Individual fixtures for client and signatures to separate concerns and improve readability
@pytest.fixture(scope="session")
def client(setup_environment):
    return setup_environment[0]

@pytest.fixture(scope="session")
def signatures(setup_environment):
    # return Signatures(
    #     config.SQLALCHEMY_DATABASE_URI, byte_len=32, 
    #     rate_limiting=config.RATE_LIMITS_ENABLED,
    #     rate_limiting_period=config.RATE_LIMITS_PERIOD, 
    #     rate_limiting_max_requests=config.RATE_LIMITS_MAX_REQUESTS,
    #     Base=Base,
    #     Signing=Signing
    # )
    return setup_environment[1]

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

