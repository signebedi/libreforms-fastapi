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
        # SignatureRoles,
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

# Test for api_form_read_all sorting on a metadata field
def test_api_form_read_all_sort_by_metadata(client, test_api_key):
    for _ in range(2):
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

    response = client.get(
        "/api/form/read_all/example_form?sort_by=__metadata__document_id&sort_method=descending",
        headers={"X-API-Key": test_api_key},
    )
    assert response.status_code == 200
    document_ids = [x["metadata"]["document_id"] for x in response.json()["documents"]]
    assert len(document_ids) >= 2
    assert document_ids == sorted(document_ids, reverse=True)

    # The default sort_by should order by creation date
    response = client.get(
        "/api/form/read_all/example_form?sort_method=descending",
        headers={"X-API-Key": test_api_key},
    )
    assert response.status_code == 200
    created_at = [x["metadata"]["created_at"] for x in response.json()["documents"]]
    assert created_at == sorted(created_at, reverse=True)


# Test that optional fields are not required when the form config sets no default for them
def test_get_form_model_optional_field_without_default(client, tmp_path):
    from pydantic import ValidationError
    from libreforms_fastapi.app import SessionLocal, User, Group
    from libreforms_fastapi.utils.pydantic_models import get_form_model

    config_path = tmp_path / "form_config.yml"
    config_path.write_text(
        "test_form:\n"
        "  optional_input:\n"
        "    input_type: text\n"
        "    output_type: !str\n"
        "    required: false\n"
        "  required_input:\n"
        "    input_type: text\n"
        "    output_type: !str\n"
        "    required: true\n"
    )

    with SessionLocal() as session:
        model = get_form_model("test_form", config_path=str(config_path), session=session, User=User, Group=Group)

    assert model(required_input="Sample text").optional_input is None
    with pytest.raises(ValidationError):
        model(optional_input="Sample text")

# Test that route names are unique, as url_for resolves a name to the first route registered with it
def test_route_names_unique(client):
    from collections import Counter
    from libreforms_fastapi.app import app

    names = Counter(route.name for route in app.routes)
    assert [name for name, count in names.items() if count > 1] == []

# Test that every name passed to url_for or a @requires redirect matches a route
def test_url_for_names_resolve(client):
    import re, glob
    import libreforms_fastapi.app as app_package
    from libreforms_fastapi.app import app

    app_dir = os.path.dirname(app_package.__file__)
    name_pattern = re.compile(r"""(?:url_for\(\s*|redirect=)["']([A-Za-z_]\w*)["']""")

    referenced = set()
    for path in glob.glob(os.path.join(app_dir, "templates", "*.jinja")):
        with open(path) as f:
            # Drop Jinja comments, which are never rendered
            referenced |= set(name_pattern.findall(re.sub(r"\{#.*?#\}", "", f.read(), flags=re.DOTALL)))
    for path in glob.glob(os.path.join(app_dir, "*.py")):
        with open(path) as f:
            referenced |= set(name_pattern.findall("".join(l for l in f if not l.lstrip().startswith("#"))))

    route_names = {route.name for route in app.routes}
    assert referenced, "No url_for references found"
    assert sorted(referenced - route_names) == []

# Test that a form with a static-method approval stage doesn't crash the needing-action
# endpoint, which base.html polls on every authenticated page (bug audit item 34)
def test_api_form_read_all_needing_action_with_static_stage(client, test_api_key):
    with open(config.FORM_CONFIG_PATH, "a") as f:
        f.write(
            "staged_form:\n"
            "  __config__:\n"
            "    form_stages:\n"
            "      review:\n"
            "        method: static\n"
            "        target: approver@example.com\n"
            "  note_field:\n"
            "    input_type: text\n"
            "    output_type: !str\n"
            "    required: false\n"
        )

    response = client.get(
        "/api/form/read_all_needing_action?return_count_only=true",
        headers={"X-API-Key": test_api_key},
    )
    assert response.status_code == 200

# Test that search skips forms the user has no read permission on instead of raising, and
# honors read_all for users without read_own (bug audit item 35)
def test_api_form_search_permissions(client, test_api_key):
    from libreforms_fastapi.app import SessionLocal, User, Group

    # A form no group has permissions on: search used to raise a KeyError over it
    with open(config.FORM_CONFIG_PATH, "a") as f:
        f.write(
            "ungranted_form:\n"
            "  some_field:\n"
            "    input_type: text\n"
            "    output_type: !str\n"
            "    required: false\n"
        )

    # Create a document with a distinctive, repeated token so the fuzzy search always
    # aligns on it (see issue 19 on segment alignment)
    response = client.post(
        "/api/form/create/example_form",
        headers={"X-API-Key": test_api_key},
        json={
            "text_input": ("xylophone " * 10).strip(),
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

    response = client.get("/api/form/search?search_term=xylophone", headers={"X-API-Key": test_api_key})
    assert response.status_code == 200
    assert any(x["metadata"]["form_name"] == "example_form" for x in response.json()["documents"])

    # A user whose only permission is example_form:read_all should see other users'
    # documents in search results
    response = client.post(
        "/api/auth/create",
        headers={"Content-Type": "application/json"},
        json={
            "username": "readalluser",
            "password": "Strongpassword123!",
            "verify_password": "Strongpassword123!",
            "email": "readall@example.com",
            "opt_out": False
        }
    )
    assert response.status_code == 200
    read_all_key = response.json()["api_key"]

    with SessionLocal() as session:
        read_all_group = Group(id=3, name="read_all_only", permissions=["example_form:read_all"])
        session.add(read_all_group)
        user = session.query(User).filter_by(username="readalluser").first()
        user.groups = [read_all_group]
        session.commit()

    response = client.get("/api/form/search?search_term=xylophone", headers={"X-API-KEY": read_all_key})
    assert response.status_code == 200
    assert any(x["metadata"]["form_name"] == "example_form" for x in response.json()["documents"])

# Test that the relationship-type existence check queries the RelationshipType table,
# not the User table (bug audit item 57)
def test_api_admin_create_user_relationship_type_lookup(client, test_api_key):
    from libreforms_fastapi.app import SessionLocal, User, RelationshipType

    with SessionLocal() as session:
        user = session.query(User).filter_by(username="testuser").first()
        user.site_admin = True
        session.commit()
        user_id = user.id
        related_user_id = session.query(User).filter_by(username="testuser1").first().id

    headers = {"X-API-Key": test_api_key}

    # Create more relationship types than there are users, so that a valid type id
    # exceeds every user id; the old code validated the type id against the User table
    for name, reciprocal in [
        ("mentor", "mentee"), ("supervisor", "report"), ("sponsor", "sponsee"),
        ("advisor", "advisee"), ("proxy", "principal"), ("trainer", "trainee"),
    ]:
        response = client.post(
            "/api/admin/create_relationship_type",
            headers=headers,
            json={"name": name, "reciprocal_name": reciprocal, "description": "x", "exclusive_relationship": False}
        )
        assert response.status_code == 200

    with SessionLocal() as session:
        max_type_id = max(t.id for t in session.query(RelationshipType).all())
        max_user_id = max(u.id for u in session.query(User).all())
    assert max_type_id > max_user_id, "Precondition: need a type id with no matching user id"

    response = client.post(
        "/api/admin/create_user_relationship",
        headers=headers,
        json={"user_id": user_id, "related_user_id": related_user_id, "relationship_type_id": max_type_id}
    )
    assert response.status_code == 200
