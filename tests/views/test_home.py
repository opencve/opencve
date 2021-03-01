from flask import request


def test_home_cve_redirect(client):
    response = client.get("/")
    assert response.status_code == 302

    with client:
        response = client.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/cve"


def test_home_welcome_redirect(app, client):
    app.config["DISPLAY_WELCOME"] = True
    response = client.get("/")
    assert response.status_code == 302

    with client:
        response = client.get("/", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/welcome"
        assert b"<title>Welcome to OpenCVE</title>" in response.data
        assert b"<h1>Welcome to OpenCVE</h1>" in response.data


def test_home_terms(app, client):
    response = client.get("/terms")
    assert response.status_code == 404

    response = client.get("/register")
    assert b"Terms of Service" not in response.data

    app.config["DISPLAY_TERMS"] = True
    response = client.get("/terms")
    assert response.status_code == 200
    assert b"Terms of Service and Privacy Policy" in response.data
    response = client.get("/register")
    assert b"Terms of Service" in response.data
