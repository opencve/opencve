def test_list_no_cwes(client):
    response = client.get("/cwe")
    assert response.status_code == 200
    assert b"No CWE found." in response.data


def taest_list_cwes(client, create_cwes, create_cwe):
    create_cwes("CWE-1", "Name of the fist CWE", "Description of the first CWE")
    create_cwes("CWE-2", "Name of the second CWE", "Description of the second CWE")

    response = client.get("/cwe")
    assert response.status_code == 200
    assert b"CWE-1" in response.data
    assert b"Name of the fist CWE" in response.data
    assert b"Description of the first CWE" in response.data
    assert b"CWE-2" in response.data
    assert b"Name of the second CWE" in response.data
    assert b"Description of the second CWE" in response.data
