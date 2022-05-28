import http


def test_api_validate_ok(client):
    test_client = client.test_client()
    test_client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )
    response = test_client.post(
        path="/v1/login",
        json={
            "username": "test",
            "password": "test",
        },
    )

    result = response.json
    access_token = result["access_token"]
    access_header_body = f"Bearer {access_token}"

    response = test_client.post(
        path=f"/v1/validate",
        headers={'Authorization': access_header_body})

    assert response.status_code == http.HTTPStatus.OK
    result = response.json
    assert result == {"verified": "true", "role": []}


def test_api_validate_after_logout(client):
    test_client = client.test_client()
    test_client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )
    response = test_client.post(
        path="/v1/login",
        json={
            "username": "test",
            "password": "test",
        },
    )

    result = response.json
    access_token = result["access_token"]
    access_header_body = f"Bearer {access_token}"

    test_client.post(
        path=f"/v1/logout",
        headers={'Authorization': access_header_body})

    response = test_client.post(
        path=f"/v1/validate",
        headers={'Authorization': access_header_body})

    assert response.status_code == http.HTTPStatus.OK
    result = response.json
    assert result == {"verified": "false"}
