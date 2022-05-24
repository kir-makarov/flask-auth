import http

def test_api_login(client):
    test_client = client.test_client()
    response = test_client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )

    assert response.status_code == http.HTTPStatus.CREATED

    response = test_client.post(
        path="/v1/login",
        json={
            "username": "test",
            "password": "test",
        },
    )

    assert response.status_code == http.HTTPStatus.OK

    result = response.json
    assert "access_token" in result
    assert "refresh_token" in result
