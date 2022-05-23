import http


def test_api_login(client):
    response = client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )

    assert response.status_code == http.HTTPStatus.CREATED

    result = response.json
