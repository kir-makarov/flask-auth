import http


def test_api_login_logout(client):
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

    assert response.status_code == http.HTTPStatus.OK

    result = response.json
    access_token = result["access_token"]
    access_header_body = f"Bearer {access_token}"

    response = test_client.post(
        path="/v1/logout",
        headers={'Authorization': access_header_body}
    )

    # logout for second time with same access token
    assert response.status_code == http.HTTPStatus.OK

    response = test_client.post(
        path="/v1/logout",
        headers={'Authorization': access_header_body}
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED

def test_api_logout_wihtout_tokens(client):
    test_client = client.test_client()

    response = test_client.post(
        path="/v1/logout",
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED
