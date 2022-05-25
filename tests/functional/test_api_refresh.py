import http


def test_api_refresh_token(client):
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
    refresh_token = result["refresh_token"]
    refresh_header_body = f"Bearer {refresh_token}"

    response = test_client.post(
        path="/v1/refresh",
        headers={'Authorization': refresh_header_body}
    )

    # trying to refresh same token for second time
    assert response.status_code == http.HTTPStatus.OK

    response = test_client.post(
        path="/v1/refresh",
        headers={'Authorization': refresh_header_body}
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED


def test_api_refresh_without_any_token(client):
    test_client = client.test_client()
    response = test_client.post(
        path="/v1/refresh",
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED


def test_api_refresh_wrong_token(client):
    test_client = client.test_client()
    test_client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )
    test_client.post(
        path="/v1/login",
        json={
            "username": "test",
            "password": "test",
        },
    )

    wrong_token = "looks.like.a_token"
    refresh_header_body = f"Bearer {wrong_token}"

    response = test_client.post(
        path="/v1/refresh",
        headers={'Authorization': refresh_header_body}
    )

    assert response.status_code == http.HTTPStatus.UNPROCESSABLE_ENTITY
