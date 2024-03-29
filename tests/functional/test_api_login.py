import http


def test_api_login_siccessful(client):
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


def test_api_login_wrong_password(client):
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
            "password": "wrong_password",
        },
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED

    result = response.json
    assert result == {"message": "Invalid credentials"}


def test_api_login_unknown_user(client):
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
            "username": "unknown_username",
            "password": "the_password",
        },
    )

    assert response.status_code == http.HTTPStatus.UNAUTHORIZED

    result = response.json
    assert result == {"message": "Invalid credentials"}
