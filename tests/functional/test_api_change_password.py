import http


def test_api_change_password_success(client):
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
    user_id = result["user_id"]
    access_header_body = f"Bearer {access_token}"

    response = test_client.post(
        path=f"/v1/user/{user_id}/change-password",
        headers={'Authorization': access_header_body},
        json={"old_password": "test",
              "new_password": "test_new"})

    assert response.status_code == http.HTTPStatus.OK


def test_api_change_password_wrong_pass(client):
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
    user_id = result["user_id"]
    access_header_body = f"Bearer {access_token}"

    response = test_client.post(
        path=f"/v1/user/{user_id}/change-password",
        headers={'Authorization': access_header_body},
        json={"old_password": "wrong_password",
              "new_password": "test_new"})

    assert response.status_code == http.HTTPStatus.NOT_FOUND
    result = response.json
    assert result == {"message": "User not found or incorrect password"}


def test_api_change_password_for_wrong_user(client):
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
    user_id = "some-wrong-user-id"
    access_header_body = f"Bearer {access_token}"

    response = test_client.post(
        path=f"/v1/user/{user_id}/change-password",
        headers={'Authorization': access_header_body},
        json={"old_password": "test",
              "new_password": "test_new"})

    assert response.status_code == http.HTTPStatus.NOT_FOUND
    result = response.json
    assert result == {"message": "User not found or incorrect password"}
