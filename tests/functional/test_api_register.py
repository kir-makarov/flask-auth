import http


def test_api_register_successful(client):
    test_client = client.test_client()

    response = test_client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )

    assert response.status_code == http.HTTPStatus.CREATED

    result = response.json
    assert result == {"message": "User created successfully."}


def test_api_register_already_registered(client):
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
        path="/v1/register",
        json={
            "username": "test",
            "password": "some_other_password",
        },
    )

    assert response.status_code == http.HTTPStatus.BAD_REQUEST

    result = response.json
    assert result == {"message": "A user with that username already exists"}


def test_api_register_wrong_format(client):
    test_client = client.test_client()
    response = test_client.post(
        path="/v1/register",
        json={
            "username": "test"
        },
    )

    assert response.status_code == http.HTTPStatus.BAD_REQUEST

    result = response.json
    assert result == {"message": {"password": "This field cannot be blank."}}
