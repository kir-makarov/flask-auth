import http


def test_api_register_successful(client):
    response = client.post(
        path="/v1/register",
        json={
            "username": "test",
            "password": "test",
        },
    )

    assert response.status_code == http.HTTPStatus.CREATED

    result = response.json
    assert result == {"message": "User created successfully."}


def test_api_register_wrong_format(client):
    response = client.post(
        path="/v1/register",
        json={
            "username": "test"
        },
    )

    assert response.status_code == http.HTTPStatus.BAD_REQUEST

    result = response.json
    assert result == {"message": {"password": "This field cannot be blank."}}
