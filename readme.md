# Сервис аутентификации и авторизации (спринт 6)

### Установка сервиса

Склонировать репозиторий
https://github.com/kir-makarov/flask-auth.git

Далее находясь в папке сервиса:

1. создайте папку .data монтирования к образу Postgres

2. в папке /src переименуйте файл .env.example в .env
описание важных переменных окружения:
JWT_SECRET_KEY - секретный ключ необходимый для формирования jwt токена (храните его в секрете!)
JWT_ACCESS_TOKEN_EXPIRES - время жизни jwt токена в секундах

3. для запуска сервиса выполните команды:

docker-compose build

docker-compose up -d


сервис будет доступен по порту 80

описание api сервиса можно посмотреть по адресу: http://127.0.0.1/apidocs/


### Запуск тестов

Для запуска тестов нужно выполнить команды

docker-compose -f docker-compose-tests.yaml build

docker-compose -f docker-compose-tests.yaml up -d

после запуска логи выполнения тестов можно посмотреть командой

docker-compose logs flask-auth

все тесты должны быть со статусом **passed**