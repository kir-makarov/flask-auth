FROM python:3.10-slim


ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

ENV HOME=/src

WORKDIR $HOME


RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY src $HOME
EXPOSE 5000

RUN chmod +x /src/entrypoint.sh

ENTRYPOINT ["/src/entrypoint.sh"]