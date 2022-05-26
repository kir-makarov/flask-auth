FROM python:3.8.6-slim


ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

ENV HOME=/src

WORKDIR $HOME

COPY src $HOME
EXPOSE 5000

CMD python app.py