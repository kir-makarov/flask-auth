#!/bin/bash

sleep 3

alembic upgrade head

python pywsgi.py
