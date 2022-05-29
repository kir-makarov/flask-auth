#!/bin/bash

alembic upgrade head

python pywsgi.py
