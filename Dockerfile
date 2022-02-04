FROM python:3.8

ADD ./ /usr/src/storage
WORKDIR /usr/src/storage

RUN pip install -r ./requirements.txt


CMD ["python", "manage.py", "migrate"]
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]