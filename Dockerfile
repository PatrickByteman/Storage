FROM python:3.8

COPY ./ /usr/src/storage
WORKDIR /usr/src/storage

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip
RUN pip install -r ./requirements.txt

# listen port
EXPOSE 8000

RUN python manage.py migrate
#RUN python manage.py runserver 127.0.0.1:8000
#CMD ["python", "manage.py", "migrate"]
#CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]