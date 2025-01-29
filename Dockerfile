FROM python:3.11-slim
#FROM python:3.11-alpine3.20

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /wtf_app

RUN apt-get update && apt-get install -y libpq-dev build-essential

COPY requirements.txt .

#RUN pip install --upgrade pip
#to run it from a venv:
RUN python -m venv /venv311 && /venv311/bin/pip install --no-cache-dir -r requirements.txt
RUN mkdir _Log_FW_ && chmod -R 777 _Log_FW_
#RUN pip install -r requirements.txt 

ENV PATH="/venv311/bin:$PATH"

COPY . .

EXPOSE 8000

CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]



