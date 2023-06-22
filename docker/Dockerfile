FROM ubuntu:22.04

WORKDIR /usr/src/app
ENV FLASK_APP=app
ENV AWS_ACCESS_KEY_ID=fake_access_key\
    AWS_SECRET_ACCESS_KEY=fake_secret_access_key\
    DYNAMODB_REGION=ap-northeast-1

COPY . . 
RUN apt update
RUN apt -y install netcat
RUN apt -y install net-tools
RUN apt -y install iputils-ping
RUN apt -y install tcpdump


EXPOSE 80