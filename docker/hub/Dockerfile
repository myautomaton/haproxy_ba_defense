FROM python:3.10.15-alpine3.20
RUN apk update && apk upgrade --no-cache

RUN apk add bash

RUN apk add \
    build-base \
    libpq \
    libpq-dev \
    curl

RUN pip3 install --upgrade pip
RUN pip3 install pyyaml


COPY apis/ /opt/apis/
RUN chmod +x /opt/apis/* -R
COPY hub.py /opt/hub.py
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

RUN touch /opt/asd.log
CMD /opt/entrypoint.sh
