FROM alphaceti/default-python:0.1.3 as base
ENV PROMETHEUS_MULTIPROC_DIR="/usr/src/app/prometheus" \
    PATH="${PATH}:/home/vaulty/.local/bin" \
    PYTHONWARNINGS="ignore:Unverified HTTPS request"
ADD app /usr/src/app
RUN addgroup -S vaulty && \
    adduser -h /home/vaulty -S vaulty -G vaulty && \
    chmod +x /usr/src/app/* && \
    chown -R vaulty:vaulty /usr/src/app && \
    apk add --update --no-cache
EXPOSE 5000/tcp
USER vaulty
WORKDIR /usr/src/app
RUN pip3 install --no-cache-dir -r ./requirements.txt
CMD [ "python3", "./main.py" ]
