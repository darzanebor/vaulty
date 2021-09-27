FROM alphaceti/default-python:0.1.3
ARG VAULT_AUTH \
    VAULT_ADDR \
    VAULT_USER \
    VAULT_PASS \
    VAULT_ROLE \
    VAULT_TLS_VER \
    VAULT_TTL \    
    VAULT_CRED \
    VAULT_MOUNT \
    VAULT_SECRET            
ENV PATH="/home/vaulty/.local/bin:${PATH}" \
    PYTHONWARNINGS="ignore:Unverified HTTPS request" \
    VAULT_AUTH=${VAULT_AUTH} \
    VAULT_ADDR=${VAULT_ADDR:-'change_me'} \
    VAULT_USER=${VAULT_USER:-'change_me'} \
    VAULT_PASS=${VAULT_PASS:-'change_me'} \
    VAULT_ROLE=${VAULT_ROLE:-'change_me'} \    
    VAULT_TTL=${VAULT_TTL} \    
    VAULT_CRED=${VAULT_CRED} \
    VAULT_MOUNT=${VAULT_MOUNT} \
    VAULT_SECRET=${VAULT_SECRET} \
    VAULT_TLS_VER=${VAULT_TLS_VER}
COPY app /usr/src/app
RUN addgroup --gid 1000 -S vaulty && \
    adduser  --uid 1000 -h /usr/src/app -S vaulty -G vaulty && \
    chmod +x /usr/src/app/*.py && \
    chown -R vaulty:vaulty /usr/src/app
WORKDIR /usr/src/app
USER vaulty
RUN pip install --no-cache-dir -r requirements.txt
CMD [ "python3", "./main.py" ]
