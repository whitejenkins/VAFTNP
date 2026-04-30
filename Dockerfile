FROM python:3.12-slim
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends x11-apps \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY run.py ./run.py
RUN sed -ri 's/^#?\s*ENCRYPT_METHOD\s+.*/ENCRYPT_METHOD MD5/' /etc/login.defs \
    && echo 'root:whiterose' | chpasswd -c MD5 \
    && useradd -m -u 10001 appuser \
    && chown -R appuser:appuser /app \
    && if [ -x /usr/bin/atobm ]; then chmod u+s /usr/bin/atobm; fi \
    && if [ -x /bin/atobm ]; then chmod u+s /bin/atobm; fi \
    && if [ -x /usr/bin/awk ]; then chmod u+s /usr/bin/awk; fi \
    && if [ -x /usr/bin/mawk ]; then chmod u+s /usr/bin/mawk; fi \
    && if [ -x /usr/bin/base64 ]; then chmod u+s /usr/bin/base64; fi
USER appuser
CMD ["python", "run.py"]
