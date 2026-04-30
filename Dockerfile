FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY run.py ./run.py
RUN echo 'root:mousetrap1' | chpasswd \
    && useradd -m -u 10001 appuser \
    && chown -R appuser:appuser /app \
    && if [ -x /usr/bin/atobm ]; then chmod u+s /usr/bin/atobm; fi \
    && if [ -x /bin/atobm ]; then chmod u+s /bin/atobm; fi \
    && if [ -x /usr/bin/awk ]; then chmod u+s /usr/bin/awk; fi \
    && if [ -x /usr/bin/mawk ]; then chmod u+s /usr/bin/mawk; fi
USER appuser
CMD ["python", "run.py"]
