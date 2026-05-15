FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY node.py .
EXPOSE 5000
ENTRYPOINT ["python", "node.py"]
CMD ["--port", "5000"]
