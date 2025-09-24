FROM python:3.11-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py ./
EXPOSE 8501
# Streamlit config to allow containerized access
ENV STREAMLIT_SERVER_ENABLECORS=false STREAMLIT_SERVER_ENABLEXsSRFProtection=false STREAMLIT_SERVER_ADDRESS=0.0.0.0
CMD ["streamlit","run","app.py","--server.port=8501","--server.address=0.0.0.0"]
