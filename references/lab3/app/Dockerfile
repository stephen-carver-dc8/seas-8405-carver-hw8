FROM python:3.13
ENV FLASK_DEBUG=1

# Install compatible XML libraries
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libxml2-dev \
        libxmlsec1-dev \
        libxmlsec1-openssl \
        pkg-config \
        xmlsec1 \
        libtool \
        libssl-dev \
       openssl \
        make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY saml /app/saml


COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
#CMD ["flask", "run", "--host=0.0.0.0", "--debug"]

