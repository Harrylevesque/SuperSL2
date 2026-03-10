# Use an official Python image
FROM python:3.12-slim

# Metadata
LABEL maintainer="Harry Levesque <harrylevesque17@gmail.com>"
LABEL description="SAMFpy Server Docker container"

# Set working directory
WORKDIR /app

# Install git for cloning the repo
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Environment variables
ENV PORT=8189
ENV PYTHONUNBUFFERED=1

# Clone the repo and checkout main branch
RUN git clone -b main https://github.com/Harrylevesque/SAMFpy-Server.git .

# Install Python dependencies
RUN python -m venv venv
RUN . venv/bin/activate && pip install --upgrade pip && pip install -r requirements.txt

# Expose port
EXPOSE $PORT

# Entrypoint to start the server
CMD ["/bin/bash", "-c", ". venv/bin/activate && exec uvicorn main:app --host 0.0.0.0 --port $PORT"]
