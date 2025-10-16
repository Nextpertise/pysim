# Use an official Python base image
FROM python:3.12

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install --no-install-recommends -y \
    pcscd \
    build-essential \
    libpcsclite-dev \
    python3-setuptools \
    python3-pycryptodome \
    python3-pyscard \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy the current directory contents into the container's /app directory
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set the default command to run pysim
ENTRYPOINT ["python", "pySim-prog.py"]