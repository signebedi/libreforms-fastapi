# Use an official Python runtime as a parent image
FROM python:3.10

# Set the working directory in the container
WORKDIR /

COPY . .

# Install any needed packages specified in requirements/base.txt
RUN pip3 install --no-cache-dir -r requirements/base.txt

# Create instance dir
RUN mkdir -p /instance

# Create a empty env files
RUN touch /instance/prod.env
RUN touch /instance/dev.env

# Make port 5000 available to the world outside this container
EXPOSE 8000

# Run flask run when the container launches
CMD ["uvicorn", "--host", "0.0.0.0", "libreforms_fastapi.app:app"]
