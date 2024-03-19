# libreforms-fastapi
FastAPI implementation of the libreForms spec

#### Installation

Follow the steps below to install the system on your computer. Please note, you need to install MongoDB, Python3, and Python3-Venv through your package manager. See your distribution's specific instructions for these steps or [install using Docker](#running-in-docker).

```bash
git clone https://github.com/signebedi/libreforms-fastapi.git
cd libreforms-fastapi
python3 -m venv venv
source venv/bin/activate
pip install -e .
uvicorn libreforms_fastapi.app:app --reload # this will run the development server
```

#### Running in Production

To run in production, you need to generate an app configuration and daemonize uvicorn. If this sounds too daunting, consider [runnning the Docker container](#running-in-docker). If you're not dissuaded, you can use the CLI. After pip installing the package, you can use the `libreformsctl` command to get the application running in production. Here's an example:

```bash
libreformsctl config production
libreformsctl uvicorn production 
libreformsctl nginx production # Optional if you want a reverse proxy 
```

#### Running in Docker

```bash
git clone https://github.com/signebedi/libreforms-fastapi.git
cd libreforms-fastapi/
sudo docker build -t libreforms-fastapi . # Please note this can take several minutes
sudo docker run -d -p 8000:8000 libreforms-fastapi
```

