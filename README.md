# libreforms-fastapi
FastAPI implementation of the libreForms spec

#### Installation

Follow the steps below to install the system on your computer. Please note, you need to install MongoDB, Python3, and Python3-Venv through your package manager. See your distribution's specific instructions for these steps or [install using Docker](#running-in-docker).

```bash
cd /opt
git clone https://github.com/signebedi/libreforms-fastapi.git
cd libreforms-fastapi
python3 -m venv venv
source venv/bin/activate
pip install -r requirements/base.txt
uvicorn app:app --reload # this will run the development server
```

This application runs out of `/opt`. At this time, it's hard-coded to that working directory but future implementations might make the application installable and general with respect to the installation directory, [see this issue](https://github.com/signebedi/libreforms-fastapi/issues/13). Stay tuned for more.

#### Running in Production

To run in production, you need to set up a unvicorn daemon, see [this issue](https://github.com/signebedi/libreforms-fastapi/issues/3). We are preparing a CLI to configure and set up a persistent runtime using systemd, [see this issue](https://github.com/signebedi/libreforms-fastapi/issues/10). Stay tuned for more.

#### Running in Docker

We are working on a docker image, [see this issue](https://github.com/signebedi/libreforms-fastapi/issues/12) for more details. Stay tuned for more.


