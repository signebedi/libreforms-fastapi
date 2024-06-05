# libreforms-fastapi
FastAPI implementation of the libreForms spec

#### Getting Started

Follow the steps below to install the system on your computer. Please note, you need to install Python3.10 (or higher) and Python3.10-Venv through your package manager. If you plan to use MongoDB and a relational database, you will need to install these, too. See your distribution's specific instructions for these steps or [install using Docker](#running-in-docker) to get started.

```bash
cd /opt/libreforms-fastapi
python3 -m venv venv
source venv/bin/activate
pip install libreforms_fastapi
uvicorn libreforms_fastapi.app:app --reload # this will run the development server
```

You can also install manually using the git repository, which is recommended for development.

```bash
git clone https://github.com/signebedi/libreforms-fastapi.git
cd libreforms-fastapi
python3 -m venv venv
source venv/bin/activate
pip install -e .
uvicorn libreforms_fastapi.app:app --reload # this will run the development server
```

#### Installing Extras

If you want to also enable the use data science libraries and Excel exports, you should pip install using the `data` extras tag.

```bash
pip install libreforms_fastapi[data]
```

If you plan to use Postgres or MariaDB, then there are additional extras tags for those, too. 

```bash
pip install libreforms_fastapi[postres] # for Postgres
pip install libreforms_fastapi[mariadb] # for MariaDB
```

#### Running in Production

To run in production, you need to generate an app configuration and daemonize uvicorn. If this sounds too daunting, consider [running the Docker container](#running-in-docker). If you're not dissuaded, you can use the CLI. After pip installing the package, you can use the `libreformsctl` command to get the application running in production. Here's an example:

```bash
libreformsctl config production
libreformsctl uvicorn --environment production 
libreformsctl nginx production # Optional if you want a reverse proxy 
```

#### Troubleshooting Errors

You may sometimes run into inexplicable runtime errors. These often result from permission issues on the filesystem. When in doubt, try running the following command as root.

```bash
chown -R fastapi:fastapi /opt/libreforms_fastapi
```


#### Running in Docker

Follow the instructions below to run in docker. Creating a custom volume is optional but will give you control over the application configurations and, in the event you are using TinyDB and SQLite, you will also be able to access the database files.

```bash
git clone https://github.com/signebedi/libreforms-fastapi.git
cd libreforms-fastapi/
sudo docker build -t libreforms-fastapi . # Please note this can take several minutes
sudo docker volume create libreforms-volume # Create a volume for the instance directory
sudo docker run -d --name libreforms-instance -v libreforms-volume:/app/instance -p 8000:8000 libreforms-fastapi
```

You can create an admin account by running the following commands, being careful to replace `<environment>` with the appropriate environment (when in doubt, use `development`). Follow the instructions from the interface that pops up.

```bash
sudo docker exec -it libreforms-instance libreformsctl useradd --environment <environment> --site-admin
```

To stop your instance, you can run the following command.

```bash
docker kill libreforms-instance
```
