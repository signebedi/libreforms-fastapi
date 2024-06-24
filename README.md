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

#### Configuring Your First Form

The form configuration file uses YAML to define the structure and behavior of form fields. Each form is represented as a key under the root, and each field within a form is defined with various parameters specifying its type, label, default values, validation rules, and other attributes. Here’s an example form configuration in YAML:

```yaml
example_form:

    text_input:
        input_type: text
        output_type: !str
        field_label: Text Input
        default: Default Text
        validators:
            min_length: 1
            max_length: 200
        required: true
        description: A text input field

    number_input:
        input_type: number
        output_type: !int
        field_label: Number Input
        default: 42
        validators:
            ge: 0
            le: 10000
        required: false
        description: A number input field

    checkbox_input:
        input_type: checkbox
        output_type: !list
        field_label: Checkbox Input
        options:
            - Option1
            - Option2
            - Option3
        required: true
        default:
            - Option1
            - Option3
        description: A checkbox input field

another_form:

    section_header:
        is_header: true
        field_label: Section Header
        description: This is an example of a section header. You can put as much text here as you need to guide users in the submission of the form in the UI.

    select_input:
        input_type: select
        output_type: !str
        field_label: Select a user
        options: !all_usernames_by_group_default
        required: true
        description: A select input field, illustrating how to use data retrieval tags.
```

##### Field Parameters

Each field configuration includes several key parameters:

- input_type: Specifies the type of input control to use, such as text, number, email, checkbox, radio, select, etc.
- output_type: Indicates the data type for the field’s output, using custom YAML tags like !str, !int, !list, etc.
- field_label: A user-friendly label for the field, which will be displayed on the form.
- default: The default value to populate the field when the form loads.
- required: A boolean indicating whether the field must be filled out for form submission. 
- options: Available choices for fields like select, radio, and checkbox inputs. This can be a static list or dynamically populated using special YAML tags. 
- description: A brief description of the field, providing context or instructions for users. 
- validators: A set of validation rules for the field, defining constraints like minimum and maximum length, patterns, and numerical limits. These are drawn from pydantic [Fields](https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.Field).

##### Adding Headers

Headers are special fields in the YAML configuration used to group related fields or provide context within the form. Unlike standard fields, headers do not capture user input but serve to organize the form layout and help guide users. Headers support fewer parameters compared to input fields since they primarily focus on labeling and organizing.

- is_header: Indicates that the field is a header. This is typically set to true.
- field_label: The label or title of the header. It acts as a section title or heading in the form.
- description: A brief description or subtitle for the header, providing additional context or information about the section.

##### Using YAML Tags
The custom loader supports specific YAML tags to define output types and dynamically retrieve data for select, radio, and checkbox fields in forms. These include output_type tags indicating the expected type of a field's output. 

- !int: Integer value.
- !str: String value.
- !date: Date value.
- !datetime: Datetime value.
- !time: Time value.
- !timedelta: Time delta value.
- !list: List value.
- !tuple: Tuple value.
- !bytes: Byte value.

These also include data retrieval tags that dynamically yield data for form fields such as select, radio, and checkbox inputs.

- !all_usernames: List of all usernames.
- !all_usernames_by_group_<group_name>: List of usernames for a specific group (replace <group_name> with the actual group name).
- !all_groups: List of all group names.
- !all_submissions_<form_name>: List of form IDs for a specific form type (replace <form_name> with the actual form name).
