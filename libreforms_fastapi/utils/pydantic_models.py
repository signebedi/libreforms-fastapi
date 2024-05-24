import re, os, yaml, shutil, difflib
from pathlib import Path
from zoneinfo import ZoneInfo
from datetime import datetime, date, time, timedelta
from typing import List, Optional, Dict, Type, Any, Annotated

from pydantic import (
    BaseModel,
    Field,
    ValidationError,
    validator,
    create_model,
    ConfigDict,
    EmailStr,
    constr,
    SecretStr,
)

from pydantic.functional_validators import field_validator, model_validator

class ImproperUsernameFormat(Exception):
    """Raised when the username does not meet the regular expression defined in the app config"""
    pass

class ImproperPasswordFormat(Exception):
    """Raised when the password does not meet the regular expression defined in the app config"""
    pass

class PasswordMatchException(Exception):
    """Raised when the passwords provided do not match each other"""
    pass

def get_user_model(
    username_regex: str,
    username_helper_text: str,
    password_regex: str,
    password_helper_text: str,
    admin: bool=False,
    password_change: bool=False,
):


    class AdminUserModel(BaseModel):
        """
        This is the model used to validate new users created by admins. It requires a username, 
        groups list, and email field.
        """
        username: str = Field(...)
        groups: List = Field(...)
        email: EmailStr = Field(...)

        # @validator('username')
        # def username_pattern(cls, value):
        #     pattern = re.compile(username_regex)
        #     if not pattern.match(value):
        #         raise ValueError(username_helper_text)
        #     return value.lower()

    if admin:
        return AdminUserModel

    class PasswordChangeUserModel(BaseModel):
        """
        This is the model used to update a user's password. It requires an old_password, 
        new_password, and verify_new_password field.
        """
        old_password: SecretStr = Field(...)
        new_password: SecretStr = Field(...)
        verify_new_password: SecretStr = Field(...)


        @validator('new_password', always=True)
        def passwords_changed(cls, v, values, **kwargs):
            if 'old_password' in values and v.get_secret_value() == values['old_password'].get_secret_value():
                raise ValueError('New password cannot be the same as the previous password')
            return v

        @validator('verify_new_password', always=True)
        def passwords_match(cls, v, values, **kwargs):
            if 'new_password' in values and v.get_secret_value() != values['new_password'].get_secret_value():
                raise ValueError('Passwords do not match')
            return v


        @validator('new_password', 'verify_new_password', pre=True, each_item=False)
        def password_pattern(cls, value):
            # Since value is now of type SecretStr, we need to get its actual value
            password = value.get_secret_value() if isinstance(value, SecretStr) else value
            pattern = re.compile(password_regex)
            if not pattern.match(password):
                raise ValueError(password_helper_text)
            return value

    if password_change:
        return PasswordChangeUserModel


    class UserModel(BaseModel):
        """
        This is the model used to validate new user requests. It requires a username, 
        password, verify_password, and email field, and a bool field for the user's 
        opt-out status for detailed usage tracking.
        """
        username: str = Field(...)
        # Added a little syntactic salt with the SecretStr, see https://stackoverflow.com/a/65277859/13301284
        password: SecretStr = Field(...)
        verify_password: SecretStr = Field(...)
        email: EmailStr = Field(...)
        opt_out: bool = Field(False)

        @validator('username')
        def username_pattern(cls, value):
            pattern = re.compile(username_regex)
            if not pattern.match(value):
                raise ValueError(username_helper_text)
            return value.lower()


        @validator('verify_password', always=True)
        def passwords_match(cls, v, values, **kwargs):
            if 'password' in values and v.get_secret_value() != values['password'].get_secret_value():
                raise ValueError('Passwords do not match')
            return v

        @validator('password', 'verify_password', pre=True, each_item=False)
        def password_pattern(cls, value):
            # Since value is now of type SecretStr, we need to get its actual value
            password = value.get_secret_value() if isinstance(value, SecretStr) else value
            pattern = re.compile(password_regex)
            if not pattern.match(password):
                raise ValueError(password_helper_text)
            return value

    return UserModel


# The options in the `validator` field are drawn from: https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.Field
# A note about min-length: https://stackoverflow.com/a/10294291/13301284. Better to set a pattern and set required.
EXAMPLE_FORM_CONFIG_YAML = """
example_form:
  text_input:
    input_type: text
    output_type: !str
    field_name: text_input
    default: Default Text
    validators:
      min_length: 1
      max_length: 200
      pattern: '^[\\s\\S]*$'
    required: true
    options: null
    description: This is a text field
  section_header:
    is_header: true
    field_label: This is a section header!
    description: This is a section header
  number_input:
    input_type: number
    output_type: !int
    field_name: number_input
    default: 42
    validators:
      ge: 0
      le: 10000
    required: false
    options: null
    description: This is a number field
  email_input:
    input_type: email
    output_type: !str
    field_name: email_input
    default: user@example.com
    required: false
    options: null
    description: This is an email field
  date_input:
    input_type: date
    output_type: !date
    field_name: date_input
    default: 2024-01-01
    required: false
    options: null
    description: This is a date field
  checkbox_input:
    input_type: checkbox
    output_type: !list
    field_name: checkbox_input
    options: 
      - Option1
      - Option2
      - Option3
    required: true
    default: 
      - Option1
      - Option3
    description: This is a checkbox field
  radio_input:
    input_type: radio
    output_type: !str
    field_name: radio_input
    options: 
      - Option1
      - Option2
    required: false
    default: Option1
    description: This is a radio field
  select_input:
    input_type: select
    output_type: !str
    field_name: select_input
    options:
      - Option1
      - Option2
      - Option3
    required: false
    default: Option2
    description: This is a select field
  textarea_input:
    input_type: textarea
    output_type: !str
    field_name: textarea_input
    default: Default textarea content.
    validators:
      min_length: 0
      max_length: 200
      pattern: '^[\\s\\S]*$'
    required: false
    options: null
    description: This is a textarea field
  file_input:
    input_type: file
    output_type: !bytes
    field_name: file_input
    required: false
    default: null
    description: This is a file field
"""

def get_yaml_constructors(**kwargs):
    """
    This factory is used to build a dictionary of built-in and custom constructors that
    will be used in building the internal, dictionary representation of the form config.
    """

    # Default constructors for returning Python types
    def type_constructor_int(loader, node):
        return int

    def type_constructor_str(loader, node):
        return str

    def type_constructor_date(loader, node):
        return date

    def type_constructor_datetime(loader, node):
        return datetime

    def type_constructor_time(loader, node):
        return time

    def type_constructor_timedelta(loader, node):
        return timedelta

    def type_constructor_list(loader, node):
        return list

    def type_constructor_tuple(loader, node):
        return tuple

    def type_constructor_bytes(loader, node):
        return bytes

    # We create a constructor mapping that we'll use later to 
    # register the constructors.
    constructor_mapping = {
        '!int': type_constructor_int,
        '!str': type_constructor_str,
        '!date': type_constructor_date,
        '!type_datetime': type_constructor_datetime,
        '!type_time': type_constructor_time,
        '!type_timedelta': type_constructor_time,
        '!list': type_constructor_list,
        '!tuple': type_constructor_list,
        '!bytes': type_constructor_bytes,
        **kwargs,
    }
    return constructor_mapping

# Register the type constructors
for key, value in get_yaml_constructors().items():
    yaml.add_constructor(key, value)

def load_form_config(config_path=None):
    """
    This is a quick abstraction to load the YAML form config with 
    while parsing for the output_type.
    """
    default_config = yaml.load(EXAMPLE_FORM_CONFIG_YAML, Loader=yaml.FullLoader)

    if not config_path:
        return default_config

    elif not os.path.exists(config_path):

        basedir = os.path.dirname(config_path)
        if not os.path.exists(basedir):
            os.makedirs(basedir)

        with open(config_path, 'w') as file:
            file.write(EXAMPLE_FORM_CONFIG_YAML)

        return default_config

    elif os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                form_config = yaml.load(file, Loader=yaml.FullLoader)

        except yaml.YAMLError as e:
            # raise Exception(f"Error parsing YAML file: {e}")
            return default_config
        except IOError as e:
            # raise Exception(f"Error reading file: {e}")
            return default_config
        except Exception as e:
            raise Exception(f"An unexpected error occurred: {e}")


    if not isinstance(form_config, dict):
        # raise Exception(f"The form config at {config_path} is not properly formatted")
        return default_config

    return form_config

def get_form_config_yaml(config_path=None):
    """
    Here we return the string representation of the yaml form config.
    """

    if not config_path or not os.path.exists(config_path):
        return EXAMPLE_FORM_CONFIG_YAML

    elif os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                form_config = file.read()
        except Exception as e:
            raise Exception(f"Failed to read the form config file at {config_path}: {e}")

    return form_config


def write_form_config_yaml(config_path, form_config_str, validate=True, timezone=ZoneInfo("America/New_York")):
    """
    Here we write the string representation of the yaml form config.
    """

    # Validate the YAML string
    if validate:
        try:
            # Attempt to load the YAML string to check its validity
            parsed_config = yaml.load(form_config_str, Loader=yaml.FullLoader)

            # I'm putting a placeholder here because we may with to add additional
            # validators down the road.

        except yaml.YAMLError as e:
            raise Exception(f"Failed to validate YAML format: {e}")

    basedir = os.path.dirname(config_path)
    if not os.path.exists(basedir):
        os.makedirs(basedir)

    config_backup_directory = Path(os.getcwd()) / 'instance' / 'form_config_backups'
    config_backup_directory.mkdir(parents=True, exist_ok=True)

    datetime_format = datetime.now(timezone).strftime("%Y%m%d%H%M%S")

    # Separate filename from its directory
    config_file_name = Path(config_path).name

    # Construct the backup filename
    backup_file_name = f"{config_file_name}.{datetime_format}"

    # Construct the full backup file path
    backup_file_path = config_backup_directory / backup_file_name

    # print("\n\n\n\n", config_backup_directory, "\n", backup_file_path)
    shutil.copy(config_path, backup_file_path)


    try:
        with open(config_path, 'w') as file:
            file.write(form_config_str)
    except Exception as e:
        raise Exception(f"Failed to write the form config to {config_path}: {e}")

    return True

def get_form_backups(config_path=None):

    current_config = get_form_config_yaml(config_path=config_path)

    # Define the backup directory path
    directory_path = os.path.join(os.getcwd(), 'instance', 'form_config_backups')
    os.makedirs(directory_path, exist_ok=True)

    # Get the list of files in the directory
    file_list = os.listdir(directory_path)

    # Filter out directories, keeping only files
    file_list = [file for file in file_list if os.path.isfile(os.path.join(directory_path, file))]
    time_string_list = [file.split('.')[-1] for file in file_list if os.path.isfile(os.path.join(directory_path, file))]

    # print(file_list)

    # Parsing the string into a datetime object
    date_list = [datetime.strptime(time_string, "%Y%m%d%H%M%S") for time_string in time_string_list]

    # print(date_list)

    # We also add the content 
    content_list = []
    for file in file_list:
        with open (os.path.join(directory_path, file), 'r') as f:
            content_list.append(f.read())

    # Add the diff count, using the current config as the baseline
    current_config_lines = current_config.split('\n')

    additions = []
    subtractions = []

    for _conf in content_list:
        old_config_lines = _conf.split('\n')

        # Use difflib to compare the configs and get the differences
        _diff = difflib.unified_diff(current_config_lines, old_config_lines)

        # Initialize counters for additions and subtractions
        additions_count = 0
        subtractions_count = 0

        # Iterate through the diff and count additions and subtractions
        diff_list = list(_diff)
        for line in diff_list:
            if line.startswith('+') and not line.startswith('+++'):
                additions_count += 1
            elif line.startswith('-') and not line.startswith('---'):
                subtractions_count += 1

        # Store the counts
        additions.append(additions_count)
        subtractions.append(subtractions_count)

    # Zip up and return the results
    return list(zip(file_list, time_string_list, date_list, content_list, additions, subtractions))[::-1]


def get_form_names(config_path=None):
    """
    Given a form config path, return a list of available forms, defaulting to the example 
    dictionary provided above.
    """

    form_config = load_form_config(config_path=config_path)
    return form_config.keys()


def get_form_model(form_name, config_path=None, update=False):
    """
    Generates a Pydantic model based on the form configuration.

    Args:
        form_name: The name of the form to generate the model for.
        config_path: Path to the configuration file.
        update: If True, all fields in the model will be optional.

    Returns:
        A dynamically created Pydantic model class.
    """
    form_config = load_form_config(config_path=config_path)

    if form_name not in form_config:
        raise Exception(f"Form '{form_name}' not found in config")

    fields = form_config[form_name]
    field_definitions = {}

    class Config:
        arbitrary_types_allowed = True

    for field_name, field_info in fields.items():
        
        # Here, we tell the model factory to ignore header fields, see
        # https://github.com/signebedi/libreforms-fastapi/issues/204.
        if field_info.get("is_header", False):
            continue

        python_type = field_info["output_type"]
        default_value = None if update else field_info.get("default", ...)
        required = field_info.get("required", False)
        description = field_info.get("description", False)

        validators: dict = field_info.get("validators", {})
        if not isinstance(validators, dict):
            raise ValueError(f"Form config validators option is malformed. Form name: {form_name}. Field name: {field_name}.")

        if "min_length" in validators.keys() and validators["min_length"] > 0 and not required:
            raise Exception(f"You've set a minlength without making the field required, which will just cause validation errors in the backend. Have you considered either making the field required or adding a regex 'pattern' instead? See the params we accept at: https://docs.pydantic.dev/latest/api/fields/#pydantic.fields.Field. See an explanation of the problem at: https://stackoverflow.com/a/10294291/13301284. Field name: {field_name}. Form name: {form_name}.")

        field_params = {}
        field_params["description"] = description
        field_params["repr"] = True # Show this field in the __repr__
        field_params = {**field_params, **validators}
        
        if not required or update:
            python_type = Optional[python_type]
            field = Field(default=default_value, **field_params)
        else:
            field = Field(default=..., **field_params)
        
        field_definitions[field_name] = (python_type, field)

    # Create dynamic model
    dynamic_model = create_model(form_name, __config__=Config, **field_definitions)

    return dynamic_model

def get_form_html(
    form_name: str, 
    config_path: str | None = None, 
    current_document: dict | None = None,
    update=False,
) -> List[str]:
    """
    Generates a list of Bootstrap 5 styled HTML form fields based on the input config and form name,
    supporting default values.

    Params:
        current_document (dict): optional document containing the form's existing data. If passed, it will override
            the default content of the form config.

    Returns: List[str] of HTML elements for the front-end
    """
    form_config = load_form_config(config_path=config_path)

    if form_name not in form_config:
        raise Exception(f"Form '{form_name}' not found in config")

    form_html = []
    
    for field_name, field_info in form_config[form_name].items():
    


        required: bool = field_info.get("required", False)

        validators: dict = field_info.get("validators", {})
        if not isinstance(validators, dict):
            raise ValueError(f"Form config validators option is malformed. Form name: {form_name}. Field name: {field_name}.")


        # Likely common validators
        field_params = f""
        if "gt" in validators:
            field_params += f'min=\"{validators["gt"]-1}\" '
        if "ge" in validators:
            field_params += f'min=\"{validators["ge"]}\" '
        if "lt" in validators:
            field_params += f'max=\"{validators["lt"]+1}\" '
        if "le" in validators:
            field_params += f'max=\"{validators["le"]}\" '
        if "max_length" in validators:
            field_params += f'maxlength=\"{validators["max_length"]}\" '
        if "min_length" in validators:
            field_params += f'minlength=\"{validators["min_length"]}\" '
        if "pattern" in validators:
            field_params += f'pattern=\"{validators["pattern"]}\" '

        if current_document and field_name in current_document['data']:
            default = current_document['data'][field_name] 
        else:
            default = field_info.get("default")

        if update:
            default = ""

        field_html = ""


        visible_field_name = field_info.get("field_label", field_name.replace("_", " ").capitalize())
        description_text = field_info.get("description", "")
        description_id = f"{field_name}HelpInline"

        # Here, we tell the model factory to treat header fields differently, see
        # https://github.com/signebedi/libreforms-fastapi/issues/204.
        if field_info.get("is_header", False):

            if not visible_field_name:
                visible_field_name = ""
                
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">

                    <h4 aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}</h4>
                    <span id="{description_id}" class="form-text">{description_text}</span>

                </fieldset>'''


        elif field_info['input_type'] in ['text', 'number', 'email', 'date']:
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text">|{' Required.' if required else ''} {description_text}</span>
                    <input type="{field_info["input_type"]}" class="form-control" id="{field_name}" name="{field_name}" {field_params} value="{default or ''}"{' required' if required else ''}>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] == 'textarea':
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}{' data-required="true"' if required else ''}</label>
                    <span id="{description_id}" class="form-text">|{' Required.' if required else ''} {description_text}</span>
                    <textarea class="form-control" id="{field_name}" name="{field_name}" {field_params} rows="4" style="resize: vertical; max-height: 300px;"{' required' if required else ''}>{default or ''}</textarea>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] in ['checkbox', 'radio']:
            field_html += f'''
                <fieldset class="form-check{' required-checkbox-group' if required else ''}" style="padding-top: 10px;"{' data-required="true"' if required else ''}>
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text">|{' Required.' if required else ''} {description_text}</span>
            '''
            for option in field_info['options']:
                checked = "checked" if default and (option == default or option in default) else ""
                field_html += f'''
                    <div class="form-check {field_info["input_type"]}-form-check">
                        <input class="form-check-input" type="{field_info["input_type"]}" id="{field_name}_{option}" name="{field_name}" value="{option}" {checked}>
                        <label class="form-check-label" for="{field_name}_{option}">{option}</label>
                    </div>
                '''
            field_html += f'''
                </fieldset>
            '''

        elif field_info['input_type'] == 'select':
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text">|{' Required.' if required else ''} {description_text}</span>
                    <select class="form-control" id="{field_name}" name="{field_name}"{' required' if required else ''}>'''
            for option in field_info['options']:
                selected = "selected" if default and (option == default or option in default) else ""
                field_html += f'<option value="{option}" {selected}>{option}</option>'
            field_html += '''
                    </select>
                </fieldset>'''

        # Skipping file input for now becase it usually doesn't have a default value and handling 
        # might be different based on requirements

        if field_html:
            form_html.append(field_html)
    
    return form_html


class HelpRequest(BaseModel):
    """A quick pydantic model for help request data"""
    subject: str
    category: str
    message: str

class DocsEditRequest(BaseModel):
    """Another quick model for managing admin edit docs API calls"""
    content: str


class FormConfigUpdateRequest(BaseModel):
    """Another quick model for managing admin update form config API calls"""
    content: str

    @validator('content')
    def validate_yaml(cls, v):
        try:
            
            # Remove leading and trailing double and single quotes
            v = v.strip('"\'')

            data = yaml.load(v, Loader=yaml.FullLoader)
            if data is None:
                raise ValueError("No content found; possibly empty YAML.")
            return v
        except yaml.YAMLError as e:
            raise ValueError(f"The content is not valid YAML: {e}")
        except Exception as e:
            raise ValueError(f"An error occurred while parsing YAML: {e}")


class GroupModel(BaseModel):
    """This model will be used for validating change to Groups through the admin API"""
    # id: int = Field(None)
    name: str = Field(...)
    permissions: List[str] = Field(...)

    @validator('permissions', each_item=True)
    def check_colon_in_permission(cls, v):
        if ':' not in v:
            raise ValueError('Each permission must contain a ":" character')
        return v

class RelationshipTypeModel(BaseModel):
    """This model will be used for validating Relationship Types through the admin API"""
    name: str = Field(...)
    reciprocal_name: str = Field(None)
    description: str = Field(...)
    exclusive_relationship: bool = Field(...)


class UserRelationshipModel(BaseModel):
    """This model will be used for validating User Relationship through the admin API"""
    user_id: int = Field(...)
    related_user_id: int = Field(...)
    relationship_type_id: int = Field(...)

class SiteConfig(BaseModel):
    """This model will be used for validating site config changes through the admin API"""
    content: dict = Field(...)


