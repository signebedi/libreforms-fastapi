import re, os, yaml, shutil, difflib, json
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

# We externalize the custom yaml constructors to create an easier entrypoint 
# to manage both default custom constructors, as well as end-user logic, see
# https://github.com/signebedi/libreforms-fastapi/issues/150.
from libreforms_fastapi.utils.custom_yaml import (
    get_custom_loader,
)


# from libreforms_fastapi.utils.jinja_emails import (
#     test_email_config,
# )


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
    forgot_password: bool=False,
):


    class AdminUserModel(BaseModel):
        """
        This is the model used to validate new users created by admins. It requires a username, 
        groups list, and email field.
        """
        username: str = Field(...)
        groups: List = Field(...)
        email: EmailStr = Field(...)
    
        # Added an optional password field without a regex, which is used to constrain 
        # regular users. The idea is that admins might want to set users to use a temp
        # password that is easy to use and remember. It's better to give the choice to
        # admins, although it is better of course to use strong passwords and to give
        # users an idea of the password strength requirements that they need to which
        # they will eventually be expected to conform. Anyways, with a default of None,
        # will the `pattern` keyword work as expected? For more discussion, see
        # https://github.com/signebedi/libreforms-fastapi/issues/251
        password: None | SecretStr = Field(default=None)

        # This will be used to manage creating service accounts, see
        # https://github.com/signebedi/libreforms-fastapi/issues/305
        no_login: bool = Field(default=False)

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


    class ForgotPasswordUserModel(BaseModel):
        """
        This is the model used to update a user's password when they've forgotten it. It 
        requires a new_password and verify_new_password field.
        """
        new_password: SecretStr = Field(...)
        verify_new_password: SecretStr = Field(...)

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

    if forgot_password:
        return ForgotPasswordUserModel



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
    field_label: Text Input
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
    description: This is a section header description. It's meant to say enough, but maybe not too much. Eventually, you might consider providing an <a href="#">external link</a>
  number_input:
    input_type: number
    output_type: !int
    field_label: Number Input
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
    field_label: Email Input
    default: user@example.com
    required: false
    options: null
    description: This is an email field
  date_input:
    input_type: date
    output_type: !date
    field_label: Date Input
    default: 2024-01-01
    required: false
    options: null
    description: This is a date field
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
    description: This is a checkbox field
  radio_input:
    input_type: radio
    output_type: !str
    field_label: Radio Input
    options: 
      - Option1
      - Option2
    required: false
    default: Option1
    description: This is a radio field
  select_input:
    input_type: select
    output_type: !str
    field_label: Select Input
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
    field_label: Textarea Input
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
    field_label: File Input
    required: false
    default: null
    description: This is a file field
"""



def clean_extra_spaces(data, exclude_fields=['description', 'field_label']):
    if isinstance(data, str):
        # print("str", data)

        # Replace multiple spaces with a single space
        return re.sub(r'\s+', ' ', data).strip()
    elif isinstance(data, list):
        # print("list", data)

        return [clean_extra_spaces(item, exclude_fields) for item in data]
    elif isinstance(data, dict):
        # print("dict", data)
        return {
            key: clean_extra_spaces(value, exclude_fields) 
            if key not in exclude_fields else value
            for key, value in data.items()
        }
    return data

def load_form_config(
    config_path: None | str = None,
    initialize_full_loader: bool = False,
    doc_db = None,
    session = None,
    User = None,
    Group = None,
):
    """
    This is a quick abstraction to load the YAML form config with while
    parsing for custom constructors using the CustomFullLoader class.
    """


    # Load the yaml CustomFullLoader class
    CustomFullLoader = get_custom_loader(
        initialize_full_loader=initialize_full_loader,
        doc_db=doc_db,
        session=session,
        User=User,
        Group=Group,
    )

    # Load the default config as a fall back if no user-provided config exists
    default_config = yaml.load(EXAMPLE_FORM_CONFIG_YAML, Loader=CustomFullLoader)

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
                form_config = yaml.load(file, Loader=CustomFullLoader)

        except yaml.YAMLError as e:
            # raise Exception(f"Error parsing YAML file: {e}")
            # return default_config
            raise e
        except IOError as e:
            # raise Exception(f"Error reading file: {e}")
            return default_config
        except Exception as e:
            raise Exception(f"An unexpected error occurred: {e}")

    if not isinstance(form_config, dict):
        # raise Exception(f"The form config at {config_path} is not properly formatted")
        return default_config

    # return form_config

    # Clean extra spaces from the parsed YAML dictionary
    cleaned_config = clean_extra_spaces(form_config)

    return cleaned_config

def get_form_config_yaml(config_path=None, default=EXAMPLE_FORM_CONFIG_YAML):
    """
    Here we return the string representation of a yaml config.
    """

    if not config_path or not os.path.exists(config_path):
        return default

    elif os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                _config = file.read()
        except Exception as e:
            raise Exception(f"Failed to read the config file at {config_path}: {e}")

    return _config


def write_form_config_yaml(
    config_path, 
    form_config_str, 
    env,
    # validate=True, 
    timezone=ZoneInfo("America/New_York")
):
    """
    Here we write the string representation of the yaml form config.
    """

    # Load the yaml CustomFullLoader class
    CustomFullLoader = get_custom_loader()

    # Validate the YAML string
    # if validate:
    try:
        # Attempt to load the YAML string to check its validity
        parsed_config = yaml.load(form_config_str, Loader=CustomFullLoader)

        # I'm putting a placeholder here because we may with to add additional
        # validators down the road.

    except yaml.YAMLError as e:
        raise Exception(f"Failed to validate YAML format: {e}")


    # Clean extra spaces from the parsed YAML dictionary
    # cleaned_config = clean_extra_spaces(parsed_config)

    # Convert the cleaned config back to a YAML string
    # cleaned_form_config_str = yaml.dump(cleaned_config, sort_keys=False, Dumper=yaml.BaseDumper, default_flow_style=False)

    # Ensure the base directory exists
    basedir = os.path.dirname(config_path)
    if not os.path.exists(basedir):
        os.makedirs(basedir)

    # Create a backup of the current config
    config_backup_directory = Path(os.getcwd()) / 'instance' / f'{env}_form_config_backups'
    config_backup_directory.mkdir(parents=True, exist_ok=True)

    datetime_format = datetime.now(timezone).strftime("%Y%m%d%H%M%S")
    config_file_name = Path(config_path).name
    backup_file_name = f"{config_file_name}.{datetime_format}"
    backup_file_path = config_backup_directory / backup_file_name

    # Copy the existing config file to the backup location
    if os.path.exists(config_path):
        shutil.copy(config_path, backup_file_path)

    # Write the cleaned YAML string to the config file
    try:
        with open(config_path, 'w') as file:
            # file.write(cleaned_form_config_str)
            file.write(form_config_str)
    except Exception as e:
        raise Exception(f"Failed to write the form config to {config_path}: {e}")

    return True


def get_form_backups(config_path=None, env=None):

    current_config = get_form_config_yaml(config_path=config_path)

    if not env:
        env = ""

    # Define the backup directory path
    directory_path = os.path.join(os.getcwd(), 'instance', f'{env}_form_config_backups')
    os.makedirs(directory_path, exist_ok=True)

    # Get the list of files in the directory
    file_list = sorted(os.listdir(directory_path))[::-1]

    # Filter out directories, keeping only files
    file_list = [file for file in file_list if os.path.isfile(os.path.join(directory_path, file))]
    time_string_list = [file.split('.')[-1] for file in file_list]

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
    return list(zip(file_list, time_string_list, date_list, content_list, additions, subtractions))


def get_form_names(config_path=None, prefer_label=False):
    """
    Given a form config path, return a list of available forms, defaulting to the example 
    dictionary provided above. If `prefer_label` is True, then we will use form labels from
    the form `__config__` dict, if it's been set.
    """

    form_config = load_form_config(config_path=config_path)

    # Eww, this really messes things up. Its return type and core assumptions are different
    # from the base function... it maybe should have been a different function altogether...
    if prefer_label:
        form_names = {}
        for form_name, fields in form_config.items():
            _config = fields.get("__config__", {}) or {}
            visible_form_name: str = _config.get("form_label", form_name.replace("_", " ").title())
            form_names[form_name] = visible_form_name
        return form_names

    return form_config.keys()


def get_form_model(
    form_name: str, 
    config_path: None | str = None, 
    update: bool = False,
    initialize_full_loader: bool = True,
    doc_db = None,
    session = None,
    User = None,
    Group = None,
):
    """
    Generates a Pydantic model based on the form configuration.

    Args:
        form_name: The name of the form to generate the model for.
        config_path: Path to the configuration file.
        update: If True, all fields in the model will be optional.

    Returns:
        A dynamically created Pydantic model class.
    """

    form_config = load_form_config(
        config_path=config_path, 
        initialize_full_loader=initialize_full_loader,
        doc_db=doc_db,
        session=session,
        User=User,
        Group=Group, 
    )

    if form_name not in form_config:
        raise Exception(f"Form '{form_name}' not found in config")

    fields = form_config[form_name]
    field_definitions = {}

    # Initialize empty data structures
    user_fields = [] # https://github.com/signebedi/libreforms-fastapi/issues/281
    form_fields = {} # https://github.com/signebedi/libreforms-fastapi/issues/280

    class Config:
        arbitrary_types_allowed = True

    # Here we set defaults that will be overwritten by __config__ if it is passed,
    # see https://github.com/signebedi/libreforms-fastapi/issues/315.
    _config = fields.get("__config__", {}) or {}

    # Here we provide for event hooks, see discussion in
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    event_hooks: dict[str, list[dict[str, Any]]] = {
        x: _config.get(x, [])
        for x in [
            "on_create", 
            "on_delete", 
            "on_update", 
            "on_duplicate", 
            "on_read", 
            # "on_sign", 
            'on_approve', 
            'on_deny', 
            'on_pushback', 
            'on_confirm',
        ]}

    # Here, we determine whether and which default email templates ought to be sent, see
    # https://github.com/signebedi/libreforms-fastapi/issues/356. 
    disable_default_emails: bool | list = _config.get("disable_default_emails", False) 

    # Here, we determine whether to permit unregistered form submission and, if we do, which
    # method will be used, see https://github.com/signebedi/libreforms-fastapi/issues/357
    unregistered_submission_enabled: bool = _config.get("unregistered_submission_enabled", False) 

    unregistered_submission_permitted_methods = [
        'email_validated_create_user',
        'email_validated',
        # 'open', # This will be implemented by https://github.com/signebedi/libreforms-fastapi/issues/358
    ]
    unregistered_submission_method: str = _config.get("unregistered_submission_method", 'email_validated_create_user') 

    # Raise an error if the user has employed an impermissible unregistered form submission method
    assert unregistered_submission_method in unregistered_submission_permitted_methods, f"{unregistered_submission_method} not a permitted method for unregistered form submission. Must be one of: {unregistered_submission_permitted_methods}"

    # If set to True, users can be invited to submit this form via the UI, see
    # https://github.com/signebedi/libreforms-fastapi/issues/365. Only works if
    # unregistered_submission_enabled is True.
    invitations_enabled: bool = _config.get("invitations_enabled", False) 


    # Here we provide for approval stages, see discussion in
    # https://github.com/signebedi/libreforms-fastapi/issues/62
    form_stages: dict = _config.get("form_stages", {}) 
    # Presumably, we will want to add some validation step here to 
    # ensure the form_stages data structure conforms to expectations.

    for field_name, field_info in fields.items():
        
        # Continue if we encounter a __config__ field
        if field_name == "__config__":
            continue

        # Here, we tell the model factory to ignore header fields, see
        # https://github.com/signebedi/libreforms-fastapi/issues/204.
        if field_info.get("is_header", False):
            continue

        # If this field links to a user account, then append that field to the 
        # user_fields list, see https://github.com/signebedi/libreforms-fastapi/issues/281
        if field_info.get("links_to_user", False):
            user_fields.append(field_name)

        # If this field links to another form, then add that to the form_fields
        # data structure, see https://github.com/signebedi/libreforms-fastapi/issues/280
        _links_to_form = field_info.get("links_to_form", False)
        if isinstance(_links_to_form, str):
            form_fields[field_name] = _links_to_form


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

    # def get_additional_metadata(self):
    #     """
    #     Return additional metadata for the form based on the form config. Added based on
    #     the discussion in https://github.com/signebedi/libreforms-fastapi/issues/280
    #     and https://github.com/signebedi/libreforms-fastapi/issues/281.
    #     """

    #     return user_fields, form_fields

    # Attach the method to the dynamic model
    # dynamic_model.get_additional_metadata = get_additional_metadata

    # Attach event hook attr to the dynamic model, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/210
    dynamic_model.event_hooks = event_hooks
    dynamic_model.user_fields = user_fields
    dynamic_model.form_fields = form_fields

    # Attach the default email template poolice to the dynamic model, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/356
    dynamic_model.disable_default_emails = disable_default_emails


    # Attach the unregistered form submission rules to the dynamic model, see
    # https://github.com/signebedi/libreforms-fastapi/issues/357. invitations_enabled 
    # is defined by  https://github.com/signebedi/libreforms-fastapi/issues/365.
    dynamic_model.unregistered_submission_enabled = unregistered_submission_enabled
    dynamic_model.unregistered_submission_method = unregistered_submission_method
    dynamic_model.invitations_enabled = invitations_enabled

    # Attach event hook attr to the dynamic model, see 
    # https://github.com/signebedi/libreforms-fastapi/issues/62
    dynamic_model.form_stages = form_stages

    return dynamic_model

def get_form_html(
    form_name: str, 
    config_path: str | None = None, 
    current_document: dict | None = None,
    update:bool = False,
    duplicate:bool = False,
    initialize_full_loader: bool = True,
    doc_db = None,
    session = None,
    User = None,
    Group = None,
    context: dict = {},
) -> List[str]:
    """
    Generates a list of Bootstrap 5 styled HTML form fields based on the input config and form name,
    supporting default values.

    Params:
        current_document (dict): optional document containing the form's existing data. If passed, it will override
            the default content of the form config.
        
        ... Need to add the other params ...

    Returns: List[str] of HTML elements for the front-end
    """
    form_config = load_form_config(
        config_path=config_path, 
        initialize_full_loader=initialize_full_loader, 
        doc_db=doc_db,
        session=session,
        User=User,
        Group=Group, 
    )

    if form_name not in form_config:
        raise Exception(f"Form '{form_name}' not found in config")

    form_html = []

    _config = form_config[form_name].get("__config__", {}) or {}
    visible_form_name: str = _config.get("form_label", form_name.replace("_", " ").title())

    # Added from https://github.com/signebedi/libreforms-fastapi/issues/379
    conditional_display_logic=[]


    # Here we set the initial form HTML
    header_html = '''
                <fieldset class="form-check text-end">
    '''


    # Append the help link
    header_html += f'''
                    <a href="/ui/help" class="ms-0" style="color: inherit; text-decoration: none; padding-right: 6px;" title="Get help for this form" target="_blank">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-question-circle" viewBox="0 0 16 16">
                            <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                            <path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286m1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94"/>
                        </svg>
                    </a>
    '''

    # Append the share link
    invitations_enabled: bool = _config.get("invitations_enabled", False) 
    if invitations_enabled:
        header_html += f'''
                    <a href="/ui/form/invite_submission/{form_name}" class="ms-0" style="color: inherit; text-decoration: none; padding-right: 6px;" title="Invite someone to submit this form" target="_blank">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-send" viewBox="0 0 16 16">
                            <path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11ZM6.636 10.07l2.761 4.338L14.13 2.576zm6.787-8.201L1.591 6.602l4.339 2.76z"/>
                        </svg>
                    </a>
        '''


    header_html += f'''
                </fieldset>
    '''

    form_html.append(header_html)

    # Add the form header
    form_html.append(f'''
        <fieldset class="form-check">
            <h4>{visible_form_name}</h4>
        </fieldset>
    ''')

    # Structured this way so we can access the list position
    for list_index, (field_name, field_info) in enumerate(list(form_config[form_name].items())):
    
        # Continue if we encounter a __config__ field
        if field_name == "__config__":
            continue

        # Added from https://github.com/signebedi/libreforms-fastapi/issues/280
        links_to_form: str | None = field_info.get("links_to_form", False)

        # This will be used to push values to other fields, if set. Defaults to 
        # empty dict, see https://github.com/signebedi/libreforms-fastapi/issues/362.
        push_populate: dict = field_info.get("push_populate", {})
        push_populate_stringified = json.dumps(push_populate).replace('"', '&quot;')

        # Added from https://github.com/signebedi/libreforms-fastapi/issues/279
        form_display_fields: list = field_info.get("form_display_fields", ['__metadata__document_id'])

        if isinstance(links_to_form, str):
            if links_to_form not in form_config:
                raise ValueError(f"You are attempting to link the the {field_name} field of the {form_name} form to the {links_to_form} form, which does not exist.")

            if not all(item in form_config[links_to_form].keys() or item.startswith("__metadata__") for item in form_display_fields):
                raise ValueError(f"You have selected form_display_fields fields for the {field_name} field of the {links_to_form} form that are not in the form model. If you are trying to set metadata fields, be sure to prepend the field name with `__metadata__`. You have provided the following keys: {form_display_fields}.")

            # This will allow admins to pass read_all query params, see 
            # https://github.com/signebedi/libreforms-fastapi/issues/322.
            links_to_form_query_params: str = field_info.get("query_params", "")

        required: bool = field_info.get("required", False)


        # Added from https://github.com/signebedi/libreforms-fastapi/issues/379. Introduces conditional display logic.
        conditional_display_enabled: bool = field_info.get("conditional_display_enabled", False)
        conditional_display_field: str | None = field_info.get("conditional_display_field", None)
        conditional_display_value = field_info.get("conditional_display_value", None) # Might change default values for these in future

        # Initialize the conditional display class and attributes
        conditional_class = ""
        conditional_attrs = ""

        if conditional_display_enabled:
            assert conditional_display_field != None and conditional_display_value != None, f"If conditional_display_enabled is set to true, then both conditional_display_field and conditional_display_value must be set."
            
            # Determine initial visibility state
            initial_hidden = True  # Default to hidden
            
            # Check if we have the current document, viz. edits, and can determine initial state
            if current_document and conditional_display_field in current_document['data']:
                # Only show if condition is met
                if str(current_document['data'][conditional_display_field]) == str(conditional_display_value):
                    initial_hidden = False
            
            # Set CSS class for visibility
            conditional_class = "d-none" if initial_hidden else ""
            
            # Set data attributes for conditional logic
            conditional_attrs = f'data-conditional-field="{conditional_display_field}" data-conditional-value="{conditional_display_value}"'

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
            default = field_info.get("default","")

        if update or duplicate:
            default = ""

        # if not default: # "" has a False-like truth value
        placeholder = field_info.get("placeholder","")

        field_html = ""

        # Add tooltips
        tooltip = field_info.get("tooltip","")
        tooltip_text = f'''
        <sup><svg xmlns="http://www.w3.org/2000/svg" style="" width="12" height="12" fill="currentColor" class="bi bi-info-circle" viewBox="0 0 16 16" data-bs-toggle="tooltip" data-bs-placement="right" title="{tooltip}">
            <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
            <path d="m8.93 6.588-2.29.287-.082.38.45.083c.294.07.352.176.288.469l-.738 3.468c-.194.897.105 1.319.808 1.319.545 0 1.178-.252 1.465-.598l.088-.416c-.2.176-.492.246-.686.246-.275 0-.375-.193-.304-.533zM9 4.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0"/>
        </svg><sup>''' if len(tooltip) > 0 else ""

        visible_field_name = field_info.get("field_label", field_name.replace("_", " ").capitalize())
        description_text = field_info.get("description", "")
        description_id = f"{field_name}HelpInline"

        # Here, we tell the model factory to treat header fields differently, see
        # https://github.com/signebedi/libreforms-fastapi/issues/204.
        if field_info.get("is_header", False):

            if not visible_field_name or visible_field_name == "":

                field_html += f'''
                    <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: {'0' if list_index == 0 else '10'}px;">
                        <span id="{description_id}" class="form-text">{description_text} {tooltip_text}</span>
                    </fieldset>'''

            else:
                field_html += f'''
                    <fieldset class="form-check {conditional_class}" {conditional_attrs} style=" padding-top: 20px;">
                        <h5 aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{visible_field_name}</h5>
                        <span id="{description_id}" class="form-text">{description_text} {tooltip_text}</span>
                    </fieldset>'''

            # Do not try to parse any of the other logic for this element
            form_html.append(field_html)
            continue

        # See https://github.com/signebedi/libreforms-fastapi/issues/275. We make 
        # this logically separate to the following conditional statement because, 
        # if this is an edit, we want to be able to fall back to a secondary input type.
        if field_info['input_type'] == "hidden" and update:
            # If the field type is hidden but this is an update,
            # check for a secondary field type.
            secondary_input_type = field_info.get("secondary_input_type", "hidden")

            # And set the input type to that value. Defaults back to hidden... but, this can
            # be powerful when you want to be able to modify hidden fields on edits.
            field_info['input_type'] = secondary_input_type

        
        if field_info['input_type'] == "hidden":

            field_html += f'''
                <input type="hidden" id="{field_name}" name="{field_name}" {field_params} value="{default or ''}">'''

        elif field_info['input_type'] == "bool_switch":

            true_label = field_info.get('true_label', "true")
            false_label = field_info.get('false_label', "false")

            is_true = False if not default else True

            field_html += f'''
                <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
                    <div class="form-check form-switch bool-switch">
                        <input class="form-check-input bool-switch-checkbox" type="checkbox" name="{field_name}" id="{field_name}" {field_params} onchange="updateLabel(this, '{true_label}', '{false_label}')" {'checked' if is_true else ''} />
                        <label class="form-check-label bool-switch-label" for="{field_name}">{true_label if is_true else false_label}</label>
                    </div>
                </fieldset>'''

        # This value will always be static and linked to a context variable like request.user or config.SITE_NAME
        elif field_info['input_type'] == "immutable_context":

            is_hidden = field_info.get('is_hidden', False)

            if update:
                make_mutable = field_info.get('update_on_edit', False)
            elif duplicate:
                make_mutable = field_info.get('update_on_duplicate', True)
            else: 
                make_mutable = False

            mutable_attr = 'data-mutable="true"' if make_mutable else 'data-mutable="false"'

            # Start by pulling the context field and splitting on the period. These support 
            # user.<some_attr> and config.<some_attr>.
            _context_field = field_info.get('context_field', '')
            _expanded_context = _context_field.split('.')
            
            _value = context

            for layer in _expanded_context:
                if isinstance(_value, dict):
                    _value = _value.get(layer, "")

            if is_hidden:
                field_html += f'''
                    <input type="hidden" id="{field_name}" name="{field_name}" {field_params} value="{default or ''}">'''

            else:
                field_html += f'''
                    <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                        <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                        <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
                        <input type="text" readonly class="form-control" id="{field_name}" {mutable_attr}
                        name="{field_name}" {field_params} 
                        value="{_value}">
                    </fieldset>'''


        elif field_info['input_type'] in ['text', 'number', 'email', 'date']:
            field_html += f'''
                <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
                    <input type="{field_info["input_type"]}" class="form-control" id="{field_name}" name="{field_name}" {field_params}'''

            if placeholder and not default:
                field_html += f'''
                    placeholder="{placeholder or ''}"'''
            else:
                field_html += f'''
                    value="{default or ''}"'''
            field_html += f'''
                    {' required' if required else ''}>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] == "date":
            field_html += f'''
                <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
                    <input type="{field_info["input_type"]}" class="form-control" id="{field_name}" name="{field_name}" {field_params} 
                    value="{default or ''}"
                    {' required' if required else ''}>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] == 'textarea':
            field_html += f'''
                <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold"{' data-required="true"' if required else ''}>{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
                    <textarea class="form-control" id="{field_name}" name="{field_name}" {field_params} rows="4"'''
                    

            if placeholder and not default:
                field_html += f'''
                    placeholder="{placeholder or ''}" style="resize: vertical; max-height: 300px;"{' required' if required else ''}></textarea>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

            else:
                field_html += f'''
                    style="resize: vertical; max-height: 300px;"{' required' if required else ''}>{default or ''}</textarea>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] in ['checkbox', 'radio']:
            field_html += f'''
                <fieldset class="form-check{' required-checkbox-group' if required else ''} {conditional_class}" {conditional_attrs} style="padding-top: 20px;"{' data-required="true"' if required else ''}>
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>
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
                <fieldset class="form-check {conditional_class}" {conditional_attrs} style="padding-top: 20px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label set-bold">{visible_field_name}</label>
                    <span id="{description_id}" class="form-text"> {' Required.' if required else ''} {description_text} {tooltip_text}</span>'''
            if isinstance(links_to_form, str):
                field_html += f'''
                    <select class="form-control data-lookup" data-pushpopulate=\'{push_populate_stringified}\' onChange="getLookup('{links_to_form}', '{field_name}', this, '{links_to_form_query_params}');" id="{field_name}" name="{field_name}" data-link="{links_to_form}"{' required' if required else ''}>'''
            else:
                field_html += f'''
                    <select class="form-control" id="{field_name}" name="{field_name}"{' required' if required else ''}>'''
                # Below, we only render options if links_to_form has not been set. When links_to_form is set, then we render
                # options in the front end with a value=document_id and visible_field_name=form_display_fields, see
                # https://github.com/signebedi/libreforms-fastapi/issues/279 and https://github.com/signebedi/libreforms-fastapi/issues/280
                
                if placeholder:
                    field_html += f'<option value="">{placeholder}</option>'

                for option in field_info['options']:
                    selected = "selected" if default and (option == default or option in default) else ""
                    field_html += f'<option value="{option}" {selected}>{option}</option>'

            field_html += '''
                    </select>'''
            if isinstance(links_to_form, str):
                field_html += f'''
        			<div><div id="content_{field_name}" style="width: 100%; height: 300px; overflow-y: auto; max-height: 700px; resize: vertical; margin-top: 10px; border: 2px solid var(--bs-secondary);"></div></div>
                    <script>
                    window.onload = function() {{
                        generateLookup('{links_to_form}', '{field_name}', {form_display_fields}, '{links_to_form_query_params}');
                        // getLookup('{links_to_form}', '{field_name}', document.getElementById('{field_name}', '{links_to_form_query_params}'));
                    }}
                    </script>'''
            field_html += '''
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

            # Load the yaml CustomFullLoader class
            CustomFullLoader = get_custom_loader()
            
            # Remove leading and trailing double and single quotes
            v = v.strip('"\'')

            data = yaml.load(v, Loader=CustomFullLoader)
            if data is None:
                raise ValueError("No content found; possibly empty YAML.")
            return v
        except yaml.YAMLError as e:
            raise ValueError(f"The content is not valid YAML: {e}")
        except Exception as e:
            raise ValueError(f"An error occurred while parsing YAML: {e}")


class EmailConfigUpdateRequest(BaseModel):
    """Another quick model for managing admin update email config API calls"""
    content: str

    @validator('content')
    def validate_yaml(cls, v):

        try:
            # Remove leading and trailing double and single quotes
            v = v.strip('"\'')

            # _ = test_email_config(v, **kwargs)

            data = yaml.safe_load(v)

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


class RequestUnregisteredForm(BaseModel):
    """The model will validate an email request body when users try request an unregistered form submission"""
    email: EmailStr  = Field(...)