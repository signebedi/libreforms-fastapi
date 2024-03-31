import re, os
from datetime import datetime, date
from typing import List, Optional, Dict, Type, Any

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
    conint, 
    confloat,
)

from pydantic.functional_validators import field_validator, model_validator

from libreforms_fastapi.utils.config import get_config

_env = os.environ.get('ENVIRONMENT', 'development')
config = get_config(_env)

class ImproperUsernameFormat(Exception):
    """Raised when the username does not meet the regular expression defined in the app config"""
    pass

class ImproperPasswordFormat(Exception):
    """Raised when the password does not meet the regular expression defined in the app config"""
    pass

class PasswordMatchException(Exception):
    """Raised when the passwords provided do not match each other"""
    pass


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=100)
    # Added a little syntactic salt with the SecretStr, see https://stackoverflow.com/a/65277859/13301284
    password: SecretStr = Field(..., min_length=8)
    verify_password: SecretStr = Field(..., min_length=8)
    email: EmailStr
    opt_out: bool = False

    @validator('username')
    def username_pattern(cls, value):
        pattern = re.compile(config.USERNAME_REGEX)
        if not pattern.match(value):
            raise ValueError(config.USERNAME_HELPER_TEXT)
        return value.lower()

    @validator('password', 'verify_password', pre=True, each_item=False)
    def password_pattern(cls, value):
        # Since value is now of type SecretStr, we need to get its actual value
        password = value.get_secret_value() if isinstance(value, SecretStr) else value
        pattern = re.compile(config.PASSWORD_REGEX)
        if not pattern.match(password):
            raise ValueError(config.PASSWORD_HELPER_TEXT)
        return value

    @validator('verify_password', always=True)
    def passwords_match(cls, v, values, **kwargs):
        if 'password' in values and v.get_secret_value() != values['password'].get_secret_value():
            raise ValueError('Passwords do not match')
        return v

# Example form configuration with default values set
example_form_config = {
    "example_form": {
        "text_input": {
            "input_type": "text",
            "output_type": str,
            "field_name": "text_input",
            "default": "Default Text",
            "validators": {
                "_min_length": 25, # for number fields this will be treated as a min value
                "_max_length": 47, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "options": None,
            "description": "This is a text field",
        },
        "number_input": {
            "input_type": "number",
            "output_type": int,
            "field_name": "number_input",
            "default": 42,
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "options": None,
            "description": "This is a number field",
        },
        "email_input": {
            "input_type": "email",
            "output_type": str,
            "field_name": "email_input",
            "default": "user@example.com",
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "options": None,
            "description": "This is an email field",
        },
        "date_input": {
            "input_type": "date",
            "output_type": date,
            "field_name": "date_input",
            "default": "2024-01-01",
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "options": None,
            "description": "This is a date field",
        },
        "checkbox_input": {
            "input_type": "checkbox",
            "output_type": List[str],
            "field_name": "checkbox_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "default": ["Option1", "Option3"],
            "description": "This is a checkbox field",
        },
        "radio_input": {
            "input_type": "radio",
            "output_type": str,
            "field_name": "radio_input",
            "options": ["Option1", "Option2"],
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "default": "Option2",
            "description": "This is a radio field",
        },
        "select_input": {
            "input_type": "select",
            "output_type": str,
            "field_name": "select_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "default": "Option2",
            "description": "This is a select field",
        },
        "textarea_input": {
            "input_type": "textarea",
            "output_type": str,
            "field_name": "textarea_input",
            "default": "Default textarea content.",
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "options": None,
            "description": "This is a textarea field",
        },
        "file_input": {
            "input_type": "file",
            "output_type": bytes,
            "field_name": "file_input",
            "options": None,
            "validators": {
                "_min_length": None, # for number fields this will be treated as a min value
                "_max_length": None, # for number fields this will be treated as a max value
                "_regex": None,
            },
            "required": False,
            "default": None,  # File inputs can't have default values
            "description": "This is a file field",
        },
    },
}

def load_form_config(config_path=config.FORM_CONFIG_PATH):
    """This is a quick abstraction to load the json form config"""
    # Try to open config_path and if not existent or empty, use example config
    form_config = example_form_config  # Default to example_form_config

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as file:
                form_config = json.load(file)
        except json.JSONDecodeError:
            pass
            # print("Failed to load the JSON file. Falling back to the default configuration.")
    else:
        pass

    return form_config


def get_form_names(config_path=config.FORM_CONFIG_PATH):
    """
    Given a form config path, return a list of available forms, defaulting to the example 
    dictionary provided above.
    """

    form_config = load_form_config(config_path=config.FORM_CONFIG_PATH)
    return form_config.keys()


def get_form_config(form_name, config_path=config.FORM_CONFIG_PATH, update=False):
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

    validators_definitions = {}

    for field_name, field_info in fields.items():
        python_type = field_info["output_type"]
        default = None if update else field_info.get("default", ...)
        required = field_info.get("required", False)
        validators = field_info.get("validators", {})

        if python_type == str:
            min_length = validators.get("_min_length")
            max_length = validators.get("_max_length")
            python_type = constr(min_length=min_length, max_length=max_length) if min_length or max_length else python_type

        elif python_type == int:
            min_value = validators.get("_min_length")
            max_value = validators.get("_max_length")
            python_type = conint(ge=min_value, le=max_value)

        elif python_type == float:
            min_value = validators.get("_min_length")
            max_value = validators.get("_max_length")
            python_type = confloat(ge=min_value, le=max_value)

        if not required or update:
            python_type = Optional[python_type]

        field_definitions[field_name] = (python_type, default)

        # Setup regex validator if specified
        regex_pattern = validators.get("_regex")
        if regex_pattern:
            def create_validator(pattern):
                def validate_regex(cls, value, field: str = field_name):
                    if not re.match(pattern, value):
                        raise ValueError(f"{field} must match regex pattern: {pattern}")
                    return value
                return validate_regex

            validator_name = f"validate_{field_name}"
            validators_definitions[validator_name] = validator(field_name, allow_reuse=True)(create_validator(regex_pattern))

    # Create dynamic model
    dynamic_model = create_model(form_name, __config__=Config, **field_definitions)

    # Add validators to the model
    for name, func in validators_definitions.items():
        setattr(dynamic_model, name, func)

    return dynamic_model

def get_form_html(form_name:str, config_path:str=config.FORM_CONFIG_PATH, current_document:dict=None) -> List[str]:
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
        default = current_document['data'][field_name] if current_document and field_name in current_document['data'] else field_info.get("default")
        field_html = ""

        description_id = f"{field_name}HelpInline"

        if field_info['input_type'] in ['text', 'number', 'email', 'date']:
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{field_name.replace("_", " ").capitalize()}</label>
                    <span id="{description_id}" class="form-text">| {field_info["description"]}</span>
                    <input type="{field_info["input_type"]}" class="form-control" id="{field_name}" name="{field_name}" value="{default or ''}">
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] == 'textarea':
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{field_name.replace("_", " ").capitalize()}</label>
                    <span id="{description_id}" class="form-text">| {field_info["description"]}</span>
                    <textarea class="form-control" id="{field_name}" name="{field_name}" rows="4">{default or ''}</textarea>
                    <div class="valid-feedback"></div>
                    <div class="invalid-feedback"></div>
                </fieldset>'''

        elif field_info['input_type'] in ['checkbox', 'radio']:
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{field_name.replace("_", " ").capitalize()}</label>
                    <span id="{description_id}" class="form-text">| {field_info["description"]}</span>
            '''
            for option in field_info['options']:
                checked = "checked" if default and (option == default or option in default) else ""
                field_html += f'''
                    <div class="form-check {field_info["input_type"]}-form-check">
                        <input class="form-check-input" type="{field_info["input_type"]}" id="{option}" name="{field_name}" value="{option}" {checked}>
                        <label class="form-check-label" for="{option}">{option}</label>
                    </div>
                '''
            field_html += f'''
                </fieldset>
            '''

        elif field_info['input_type'] == 'select':
            field_html += f'''
                <fieldset class="form-check" style="padding-top: 10px;">
                    <label aria-labelledby="{description_id}" for="{field_name}" class="form-check-label">{field_name.replace("_", " ").capitalize()}</label>
                    <span id="{description_id}" class="form-text">| {field_info["description"]}</span>
                    <select class="form-control" id="{field_name}" name="{field_name}">'''
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
    """A quick and dirty pydantic model for help request data"""
    subject: str
    category: str
    message: str