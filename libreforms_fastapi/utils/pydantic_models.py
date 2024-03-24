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
)

from pydantic.functional_validators import field_validator, model_validator

from libreforms_fastapi.utils.config import yield_config

_env = os.environ.get('ENVIRONMENT', 'development')
config = yield_config(_env)

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
    password: str = Field(..., min_length=8)
    verify_password: str = Field(..., min_length=8)
    email: EmailStr
    opt_out: bool = False

    @field_validator('username')
    def username_pattern(cls, value):
        pattern = re.compile(config.USERNAME_REGEX)
        if not pattern.match(value):
            raise ValueError(config.USERNAME_HELPER_TEXT)
        return value.lower()

    @field_validator('password')
    def password_pattern(cls, value):
        pattern = re.compile(config.PASSWORD_REGEX)
        if not pattern.match(value):
            raise ValueError(config.PASSWORD_HELPER_TEXT)
        return value

    # Custom method to validate that the two passwords match
    @model_validator(mode='before')
    def passwords_match(cls, data: Any) -> Any:
        if data.get('password') != data.get('verify_password'):
            raise ValueError('Passwords do not match')
        return data

# Example form configuration with default values set
example_form_config = {
    "example_form": {
        "text_input": {
            "input_type": "text",
            "output_type": str,
            "field_name": "text_input",
            "default": "Default Text",
            "validators": [],
            "required": False,
            "options": None
        },
        "number_input": {
            "input_type": "number",
            "output_type": int,
            "field_name": "number_input",
            "default": 42,
            "validators": [],
            "required": False,
            "options": None
        },
        "email_input": {
            "input_type": "email",
            "output_type": str,
            "field_name": "email_input",
            "default": "user@example.com",
            "validators": [],
            "required": False,
            "options": None
        },
        "date_input": {
            "input_type": "date",
            "output_type": date,
            "field_name": "date_input",
            "default": "2024-01-01",
            "validators": [],
            "required": False,
            "options": None
        },
        "checkbox_input": {
            "input_type": "checkbox",
            "output_type": List[str],
            "field_name": "checkbox_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": [],
            "required": False,
            "default": ["Option1", "Option3"]
        },
        "radio_input": {
            "input_type": "radio",
            "output_type": str,
            "field_name": "radio_input",
            "options": ["Option1", "Option2"],
            "validators": [],
            "required": False,
            "default": "Option2"
        },
        "select_input": {
            "input_type": "select",
            "output_type": str,
            "field_name": "select_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": [],
            "required": False,
            "default": "Option2"
        },
        "textarea_input": {
            "input_type": "textarea",
            "output_type": str,
            "field_name": "textarea_input",
            "default": "Default textarea content.",
            "validators": [],
            "required": False,
            "options": None
        },
        "file_input": {
            "input_type": "file",
            "output_type": bytes,
            "field_name": "file_input",
            "options": None,
            "validators": [],
            "required": False,
            "default": None  # File inputs can't have default values
        },
    },
}

def generate_html_form(fields: dict) -> List[str]:
    """
    Generates a list of HTML form fields based on the input dictionary, supporting default values.

    Params
        Fields (dict), required: Dictionary of field data

    Returns: List[str] of HTML elements for front-end
    """
    form_html = []
    
    for field_name, field_info in fields.items():
        default = field_info.get("default")
        if field_info['input_type'] in ['text', 'number', 'email', 'date']:
            field_html = f'<label for="{field_name}">{field_name.capitalize()}:</label>' \
                         f'<input type="{field_info["input_type"]}" id="{field_name}" name="{field_name}" value="{default or ""}"><br><br>'
        elif field_info['input_type'] == 'textarea':
            field_html = f'<label for="{field_name}">{field_name.capitalize()}:</label><br>' \
                         f'<textarea id="{field_name}" name="{field_name}" rows="4" cols="50">{default or ""}</textarea><br><br>'
        elif field_info['input_type'] in ['checkbox', 'radio']:
            field_html = f'<label>{field_name.capitalize()}:</label><br>'
            for option in field_info['options']:
                checked = "checked" if default and option in default else ""
                field_html += f'<input type="{field_info["input_type"]}" id="{option}" name="{field_name}" value="{option}" {checked}>' \
                              f'<label for="{option}">{option}</label><br>'
            field_html += '<br>'
        elif field_info['input_type'] == 'select':
            field_html = f'<label for="{field_name}">{field_name.capitalize()}:</label>' \
                         f'<select id="{field_name}" name="{field_name}">'
            for option in field_info['options']:
                selected = "selected" if option == default else ""
                field_html += f'<option value="{option}" {selected}>{option}</option>'
            field_html += '</select><br><br>'
        else:
            continue  # Skip if the input type is not recognized
        
        form_html.append(field_html)
    
    return form_html

def get_form_names(config_path=config.FORM_CONFIG_PATH):
    """
    Given a form config path, return a list of available forms, defaulting to the example 
    dictionary provided above.
    """
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
        # print("Config file does not exist. Using the default configuration.")
    return form_config.keys()

def get_form_config(form_name, config_path=config.FORM_CONFIG_PATH, update=False):
    """
    Yields a single config dict for the form name passed, following a factory pattern approach.

    If update is set to True, all fields will be set to optional.
    """
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
        # print("Config file does not exist. Using the default configuration.")

    if form_name not in form_config:
        raise Exception(f"Form '{form_name}' not found in")

    fields = form_config[form_name]
    field_definitions = {}
    
    for field_name, field_info in fields.items():
        
        # Should we consider making an Enum for fields with a limited set of options... 
        # essentially requiring that the values passed are in the Enum of acceptable
        # values? Bit difficult to implement for List and other data types, but may
        # be worthwhile.

        python_type: Type = field_info["output_type"]
        default = field_info.get("default", ...)
        required = field_info.get("required", False) # Default to not required field
        validators = field_info.get("validators", [])

        # If update is True, provide None as the default value ... the idea here is that 
        # the model has already imposed default value constraints at the time of creation.
        # But, it is a legitimate format for clients to pass either (1) data that only 
        # includes the changes the client wants to make or (2) all the data, changing only
        # the fields the client wants to change. We need to be able to make sense of these 
        # two cases. See: https://github.com/signebedi/libreforms-fastapi/issues/34.
        if update:
            field_definitions[field_name] = (Optional[python_type], None)
        else:
            default = field_info.get("default", ...)
            # Use Optional type if default is not set or field is not required
            if (default is ... and python_type != Optional) or not required:
                python_type = Optional[python_type]
            field_definitions[field_name] = (python_type, default)


        for validator_func in validators:
            # This assumes validator_func is callable that accepts a single 
            # value and returns a value or raises an exception
            pass
        
    print(field_definitions)

    # Creating the model dynamically, allowing arbitrary types
    class Config:
        arbitrary_types_allowed = True
    
    model = create_model(form_name, __config__=Config, **field_definitions)

    for field_name, field_info in fields.items():
        validators = field_info.get("validators", [])
        for v in validators:
            # Placeholder for adding the validators to the model here
            pass

    return model

# Deprecated
def __reconstruct_form_data(request, form_fields):
    """
    This repackages request data into a format that pydantic will be able to understand.

    The flask request structure can be understood from the following resource https://stackoverflow.com/a/16664376/13301284.

    We can start by getting the list of fields:

    >>> list(request.form)

    Then, we can iterate through each and get each value:

    >>> for field in list(request.form):
    ...     print(request.form.getlist(field))
    """

    reconstructed_form_data = {}

    for field in list(request):

        # Skip field if it's not supposed to be here
        if not field in form_fields:
            continue

        field_config = form_fields[field]
        reconstructed_form_data[field] = request[field]

        target_type = form_fields[field]['output_type']

        # Check if the output type calls for a collection or a scalar
        if isinstance(reconstructed_form_data[field], list) and len(reconstructed_form_data[field]) == 1 and target_type != list:
            reconstructed_form_data[field] = reconstructed_form_data[field][0]

    return reconstructed_form_data



# Deprecated
def __generate_pydantic_models(form_config: dict):
    """
    Dynamically generates Pydantic models based on a specified form configuration. Each form is represented as a model, 
    with fields defined according to the configuration provided in `form_config`. This allows for the dynamic validation 
    of data according to administratively defined forms. Each field's type, default value, and optionality are considered 
    in the model creation process.

    Parameters
    ----------
    form_config : dict
        A dictionary containing the form configurations, where each key is a form name and its value is another dictionary
        mapping field names to their specifications. Each field specification must at least include 'output_type' for the 
        field's data type, and may optionally include a 'default' value. If a 'default' value is not provided, the field 
        is treated as optional.

        Example:
        {
            "form_name": {
                "field_name": {
                    "output_type": Type,
                    "default": Any,  # Optional
                },
                ...
            },
            ...
        }

    Returns
    -------
    dict
        A dictionary where each key is a form name and its value is a dynamically created Pydantic model class. These models
        can then be used to validate data according to the defined form configurations.

    Raises
    ------
    TypeError
        If an unrecognized type is provided in the form configuration, though this is primarily handled through Pydantic's
        own type validation mechanisms.

    Example Usage
    -------------
    form_config = {
        "contact_form": {
            "name": {
                "output_type": str,
                "default": "John Doe"
            },
            "age": {
                "output_type": int,
                # No default implies optional
            },
            ...
        }
    }
    models = generate_pydantic_models(form_config)
    ContactFormModel = models["contact_form"]
    form_data = {"name": "Jane Doe", "age": 30}
    validated_data = ContactFormModel(**form_data)

    A quick note
    -----
    The function dynamically sets fields as optional if no default value is provided, unless the field is explicitly
    marked as `Optional[Type]`. It also allows for arbitrary types to be used within the models through the
    `arbitrary_types_allowed` configuration.

    This function is designed for use in applications where form fields and validation rules are configurable and 
    not known until runtime, providing flexibility in handling user submissions.
    """
    models = {}

    for form_name, fields in form_config.items():
        field_definitions = {}
        
        for field_name, field_info in fields.items():
            python_type: Type = field_info["output_type"]
            default = field_info.get("default", ...)
            
            # Ensure Optional is always used with a specific type
            if default is ... and python_type != Optional:
                python_type = Optional[python_type]
            
            field_definitions[field_name] = (python_type, default)
            
        # Creating the model dynamically, allowing arbitrary types
        class Config:
            arbitrary_types_allowed = True
        
        model = create_model(form_name, __config__=Config, **field_definitions)
        models[form_name] = model
    
    return models