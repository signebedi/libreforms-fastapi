from datetime import datetime, date
from typing import List, Optional, Dict, Type

from pydantic import (
    BaseModel,
    ValidationError,
    create_model,
    ConfigDict,
)

# Example form configuration with default values set
example_form_config = {
    "example_form": {
        "text_input": {
            "input_type": "text",
            "output_type": str,
            "field_name": "text_input",
            "default": "Default Text",
            "validators": [],
            "options": None
        },
        "number_input": {
            "input_type": "number",
            "output_type": int,
            "field_name": "number_input",
            "default": 42,
            "validators": [],
            "options": None
        },
        "email_input": {
            "input_type": "email",
            "output_type": str,
            "field_name": "email_input",
            "default": "user@example.com",
            "validators": [],
            "options": None
        },
        "date_input": {
            "input_type": "date",
            "output_type": date,
            "field_name": "date_input",
            "default": "2024-01-01",
            "validators": [],
            "options": None
        },
        "checkbox_input": {
            "input_type": "checkbox",
            "output_type": List[str],
            "field_name": "checkbox_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": [],
            "default": ["Option1", "Option3"]
        },
        "radio_input": {
            "input_type": "radio",
            "output_type": str,
            "field_name": "radio_input",
            "options": ["Option1", "Option2"],
            "validators": [],
            "default": "Option2"
        },
        "select_input": {
            "input_type": "select",
            "output_type": str,
            "field_name": "select_input",
            "options": ["Option1", "Option2", "Option3"],
            "validators": [],
            "default": "Option2"
        },
        "textarea_input": {
            "input_type": "textarea",
            "output_type": str,
            "field_name": "textarea_input",
            "default": "Default textarea content.",
            "validators": [],
            "options": None
        },
        "file_input": {
            "input_type": "file",
            "output_type": Optional,
            "field_name": "file_input",
            "options": None,
            "validators": [],
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




def generate_pydantic_models(form_config):
    models = {}

    for form_name, fields in form_config.items():
        field_definitions = {}
        
        for field_name, field_info in fields.items():
            python_type: Type = field_info["output_type"]
            default = field_info.get("default", ...)
            
            # Ensure Optional is always used with a specific type
            if default is ... and python_type != Optional:  # Check if there's no default and it's not already Optional
                python_type = Optional[python_type]
            
            field_definitions[field_name] = (python_type, default)
            
        # Creating the model dynamically with arbitrary types allowed
        model_config = ConfigDict(arbitrary_types_allowed=True)
        model = create_model(form_name, __config__=model_config, **field_definitions)
        models[form_name] = model
    
    return models

def reconstruct_form_data(request, form_fields):
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

    for field in list(request.form):

        # Skip field if it's not supposed to be here
        if not field in form_fields:
            continue

        field_config = form_fields[field]
        reconstructed_form_data[field] = request.form.getlist(field)

        target_type = form_fields[field]['output_type']

        # Check if the output type calls for a collection or a scalar
        if isinstance(reconstructed_form_data[field], list) and len(reconstructed_form_data[field]) == 1 and target_type != list:
            reconstructed_form_data[field] = reconstructed_form_data[field][0]

    return reconstructed_form_data