import yaml, os, shutil
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo
from jinja2 import Template, Undefined, Environment, make_logging_undefined, select_autoescape


from libreforms_fastapi.utils.pydantic_models import get_form_config_yaml

class RaiseExceptionUndefined(Undefined):
    """This exception will raise when admins invoke a context in an email template that is not available."""
    def _fail_with_undefined_error(self):
        raise Exception(f"{self._undefined_name} is undefined but is required for rendering the email template.")

    # Override the __getattr__ to raise error when accessing undefined attributes
    def __getattr__(self, name):
        self._fail_with_undefined_error()

    # Override other methods that should raise an exception when dealing with undefined
    def __str__(self):
        self._fail_with_undefined_error()



# Here we create a jinja env and pass our custom undefined exception
env = Environment(
    autoescape=select_autoescape(['html', 'xml']),
    undefined=RaiseExceptionUndefined,
)


EXAMPLE_EMAIL_CONFIG_YAML = '''
transaction_log_error:
  subj: "Transaction Log Error"
  cont: |
    <html>
    <body>
      <p>You are receiving this message because you are the designated help email for <b>{{ config.SITE_NAME }}</b>. This message is to notify you that there was an error when writing the following transaction to the transaction log for <b>{{ config.SITE_NAME }}</b>:</p>
      <hr>
      <p>
        <b>User:</b> {{ user.username if not user.opt_out else 'N/A' }}<br>
        <b>Timestamp:</b> {{ current_time }}<br>
        <b>Endpoint:</b> {{ endpoint }}<br>
        <b>Query Params:</b> {{ query_params if query_params else 'N/A' }}<br>
        <b>Remote Address:</b> {{ remote_addr if not user.opt_out else 'N/A' }}
      </p>
    </body>
    </html>
api_key_rotation:
  subj: "{{ config.SITE_NAME }} API Key Rotated"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that an API key for user <b>{{ user.username }}</b> has just rotated at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. Please note that your past API key will no longer work if you are employing it in applications. Your new key will be active for 365 days. You can see your new key by visiting <a href="{{ config.DOMAIN }}/profile">{{ config.DOMAIN }}/profile</a>.</p>
    </body>
    </html>
form_created:
  subj: "Form Created"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that a form was submitted at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a> by the user registered at this email address. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not submit a form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
form_updated:
  subj: "Form Updated"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that an existing form was updated at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a> by the user registered at this email address. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not submit a form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
form_deleted:
  subj: "Form Deleted"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that a form was deleted at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a> by the user registered at this email address. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not submit a form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
form_restored:
  subj: "Form Restored"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that a deleted form was restored at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a> by the user registered at this email address. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not submit a form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
form_stage_changed:
  subj: "Form Stage has Changed"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that a form's stage was changed at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not intend to sign this form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
form_unsigned:
  subj: "Form Unsigned"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that a form was unsigned at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a> by the user registered at this email address. The form's document ID is <b>{{ document_id }}</b>. If you believe this was a mistake, or did not intend to unsign this form, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
user_password_changed:
  subj: "{{ config.SITE_NAME }} User Password Changed"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ user.username }}</b> has just had their password changed at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. If you believe this was a mistake, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
password_reset_instructions:
  subj: "{{ config.SITE_NAME }} User Password Reset Instructions"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ user.username }}</b> has just requested to reset their password at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. If you have access to the user interface, you may reset your password at the following link: <a href="{{ config.DOMAIN }}/ui/auth/forgot_password/{{ otp }}">{{ config.DOMAIN }}/ui/auth/forgot_password/{{ otp }}</a>.  This link will expire in three hours. If you believe this was a mistake, please contact your system administrator {{ "at" + config.HELP_EMAIL + "'>" + config.HELP_EMAIL + "</a>" if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
password_reset_complete:
  subj: "{{ config.SITE_NAME }} User Password Reset"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ user.username }}</b> has just successfully reset their password at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. If you believe this was a mistake, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
user_registered_admin:
  subj: "{{ config.SITE_NAME }} User Registered"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ username }}</b> has just been registered for this email address at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. Your user has been given the following temporary password:</p>
      <p><b>{{ password }}</b></p>
      <p>Please login to the system and update this password at your earliest convenience.</p>
    </body>
    </html>
user_registered:
  subj: "{{ config.SITE_NAME }} User Registered"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ username }}</b> has just been registered for this email address at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>.</p>
    </body>
    </html>
user_registered_verification:
  subj: "{{ config.SITE_NAME }} User Registered"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that the user <b>{{ username }}</b> has just been registered for this email address at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. Please verify your email by clicking the following link: <a href="{{ config.DOMAIN }}/verify/{{ key }}">{{ config.DOMAIN }}/verify/{{ key }}</a>. Please note this link will expire after 48 hours.</p>
    </body>
    </html>
suspicious_activity:
  subj: "{{ config.SITE_NAME }} Suspicious Activity"
  cont: |
    <html>
    <body>
      <p>This email serves to notify you that there was an attempt to register a user with the same email as the account registered to you at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. If this was you, you may safely disregard this email. If it was not you, you should consider contacting your system administrator and changing your password.</p>
    </body>
    </html>
help_request:
  subj: "Help Request from {{ user.username }}"
  cont: |
    <html>
    <body>
      <p>You are receiving this message because a user has submitted a request for help at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. You can see the request details below.</p>
      <hr>
      <p>
        <b>User:</b> {{ user.username }}<br>
        <b>Email:</b> {{ user.email }}<br>
        <b>Time of Submission:</b> {{ time }}<br>
        <b>Category:</b> {{ category }}<br>
        <b>Subject:</b> {{ subject }}<br>
        <b>Message:</b> {{ message }}
      </p>
      <p>You may reply directly to the user who submitted this request by replying to this email.</p>
    </body>
    </html>
unregistered_submission_request_new_user:
  subj: "Your submission link for {{ config.SITE_NAME }}"
  cont: |
    <html>
    <body>
      <p>Hello {{ user.username }},</p>
      <p>You are invited to submit a {{form_name}} form at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. If you didn't previously have an account, a new account has been created for you. Please use the following link to submit a {{form_name}} form:</p>
      <p><a href="{{ config.DOMAIN }}/ui/form/create_unregistered/{{form_name}}/{{api_key}}">{{ config.DOMAIN }}/ui/form/create_unregistered/{{form_name}}/{{api_key}}</a></p>
      <p>If you believe this request was submitted by mistake, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>

unregistered_submission_request_single_use_key:
  subj: "Your single-use submission link for {{ config.SITE_NAME }}"
  cont: |
    <html>
    <body>
      <p>Hello,</p>
      <p>You are invited to submit a {{form_name}} form at <a href="{{ config.DOMAIN }}">{{ config.DOMAIN }}</a>. Please use the following link to submit a {{form_name}} form:</p>
      <p><a href="{{ config.DOMAIN }}/ui/form/create_unregistered/{{form_name}}/{{api_key}}">{{ config.DOMAIN }}/ui/form/create_unregistered/{{form_name}}/{{api_key}}</a></p>
      <p>This key will expire in 4 hours. If you believe this request was submitted by mistake, please contact your system administrator {{ "at " + config.HELP_EMAIL if config.HELP_EMAIL else "" }}.</p>
    </body>
    </html>
'''



def get_email_yaml(config_path, return_as_yaml_str=False):

    # We want to add logic to read and overwrite 
    # these template key-value pairs using yaml.
    default_config = yaml.safe_load(EXAMPLE_EMAIL_CONFIG_YAML)

    try:
        assert(os.path.exists(config_path)) # If it doesn't exist, let's skip this rigamarole
        with open(config_path, 'r') as file:

            yaml_str = file.read()

        if return_as_yaml_str: 
            return yaml_str

        loaded_config = yaml.safe_load(yaml_str)

    except Exception as e:

        if return_as_yaml_str: 
            return EXAMPLE_EMAIL_CONFIG_YAML

        loaded_config = {}

    # Overwrite default config with values from the default path
    for key, value in loaded_config.items():
        default_config[key] = value

    return default_config


def get_message_jinja(message_type, config_path):

    config = get_email_yaml(config_path)
    
    # Retrieve the unrendered Jinja templates from the dictionary
    subj_template_str = config[message_type]['subj']
    cont_template_str = config[message_type]['cont']

    return subj_template_str, cont_template_str


def render_email_message_from_jinja(message_type, config_path, **kwargs):
    # Get the template strings
    unrendered_subj, unrendered_cont = get_message_jinja(message_type, config_path)

    # Create template objects from strings using the environment
    template_subj = env.from_string(unrendered_subj)
    template_cont = env.from_string(unrendered_cont)

    # Render the templates with the provided keyword arguments
    rendered_subj = template_subj.render(**kwargs)
    rendered_cont = template_cont.render(**kwargs)

    return rendered_subj, rendered_cont

def write_email_config_yaml(
    config_path:str,
    email_config_str:str,
    env:str,
    timezone=ZoneInfo("America/New_York"),
    test_on_write:bool=True,
    **kwargs,
):
    """
    Here we write the string representation of the yaml email config.
    """

    if test_on_write:
        # Attempt to load the YAML string to check its validity
        _ = test_email_config(email_config_str, **kwargs)

    # Ensure the base directory exists
    basedir = os.path.dirname(config_path)
    if not os.path.exists(basedir):
        os.makedirs(basedir)

    # Create a backup of the current config
    config_backup_directory = Path(os.getcwd()) / 'instance' / f'{env}_email_config_backups'
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
            file.write(email_config_str)
    except Exception as e:
        raise Exception(f"Failed to write the email config to {config_path}: {e}")

    return True



def test_email_config(email_config_yaml, **kwargs):
    # Load the YAML configuration into a Python dictionary
    email_configs = yaml.safe_load(email_config_yaml)

    # Set default values for parameters
    defaults = {
        'config': {'SITE_NAME': 'ExampleSite', 'DOMAIN': 'example.com'},
        'user': {'username': 'default_user', 'opt_out': False},
        'username': "default_user",
        'current_time': '2022-07-01 12:00:00',
        'endpoint': '/default/endpoint',
        'query_params': 'default=query',
        'remote_addr': '192.168.0.1',
        'document_id': 'default_doc_id',
        'form_name': 'default_form_name',
        'otp': '123456',
        'time': '12:00 PM',
        'category': 'General Inquiry',
        'subject': 'Default Subject',
        'message': 'Default Message',
        'key': 'default_key',
        'api_key': 'default_key',
        'password': 'tempPassword123',
        'document': {},
    }

    # Update defaults with any additional provided parameters
    defaults.update(kwargs)

    # Iterate through each email type in the configuration
    for email_type, template_data in email_configs.items():
        
        # This is a temporary workaround for https://github.com/signebedi/libreforms-fastapi/issues/311
        if email_type not in yaml.safe_load(EXAMPLE_EMAIL_CONFIG_YAML).keys():
          continue

        # We create a copy of defaults so we can remove some context
        # that is not available to certain events
        modified_defaults = defaults.copy()

        # We remove form details here because 
        if email_type in ['transaction_log_error', 'api_key_rotation', 'user_password_changed', 'password_reset_instructions', 'password_reset_complete', 'user_registered', 'user_registered_verification', 'suspicious_activity', 'help_request']:

            modified_defaults.pop('document_id')
            modified_defaults.pop('form_name')

        if email_type != 'user_registered_verification':
            modified_defaults.pop('key')
        
        if email_type != 'password_reset_instructions':
            modified_defaults.pop('otp')

        if email_type != 'user_registered_admin':
            modified_defaults.pop('password')

        if email_type not in ['user_registered', 'user_registered_verification', 'user_registered_admin']:
            modified_defaults.pop('username')

        subj_template = env.from_string(template_data['subj'])
        cont_template = env.from_string(template_data['cont'])

        # Render the subject and content templates without try-except block
        rendered_subj = subj_template.render(**modified_defaults)
        rendered_cont = cont_template.render(**modified_defaults)
        # print(f"Successfully rendered '{email_type}':\nSubject: {rendered_subj}\nContent: {rendered_cont[:60]}...")
    
    return True