from jinja2 import Environment, Template, select_autoescape

# Here we create a jinja env
env = Environment(autoescape=select_autoescape(['html', 'xml']))


default_templates = {
    'transaction_log_error': {
        'subj': "Transaction Log Error",
        'cont': "You are receiving this message because you are the designated help email for {{ config.SITE_NAME }}. This message is to notify you that there was an error when writing the following transaction to the transaction log for {{ config.SITE_NAME }}:\n\n***\n\nUser: {{ user.username if not user.opt_out else 'N/A' }}\nTimestamp: {{ current_time }}\nEndpoint: {{ endpoint }}\nQuery Params: {{ query_params if query_params else 'N/A' }}\nRemote Address: {{ remote_addr if not user.opt_out else 'N/A' }}",
    },
    'api_key_rotation': {
        'subj': "{{ config.SITE_NAME }} API Key Rotated",
        'cont': "This email serves to notify you that an API key for user {{ user.username }} has just rotated at {{ config.DOMAIN }}. Please note that your past API key will no longer work if you are employing it in applications. Your new key will be active for 365 days. You can see your new key by visiting {{ config.DOMAIN }}/profile.",
    },
    'form_created': {
        'subj': "Form Created",
        'cont': "This email serves to notify you that a form was submitted at {{ config.DOMAIN }} by the user registered at this email address. The form's document ID is '{{ document_id }}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.",
    },
    'form_updated': {
        'subj': "Form Updated",
        'cont': "This email serves to notify you that an existing form was updated at {{ config.DOMAIN }} by the user registered at this email address. The form's document ID is '{{ document_id }}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.",
    },
    'form_deleted': {
        'subj': "Form Deleted",
        'cont': "This email serves to notify you that a form was deleted at {{ config.DOMAIN }} by the user registered at this email address. The form's document ID is '{{ document_id }}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.",
    },
    'form_restored': {
        'subj': "Form Restored",
        'cont': "This email serves to notify you that a deleted form was restored at {{ config.DOMAIN }} by the user registered at this email address. The form's document ID is '{{ document_id }}'. If you believe this was a mistake, or did not submit a form, please contact your system administrator.",
    },
    'password_reset_instructions': {
        'subj': "{{ config.SITE_NAME }} User Password Reset Instructions",
        'cont': "This email serves to notify you that the user {{ user.username }} has just requested to reset their password at {{ config.DOMAIN }}. To do so, you may use the one-time password {{ otp }}. This one-time password will expire in three hours. If you have access to the user interface, you may reset your password at the following link: {{ config.DOMAIN }}/ui/auth/forgot_password/{{ otp }}. If you believe this was a mistake, please contact your system administrator.",
    },
    'user_registered': {
        'subj': "{{ config.SITE_NAME }} User Registered",
        'cont': "This email serves to notify you that the user {{ new_username }} has just been registered for this email address at {{ config.DOMAIN }}. Your user has been given the following temporary password:\n\n{{ password }}\n\nPlease login to the system and update this password at your earliest convenience.",
    },
    'suspicious_activity': {
        'subj': "{{ config.SITE_NAME }} Suspicious Activity",
        'cont': "This email serves to notify you that there was an attempt to register a user with the same email as the account registered to you at {{ config.DOMAIN }}. If this was you, you may safely disregard this email. If it was not you, you should consider contacting your system administrator and changing your password."
    },
    'help_request': {
        'subj': "Help Request from {{ user.username }}",
        'cont': "You are receiving this message because a user has submitted a request for help at {{ config.DOMAIN }}. You can see the request details below.\n\n****\nUser: {{ user.username }}\nEmail: {{ user.email }}\nTime of Submission: {{ time_str }}\nCategory: {{ help_request.category }}\nSubject: {{ help_request.subject }}\nMessage: {{ help_request.message }}\n****\n\nYou may reply directly to the user who submitted this request by replying to this email."
    }
}



def get_message_jinja(message_type):
    # Retrieve the unrendered Jinja templates from the dictionary
    subj_template_str = default_templates[message_type]['subj']
    cont_template_str = default_templates[message_type]['cont']

    # Placeholder: we want to add logic to read and overwrite 
    # these template key-value pairs using yaml.

    return subj_template_str, cont_template_str


def render_email_message_from_jinja(message_type, **kwargs):
    # Get the template strings
    unrendered_subj, unrendered_cont = get_message_jinja(message_type)

    # Create template objects from strings
    template_subj = Template(unrendered_subj)
    template_cont = Template(unrendered_cont)

    # Render the templates with the provided keyword arguments
    rendered_subj = template_subj.render(**kwargs)
    rendered_cont = template_cont.render(**kwargs)

    return rendered_subj, rendered_cont