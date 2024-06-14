import markdown, os
from pathlib import Path
from datetime import datetime
from html_sanitizer import Sanitizer

sanitizer_config = {
    'tags': {'a', 'br', 'p', 'strong', 'em', 'ul', 'ol', 'li', 'b', 'i', 'u', 'span', 'div', 'img', 'h1', 'h2', 'h3', 'h4', 'h5'},
    'attributes': {
        'a': ['href', 'title'],
        'img': ['src', 'alt'], 
        'div': ['style'],  # Might mkae sense to sanitize style content separately
    },
    'empty': {'br', 'h1', 'h2', 'h3', 'h4', 'h5'},
    'separate': {'a', 'p', 'ul', 'ol', 'li', 'br', 'img'}, 
    'protocols': {'a': ['http', 'https', 'mailto'], 'img': ['http', 'https']},
    'unescape_special_chars': True
}

sanitizer = Sanitizer()


class UnsafeHtmlContentError(Exception):
    """Custom exception for unsafe HTML content."""
    def __init__(self, message="Unsafe HTML content detected"):
        self.message = message
        super().__init__(self.message)

def validate_html_content(html_content):
    """Validates the provided HTML content for safety.

    Args:
        html_content (str): The HTML content to validate.

    Raises:
        UnsafeHtmlContentError: If unsafe HTML content is detected.
    """
    # List of tags and attributes that are considered unsafe.
    unsafe_patterns = [
        "<script", "</script>",  # Script tags
        "<iframe", "</iframe>",  # Iframe tags
        "javascript:",  # Javascript URLs
        "onerror=", "onload=",  # Event handlers
    ]

    # Check for unsafe patterns in the provided HTML content.
    for pattern in unsafe_patterns:
        if pattern.lower() in html_content.lower():
            raise UnsafeHtmlContentError(f"Detected unsafe pattern: {pattern}")

    # If no unsafe content is detected, the HTML is considered safe.
    return True

def escape_unsafe_html(html_content):
    """Escapes unsafe HTML patterns in the provided content.

    Args:
        html_content (str): The HTML content to sanitize.

    Returns:
        str: The sanitized HTML content.
    """
    # Dictionary of unsafe patterns and their escaped equivalents.
    replacements = {
        "<script": "&lt;script",
        "</script>": "&lt;/script&gt;",
        "<iframe": "&lt;iframe",
        "</iframe>": "&lt;/iframe&gt;",
        "javascript:": "javascript&#58;",
        "onerror=": "onerror&#61;",
        "onload=": "onload&#61;"
    }

    # Escape each unsafe pattern.
    for unsafe, safe in replacements.items():
        html_content = html_content.replace(unsafe, safe)

    return html_content

default_content = """

#### Getting Started

Welcome! This brief guide will help you familiarize yourself with the essential functionalities and navigation tips to enhance your experience on this platform.

To get started, if you're new to our application, you'll want to create an account. You can do this by heading over to the [Create User](/ui/auth/create) page, accessible from the main navigation bar. For those who already have an account, logging in is just as simple—just click on the [Login](/ui/auth/login) link located in the same area.

Once logged in, our application offers a variety of options tailored to enhance your experience. If at any point you find yourself in need of assistance, you can request help through the [Request Help](/ui/help) option, available under the "Account" dropdown menu in the top navigation bar. This feature is there to provide you with the support you need, ensuring a smooth and enjoyable user experience.

For users looking to engage more deeply with our application, the "Submit Forms" dropdown in the top navbar is your gateway to participation. Here, you can choose from a variety of available forms to submit. This functionality is designed to be straightforward, allowing you to contribute or request services efficiently.

Curious about your account details or need to make updates? Your personal profile page is just a few clicks away. Accessible from the "Account" dropdown, the [Profile](/ui/auth/profile) page lets you view and edit your account information at your convenience, ensuring you have full control over your personal data and preferences.

Lastly, we believe in transparency and your right to privacy. To learn more about how we handle your information, please visit this [Privacy Policy](/ui/privacy), a link to which is also located in the footer of this web application. It's there to provide you with clear information about our practices and your rights.

If you have any questions or need further assistance, don't hesitate to reach out through our help features. Welcome aboard, and we look forward to your participation in our web application community!

"""

def get_docs(
    docs_path, 
    scrub_unsafe=True, 
    init_doc_content=default_content, 
    render_markdown=True,
):
    """
    Returns the markdown content of the document,
    creating the document and its parents if they don't exist.
    
    Args:
        docs_path (str): Path to the markdown document.
        scrub_unsafe (bool): If True, scrub unsafe HTML patterns from the content.
    
    """
    # Ensure the path is a Path object
    path_obj = Path(docs_path)
    try:
        # Try to open and read the file
        with open(path_obj, 'r', encoding='utf-8') as file:
            content = file.read()
            if scrub_unsafe:
                content = escape_unsafe_html(content)
            if render_markdown:
                content = markdown.markdown(content, extensions=['toc'])
            return content
    except FileNotFoundError:
        # Create the parent directories and the file if it doesn't exist
        path_obj.parent.mkdir(parents=True, exist_ok=True)
        with open(path_obj, 'w', encoding='utf-8') as file:
            # Create an empty file or initialize with some default content
            file.write(init_doc_content)
            return init_doc_content
    except Exception as e:
        raise e
    



def write_docs(docs_path, content, scrub_unsafe=False):
    """
    Writes content to a document at docs_path, backing up the original if it exists.
    
    Args:
        docs_path (str): Path to the document.
        content (str): Content to write to the document.
        scrub_unsafe (bool): Whether to scrub unsafe HTML from the content.
    """
    docs_path = Path(docs_path)
    backup_dir = Path('instance/docs_backups')  # Define the backup directory path

    if docs_path.exists():
        # Ensure the backup directory exists
        backup_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate a timestamped backup file name and ensure it is placed in the backup directory
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / (docs_path.stem + f"_{timestamp}" + docs_path.suffix)
        docs_path.rename(backup_path)
        
    if scrub_unsafe:
        content = escape_unsafe_html(content)

    # Ensure the parent directory exists
    docs_path.parent.mkdir(parents=True, exist_ok=True)

    with open(docs_path, 'w', encoding='utf-8') as file:
        file.write(content)
        # print(f"Document written to: {docs_path}")
    
    return True



def render_markdown_content(
    markdown_str:str, 
    scrub_unsafe:bool = True, 
):
    """
    Render markdown strings as HTML

    Args:
        markdown_str (str): Markdown text to be rendered as HTML.
        scrub_unsafe (bool): If True, scrub unsafe HTML patterns from the content.
    
    """
    try:
        markdown_str = markdown.markdown(markdown_str, extensions=['toc'])


        if scrub_unsafe:
            markdown_str = sanitizer.sanitize(markdown_str)
            # Restore special chars, see https://github.com/matthiask/html-sanitizer/issues/46
            markdown_str = markdown_str.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">") 


        return markdown_str

    except Exception as e:
        raise e
    