import os, shutil, json
from datetime import datetime
from zoneinfo import ZoneInfo
from tinydb import TinyDB, Query
from abc import ABC, abstractmethod

class CollectionDoesNotExist(Exception):
    """Exception raised when attempting to access a collection that does not exist."""
    def __init__(self, form_name):
        message = f"The collection '{form_name}' does not exist."
        super().__init__(message)

class ManageDocumentDB(ABC):
    def __init__(self, config: dict, timezone: ZoneInfo):
        self.config = config

        # Here we'll set metadata field names
        self.is_deleted_field = "_is_deleted"
        self.timezone_field= "_timezone"
        self.created_at_field = "_created_at"
        self.last_modified_field = "_last_modified"
        self.ip_address_field = "_ip_address"
        self.created_by_field = "_created_by"
        self.signature_field = "_signature"        
        self.last_editor_field = "_last_editor"
        self.approved_field = "_approved"
        self.approved_by_field = "_approved_by"
        self.approval_signature_field = "_approval_signature"

        # These configs will be helpful later for managing time consistently
        self.timezone = timezone

        # Finally we'll initialize the database instances
        self._initialize_database_collections()

    @abstractmethod
    def _initialize_database_collections(self):
        """Establishes database instances / collections for each form."""
        pass

    @abstractmethod
    def _check_form_exists(self, form_name:str):
        """Checks if the form exists in the configuration."""
        pass
    
    @abstractmethod
    def create_document(self, form_name:str, json_data):
        """Adds an entry to the specified form's database."""
        pass

    @abstractmethod
    def update_document(self, form_name:str, json_data, metadata={}):
        """Updates existing form in specified form's database."""
        pass

    @abstractmethod
    def sign_document(self, form_name:str, json_data, metadata={}):
        """Manage signatures existing form in specified form's database."""
        pass

    @abstractmethod
    def approve_document(self, form_name:str, json_data, metadata={}):
        """Manage approval for existing form in specified form's database."""
        pass

    @abstractmethod
    def search_documents(self, form_name:str, search_query, exclude_deleted=True):
        """Searches for entries that match the search query."""
        pass

    @abstractmethod
    def delete_document(self, form_name:str, search_query, permanent:bool=False):
        """Deletes entries that match the search query, permanently or soft delete."""
        pass

    @abstractmethod
    def get_all_documents(self, form_name:str, exclude_deleted=True):
        """Retrieves all entries from the specified form's database."""
        pass

    @abstractmethod
    def get_one_document(self, form_name:str, search_query, exclude_deleted=True):
        """Retrieves a single entry that matches the search query."""
        pass

    @abstractmethod
    def restore_document(self, form_name:str, search_query):
        """Restores soft deleted entries that match the search query."""
        pass

    @abstractmethod
    def backup_database(self, form_name:str):
        """Creates a backup of the specified form's database."""
        pass

    @abstractmethod
    def restore_database_from_backup(self, form_name:str, backup_filename:str, backup_before_overwriting:bool=True):
        """Restores the specified form's database from its backup."""
        pass


class ManageTinyDB(ManageDocumentDB):
    def __init__(self, config: dict, timezone: ZoneInfo, db_path: str = "instance/"):
        self.db_path = db_path
        os.makedirs(self.db_path, exist_ok=True)

        super().__init__(config, timezone)

        # Here we create a Query object to ship with the class
        self.Form = Query()


    def _initialize_database_collections(self):
        """Establishes database instances for each form."""
        # Initialize databases
        self.databases = {}
        for form_name in self.config.keys():
            self.databases[form_name] = TinyDB(self._get_db_path(form_name))

    def _get_db_path(self, form_name:str):
        """Constructs a file path for the given form's database."""
        return os.path.join(self.db_path, f"{form_name}.json")

    def _check_form_exists(self, form_name:str):
        """Checks if the form exists in the configuration."""
        if form_name not in self.config:
            raise CollectionDoesNotExist(form_name)

    def create_document(self, form_name:str, json_data, metadata={}):
        """Adds json data to the specified form's database."""
        self._check_form_exists(form_name)

        current_timestamp = datetime.now(self.timezone)

        # data_dict = json.loads(json_data)
        data_dict = {
            "data": json_data,
            "metadata": {
                self.is_deleted_field: metadata.get(self.is_deleted_field, False),
                self.timezone_field: metadata.get(self.timezone_field, self.timezone.key),
                self.created_at_field: metadata.get(self.created_at_field, current_timestamp.isoformat()),
                self.last_modified_field: metadata.get(self.last_modified_field, current_timestamp.isoformat()),
                self.ip_address_field: metadata.get(self.ip_address_field, None),
                self.created_by_field: metadata.get(self.created_by_field, None),
                self.signature_field: metadata.get(self.signature_field, None),
                self.last_editor_field: metadata.get(self.last_editor_field, None),
                self.approved_field: metadata.get(self.approved_field, None),
                self.approved_by_field: metadata.get(self.approved_by_field, None),
                self.approval_signature_field: metadata.get(self.approval_signature_field, None),
            }
        }

        document_id = self.databases[form_name].insert(data_dict)

        return document_id

    def update_document(self, form_name:str, json_data, metadata={}):
        """Updates existing form in specified form's database."""
        pass

    def sign_document(self, form_name:str, json_data, metadata={}):
        """Manage signatures existing form in specified form's database."""
        pass


    def approve_document(self, form_name:str, json_data, metadata={}):
        """Manage approval for existing form in specified form's database."""
        pass


    def search_documents(self, form_name:str, search_query, exclude_deleted=True):
        """Searches for entries that match the search query."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            search_query &= Query()[self.is_deleted_field] == False
        return self.databases[form_name].search(search_query)

    def delete_document(self, form_name:str, search_query, permanent:bool=False):
        """Deletes entries that match the search query, permanently or soft delete."""
        self._check_form_exists(form_name)
        if permanent:
            self.databases[form_name].remove(search_query)
        else:
            # Perform a soft delete
            for doc_id in [d.doc_id for d in self.databases[form_name].search(search_query)]:
                self.databases[form_name].update({self.is_deleted_field: True}, doc_ids=[doc_id])

    def get_all_documents(self, form_name:str, exclude_deleted=True):
        """Retrieves all entries from the specified form's database."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            return self.databases[form_name].search(Query()[self.is_deleted_field] == False)
        else:
            return self.databases[form_name].all()

    def get_one_document(self, form_name:str, search_query, exclude_deleted=True):
        """Retrieves a single entry that matches the search query."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            search_query &= Query()[self.is_deleted_field] == False
        return self.databases[form_name].get(search_query)

    def restore_document(self, form_name:str, search_query):
        """Restores soft deleted entries that match the search query."""
        self._check_form_exists(form_name)
        for doc_id in [d.doc_id for d in self.databases[form_name].search(search_query)]:
            self.databases[form_name].update({self.is_deleted_field: False}, doc_ids=[doc_id])

    def backup_database(self, form_name:str):
        """Creates a backup of the specified form's database."""
        self._check_form_exists(form_name)

        backup_dir = os.path.join(self.db_path, 'backups')

        # Ensure the backup directory exists
        os.makedirs(backup_dir, exist_ok=True) 

        timestamp = datetime.now(self.timezone).strftime("%Y%m%d%H%M%S")
        backup_filename = f"{timestamp}_{form_name}.json"
        backup_path = os.path.join(backup_dir, backup_filename)

        source_path = self._get_db_path(form_name)
        shutil.copyfile(source_path, backup_path)

        return backup_path

    def restore_database_from_backup(self, form_name:str, backup_filename:str, backup_before_overwriting:bool=True):
        """Restores the specified form's database from its backup."""
        self._check_form_exists(form_name)

        backup_dir = os.path.join(self.db_path, 'backups')
        backup_path = os.path.join(backup_dir, backup_filename)

        if os.path.exists(backup_path):
            # Backup the current database just to be safe
            if backup_before_overwriting:
                self.backup_database(form_name)

            shutil.copyfile(backup_path, self._get_db_path(form_name))
        else:
            raise FileNotFoundError("Backup file does not exist.")

        # Reinitialize the databse instances
        self._initialize_database_collections()

class ManageMongoDB(ManageDocumentDB):
    pass