import os, shutil
from datetime import datetime
from tinydb import TinyDB, Query

class CollectionDoesNotExist(Exception):
    """Exception raised when attempting to access a collection that does not exist."""
    def __init__(self, form_name):
        message = f"The collection '{form_name}' does not exist."
        super().__init__(message)

class ManageTinyDB:
    def __init__(self, config: dict, db_path: str = "instance/"):
        self.config = config
        self.db_path = db_path
        os.makedirs(self.db_path, exist_ok=True)


        # Here we create a Query object to ship with the class
        self.Form = Query()

        # Here we'll set metadata field names
        self.is_deleted_field = "_is_deleted"

        # Finally we'll initialize the database instances
        self._initialize_database_instances()

    def _initialize_database_instances(self):
        """Establishes database instances for each form."""
        # Initialize databases
        self.databases = {}
        for form_name in self.config.keys():
            self.databases[form_name] = TinyDB(self._get_db_path(form_name))

    def _get_db_path(self, form_name:str):
        """Constructs a file path for the given form's database."""
        return os.path.join(self.db_path, f"{form_name}.json")

    def _check_form_exists(self, form_name):
        """Checks if the form exists in the configuration."""
        if form_name not in self.config:
            raise CollectionDoesNotExist(form_name)

    def add_entry(self, form_name:str, entry):
        """Adds an entry to the specified form's database."""
        self._check_form_exists(form_name)
        document_id = self.databases[form_name].insert(entry)

        return document_id

    def search_entries(self, form_name:str, search_query, exclude_deleted=True):
        """Searches for entries that match the search query."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            search_query &= Query()[self.is_deleted_field] == False
        return self.databases[form_name].search(search_query)

    def delete_entry(self, form_name:str, search_query, permanent=False):
        """Deletes entries that match the search query, permanently or soft delete."""
        self._check_form_exists(form_name)
        if permanent:
            self.databases[form_name].remove(search_query)
        else:
            # Perform a soft delete
            for doc_id in [d.doc_id for d in self.databases[form_name].search(search_query)]:
                self.databases[form_name].update({self.is_deleted_field: True}, doc_ids=[doc_id])

    def get_all_entries(self, form_name:str, exclude_deleted=True):
        """Retrieves all entries from the specified form's database."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            return self.databases[form_name].search(Query()[self.is_deleted_field] == False)
        else:
            return self.databases[form_name].all()

    def get_one_entry(self, form_name:str, search_query, exclude_deleted=True):
        """Retrieves a single entry that matches the search query."""
        self._check_form_exists(form_name)
        if exclude_deleted:
            search_query &= Query()[self.is_deleted_field] == False
        return self.databases[form_name].get(search_query)

    def restore_entry(self, form_name:str, search_query):
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

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
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
        self._initialize_database_instances()

class ManageMongoDB:
    pass