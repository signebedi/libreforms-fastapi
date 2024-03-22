import os, shutil, json
from bson import ObjectId
from datetime import datetime
from zoneinfo import ZoneInfo
from tinydb import (
    TinyDB, 
    Query, 
    Storage
)
from tinydb.table import (
    Table as TinyTable, 
    Document
)

from typing import (
    Mapping,
    Union,
    Iterable,
    List,
)
from abc import ABC, abstractmethod

from libreforms_fastapi.utils.logging import set_logger

# We want to modify TinyDB use use string representations of bson 
# ObjectIDs. As such, we will need to modify some underlying behavior, 
# see https://github.com/signebedi/libreforms-fastapi/issues/15.
class CustomTable(TinyTable):
    document_id_class = str  # Use string IDs instead of integers

    def _get_next_id(self, document_id=str(ObjectId())):
        """
        Generate a new BSON ObjectID string to use as the TinyDB document ID.
        """
        return document_id


    def insert(self, document: Mapping, document_id:Union[str, bool]=False) -> int:
        """
        Insert a new document into the table.

        :param document: the document to insert
        :returns: the inserted document's ID
        """

        if not document_id:
            document_id = str(ObjectId())

        # Make sure the document implements the ``Mapping`` interface
        if not isinstance(document, Mapping):
            raise ValueError('Document is not a Mapping')

        # First, we get the document ID for the new document
        if isinstance(document, Document):
            # For a `Document` object we use the specified ID
            doc_id = document.doc_id

            # We also reset the stored next ID so the next insert won't
            # re-use document IDs by accident when storing an old value
            self._next_id = None
        else:
            # In all other cases we use the next free ID
            doc_id = self._get_next_id(document_id=document_id)

        # Now, we update the table and add the document
        def updater(table: dict):
            if doc_id in table:
                raise ValueError(f'Document with ID {str(doc_id)} '
                                 f'already exists')
                
            # By calling ``dict(document)`` we convert the data we got to a
            # ``dict`` instance even if it was a different class that
            # implemented the ``Mapping`` interface
            table[doc_id] = dict(document)

        # See below for details on ``Table._update``
        self._update_table(updater)

        return doc_id

    def insert_multiple(self, documents: Iterable[Mapping], document_ids:Union[List, bool]=False) -> List[int]:
        """
        Insert multiple documents into the table.

        :param documents: an Iterable of documents to insert
        :returns: a list containing the inserted documents' IDs
        """
        doc_ids = []

        if document_ids and len(document_ids) != len(documents):
            raise Exception("When inserting multiple and passing your own document_ids," \
                "the list must be the same length as the document list")

        def updater(table: dict):
            # for document in documents:
            for i, document in enumerate(documents):

                # Make sure the document implements the ``Mapping`` interface
                if not isinstance(document, Mapping):
                    raise ValueError('Document is not a Mapping')

                if isinstance(document, Document):
                    # Check if document does not override an existing document
                    if document.doc_id in table:
                        raise ValueError(
                            f'Document with ID {str(document.doc_id)} '
                            f'already exists'
                        )

                    # Store the doc_id, so we can return all document IDs
                    # later. Then save the document with its doc_id and
                    # skip the rest of the current loop
                    doc_id = document.doc_id
                    doc_ids.append(doc_id)
                    table[doc_id] = dict(document)
                    continue

                # Generate new document ID for this document
                # Store the doc_id, so we can return all document IDs
                # later, then save the document with the new doc_id
                if not document_ids:
                    document_id = str(ObjectId())
                else:
                    document_id = document_ids[i]
                doc_id = self._get_next_id()
                doc_ids.append(doc_id)
                table[doc_id] = dict(document)

        # See below for details on ``Table._update``
        self._update_table(updater)

        return doc_ids

# Subclass TinyDB and override the table_class attribute with our new logic
class CustomTinyDB(TinyDB):
    table_class = CustomTable



class CollectionDoesNotExist(Exception):
    """Exception raised when attempting to access a collection that does not exist."""
    def __init__(self, form_name):
        message = f"The collection '{form_name}' does not exist."
        super().__init__(message)

class ManageDocumentDB(ABC):
    def __init__(self, config: dict, timezone: ZoneInfo):
        self.config = config

        # Set default log_name if not already set by a subclass
        if not hasattr(self, 'log_name'):
            self.log_name = "document_db.log"

        # Here we'll set metadata field names
        self.document_id_field = "_document_id"
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
    def __init__(self, config: dict, timezone: ZoneInfo, db_path: str = "instance/", use_logger=True, env="development"):
        self.db_path = db_path
        os.makedirs(self.db_path, exist_ok=True)

        self.log_name = "tinydb.log"
        self.use_logger = use_logger

        if self.use_logger:
            self.logger = set_logger(
                environment=env, 
                log_file_name=self.log_name, 
                namespace=self.log_name
            )

        super().__init__(config, timezone)

        # Here we create a Query object to ship with the class
        self.Form = Query()


    def _initialize_database_collections(self):
        """Establishes database instances for each form."""
        # Initialize databases
        self.databases = {}
        for form_name in self.config.keys():
            # self.databases[form_name] = TinyDB(self._get_db_path(form_name))
            self.databases[form_name] = CustomTinyDB(self._get_db_path(form_name))

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

        # This is a little hackish but TinyDB write data to file as Python dictionaries, not JSON.
        convert_data_to_dict = json.loads(json_data)

        # data_dict = json.loads(json_data)

        document_id = metadata.get(self.document_id_field, str(ObjectId()))

        data_dict = {
            "data": convert_data_to_dict,
            "metadata": {
                # self.document_id_field: document_id,
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

        # document_id = self.databases[form_name].insert(data_dict)
        _ = self.databases[form_name].insert(data_dict, document_id=document_id)

        if self.use_logger:
            self.logger.info(f"Inserted document for {form_name} with document_id {document_id}")

        return document_id

    def update_document(self, form_name:str, json_data, metadata={}):
        """Updates existing form in specified form's database."""

        # Placeholder for logger

        pass

    def sign_document(self, form_name:str, json_data, metadata={}):
        """Manage signatures existing form in specified form's database."""

        # Placeholder for logger


        pass


    def approve_document(self, form_name:str, json_data, metadata={}):
        """Manage approval for existing form in specified form's database."""

        # Placeholder for logger

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
                # Placeholder for logger
        else:
            # Perform a soft delete
            for doc_id in [d.doc_id for d in self.databases[form_name].search(search_query)]:
                self.databases[form_name].update({self.is_deleted_field: True}, doc_ids=[doc_id])

                # Placeholder for logger


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

            # Placeholder for logger

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

        if self.use_logger:
            self.logger.info(f"Successfully backed up {form_name} collection to {backup_path}")

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

            if self.use_logger:
                self.logger.info(f"Successfully restored {form_name} collection to from backup {backup_path}")

        else:
            if self.use_logger:
                self.logger.error(f"Failed to restore {form_name} collection from backup - {backup_path} does not exist")

            raise FileNotFoundError("Backup file does not exist.")

        # Reinitialize the databse instances
        self._initialize_database_collections()

class ManageMongoDB(ManageDocumentDB):
    pass