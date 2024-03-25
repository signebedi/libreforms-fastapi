import os, shutil, json
from bson import ObjectId
from fuzzywuzzy import fuzz
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

class DocumentDoesNotExist(Exception):
    """Exception raised when attempting to access a document that does not exist."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' collection '{form_name}' does not exist."
        super().__init__(message)

class DocumentIsDeleted(Exception):
    """Exception raised when attempting to access a document that has been deleted."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' collection '{form_name}' has been deleted and cannot be edited."
        super().__init__(message)

class DocumentIsNotDeleted(Exception):
    """Exception raised when attempting to restore a document that is not deleted."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' collection '{form_name}' has not been deleted and cannot be restored."
        super().__init__(message)



class InsufficientPermissions(Exception):
    """Exception raised when attempting to access a document that user lacks permissions for."""
    def __init__(self, form_name, document_id, username):
        message = f"User '{user}' has insufficinet permissions to perform the requested operation on document" \
            f"with ID '{document_id}' collection '{form_name}'."
        super().__init__(message)


# Pulled from https://github.com/signebedi/gita-api
def fuzzy_search_normalized(text_string, search_term, segment_length=None):
    if segment_length is None:
        segment_length = len(search_term)
    highest_score = 0
    text_string = text_string.lower()
    search_term = search_term.lower()
    for i in range(0, len(text_string), segment_length):
        segment = text_string[i:i+segment_length]
        score = fuzz.ratio(search_term, segment)
        if score > highest_score:
            highest_score = score
    return highest_score


class ManageDocumentDB(ABC):
    def __init__(self, form_names_callable, timezone: ZoneInfo):
        self.form_names_callable = form_names_callable

        # Set default log_name if not already set by a subclass
        if not hasattr(self, 'log_name'):
            self.log_name = "document_db.log"

        # Here we'll set metadata field names
        self.form_name_field = "_form_name"
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
        self.journal_field = "_journal"

        # These configs will be helpful later for managing time consistently
        self.timezone = timezone

        # Finally we'll initialize the database instances
        self._initialize_database_collections()

    @abstractmethod
    def _initialize_database_collections(self):
        """Establishes database instances / collections for each form."""
        pass

    # @abstractmethod
    # def _update_database_collections(self, form_names_callable):
    #     """Idempotent method to update available collections."""
    #     pass

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
    def fuzzy_search_documents(self, form_name:str, search_query, exclude_deleted:bool=True):
        """Fuzzy searches for entries that match the search query."""
        pass

    @abstractmethod
    def delete_document(self, form_name:str, search_query, permanent:bool=False):
        """Deletes entries that match the search query, permanently or soft delete."""
        pass

    @abstractmethod
    def get_all_documents(self, form_name:str, exclude_deleted:bool=True):
        """Retrieves all entries from the specified form's database."""
        pass

    @abstractmethod
    def get_one_document(self, form_name:str, search_query, exclude_deleted:bool=True):
        """Retrieves a single entry that matches the search query."""
        pass

    @abstractmethod
    def restore_document(self, form_name:str, search_query):
        """Restores soft deleted entries that match the search query."""
        pass

    @abstractmethod
    def backup_collection(self, form_name:str):
        """Creates a backup of the specified form's database."""
        pass

    @abstractmethod
    def restore_collection_from_backup(self, form_name:str, backup_filename:str, backup_before_overwriting:bool=True):
        """Restores the specified form's database from its backup."""
        pass


class ManageTinyDB(ManageDocumentDB):
    def __init__(self, form_names_callable, timezone: ZoneInfo, db_path: str = "instance/", use_logger=True, env="development"):
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

        super().__init__(form_names_callable, timezone)

        # Here we create a Query object to ship with the class
        self.Form = Query()


    def _initialize_database_collections(self):
        """Establishes database instances for each form."""
        # Initialize databases
        self.databases = {}
        for form_name in self.form_names_callable():
            # self.databases[form_name] = TinyDB(self._get_db_path(form_name))
            self.databases[form_name] = CustomTinyDB(self._get_db_path(form_name))

    def _get_db_path(self, form_name:str):
        """Constructs a file path for the given form's database."""
        return os.path.join(self.db_path, f"{form_name}.json")

    def _check_form_exists(self, form_name:str):
        """Checks if the form exists in the configuration."""
        if form_name not in self.form_names_callable():
            raise CollectionDoesNotExist(form_name)

        # If a form name is found in the callable but not in the collections, reinitialize. 
        # This probably means there has been a change to the form config. This class should
        # be able to work even when configuration data changes.
        if form_name not in self.databases.keys():
            self._initialize_database_collections()

    def create_document(self, form_name:str, json_data, metadata={}):
        """Adds json data to the specified form's database."""
        self._check_form_exists(form_name)

        current_timestamp = datetime.now(self.timezone)

        # This is a little hackish but TinyDB write data to file as Python dictionaries, not JSON.
        convert_data_to_dict = json.loads(json_data)

        document_id = metadata.get(self.document_id_field, str(ObjectId()))

        data_dict = {
            "data": convert_data_to_dict,
            "metadata": {
                # self.document_id_field: document_id,
                self.is_deleted_field: metadata.get(self.is_deleted_field, False),
                self.document_id_field: document_id,
                self.form_name_field: form_name,
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
                self.journal_field: []
            }
        }

        # document_id = self.databases[form_name].insert(data_dict)
        _ = self.databases[form_name].insert(data_dict, document_id=document_id)

        if self.use_logger:
            self.logger.info(f"Inserted document for {form_name} with document_id {document_id}")

        return data_dict

    def update_document(self, form_name:str, document_id:str, json_data:str, metadata={}, limit_users:Union[bool, str]=False, exclude_deleted:bool=True):
        """Updates existing form in specified form's database."""

        self._check_form_exists(form_name)
        # if self.use_logger:
        #     self.logger.info(f"Starting update for {form_name} with document_id {document_id}")

        # Ensure the document exists
        document = self.databases[form_name].get(doc_id=document_id)
        if not document:
            if self.use_logger:
                self.logger.warning(f"No document for {form_name} with document_id {document_id}")
            raise DocumentDoesNotExist(form_name, document_id)

        # If exclude_deleted is set, then we return None if the document is marked as deleted
        if exclude_deleted and document['metadata'][self.is_deleted_field] == True:
            if self.use_logger:
                self.logger.warning(f"Document for {form_name} with document_id {document_id} is deleted and was not updated")
            raise DocumentIsDeleted(form_name, document_id)

        # If we are limiting user access based on group-based access controls, and this user is 
        # not the document creator, then return None
        if isinstance(limit_users, str) and document['metadata'][self.created_by_field] != limit_users:
            if self.use_logger:
                self.logger.warning(f"Insufficient permissions to update document for {form_name} with document_id {document_id}")
            raise InsufficientPermissions(form_name, document_id, limit_users)

        current_timestamp = datetime.now(self.timezone)

        # print("\n\n\n\nDocument: ", document)

        # This is a little hackish but TinyDB write data to file as Python dictionaries, not JSON.
        updated_data_dict = json.loads(json_data)

        # Here we remove data that has not been changed
        dropping_unchanged_data = {}
        for field in updated_data_dict.keys():

            # print(field)

            if all([
                field in document['data'].keys(),
                updated_data_dict[field] != document['data'][field],
                updated_data_dict[field] is not None
            ]):

                # print(f"\n\n\n{field} in document data but has different value")

                dropping_unchanged_data[field] = updated_data_dict[field]
            elif all([
                field not in document['data'].keys(),
                updated_data_dict[field] is not None
            ]):

                # print(f"\n\n\n{field} not in document data")

                dropping_unchanged_data[field] = updated_data_dict[field]

        # print("\n\n\nDropping Unchanged Fields: ", dropping_unchanged_data)

        # Build the journal
        journal = document['metadata'].get(self.journal_field)
        journal.append (
            {
                self.last_modified_field: current_timestamp.isoformat(),
                self.last_editor_field: metadata.get(self.last_editor_field, None),
                self.ip_address_field: metadata.get(self.ip_address_field, None),
                **dropping_unchanged_data,
            }
        )

        # Now we update the document with the changes
        for field in dropping_unchanged_data.keys():
            document['data'][field] = dropping_unchanged_data[field]

        # Here we update only a few metadata fields ... fields like approval and signature should be
        # handled through separate API calls.
        document['metadata'][self.last_modified_field] = current_timestamp.isoformat()
        document['metadata'][self.last_editor_field] = metadata.get(self.last_editor_field, None)
        document['metadata'][self.ip_address_field] = metadata.get(self.ip_address_field, None)
        document['metadata'][self.journal_field] = journal


        # print("\n\n\nUpdated Document: ", document)

        # Update only the fields that are provided in json_data and metadata, not replacing the entire 
        # document. The partial approach will minimize the room for mistakes from overwriting entire documents.
        _ = self.databases[form_name].update(document, doc_ids=[document_id])

        if self.use_logger:
            self.logger.info(f"Updated document for {form_name} with document_id {document_id}")

        return document

    def sign_document(self, form_name:str, json_data, metadata={}):
        """Manage signatures existing form in specified form's database."""

        # Placeholder for logger


        pass


    def approve_document(self, form_name:str, json_data, metadata={}):
        """Manage approval for existing form in specified form's database."""

        # Placeholder for logger

        pass


    def fuzzy_search_documents(self, search_term:str, limit_users:Union[bool, dict]=False, form_name:Union[bool, str]=False, threshold=80, exclude_deleted:bool=True):
        """Searches for entries that match the search query."""
        
        if isinstance(form_name, str):
            self._check_form_exists(form_name)
            data = self.databases[form_name].all()

            if isinstance(limit_users, dict):
                if form_name not in limit_users.keys():
                    return []
                elif isinstance(limit_users[form_name], str):
                    data = [x for x in data if x['metadata'][self.created_by_field] == limit_users[form_name]]

        else:
            data = []
            for f in self.databases.keys():
                d = self.databases[f].all()

                if isinstance(limit_users, dict):
                    if f not in limit_users.keys():
                        # print("Form name not found")
                        continue
                    elif isinstance(limit_users[f], str):
                        d = [x for x in d if x['metadata'][self.created_by_field] == limit_users[f]]

                data.extend(d)


        if exclude_deleted:

            print(data)
            data = [x for x in data if x['metadata'][self.is_deleted_field] == False]

        search_results = []

        for document in data:
            # Convert the document to a string representation for comparison.
            doc_string = json.dumps(document).lower()
            score = fuzzy_search_normalized(doc_string, search_term)
            if score >= threshold:
                search_results.append((document, score))

        # Sort results based on score in descending order.
        sorted_results = sorted(search_results, key=lambda x: x[1], reverse=True)
        return [doc for doc, score in sorted_results]

    def delete_document(self, form_name:str, document_id:str, limit_users:Union[bool, str]=False, restore=False, metadata:dict={}, permanent:bool=False):
        """Deletes entries that match the search query, permanently or soft delete."""
        self._check_form_exists(form_name)

        document = self.databases[form_name].get(doc_id=document_id)
        if not document:
            if self.use_logger:
                self.logger.warning(f"No document for {form_name} with document_id {document_id}")
            raise DocumentDoesNotExist(form_name, document_id)

        if document['metadata'][self.is_deleted_field] == True and not restore:
            if self.use_logger:
                self.logger.warning(f"Document for {form_name} with document_id {document_id} is already deleted and was not updated")
            raise DocumentIsDeleted(form_name, document_id)


        if document['metadata'][self.is_deleted_field] == False and restore:
            raise DocumentIsNotDeleted(form_name, document_id)

        # If we are limiting user access based on group-based access controls, and this user is 
        # not the document creator, then return None
        if isinstance(limit_users, str) and document['metadata'][self.created_by_field] != limit_users:
            if self.use_logger:
                self.logger.warning(f"Insufficient permissions to delete document for {form_name} with document_id {document_id}")
            raise InsufficientPermissions(form_name, document_id, limit_users)

        if permanent and not restore:
            self.databases[form_name].remove(doc_ids=[document_id])
            if self.use_logger:
                self.logger.info(f"Permanently deleted document for {form_name} with document_id {document_id}")

        current_timestamp = datetime.now(self.timezone)

        # Build the journal
        journal = document['metadata'].get(self.journal_field)
        journal.append (
            {
                self.last_modified_field: current_timestamp.isoformat(),
                self.last_editor_field: metadata.get(self.last_editor_field, None),
                self.ip_address_field: metadata.get(self.ip_address_field, None),
                self.is_deleted_field: restore==False, # Here we base the value for _is_deleted based on the `restore` param
            }
        )

        # Here we update only a few metadata fields ... fields like approval and signature should be
        # handled through separate API calls. The most important here are _is_deleted and _journal.
        document['metadata'][self.last_modified_field] = current_timestamp.isoformat()
        document['metadata'][self.last_editor_field] = metadata.get(self.last_editor_field, None)
        document['metadata'][self.ip_address_field] = metadata.get(self.ip_address_field, None)
        document['metadata'][self.is_deleted_field] = restore==False # Here we base the value for _is_deleted based on the `restore` param
        document['metadata'][self.journal_field] = journal

        # Update only the fields that are provided in json_data and metadata, not replacing the entire 
        # document. The partial approach will minimize the room for mistakes from overwriting entire documents.
        _ = self.databases[form_name].update(document, doc_ids=[document_id])

        if self.use_logger:
            self.logger.info(f"Deleted document for {form_name} with document_id {document_id}")

        return document



    def get_all_documents(self, form_name:str, limit_users:Union[bool, str]=False, exclude_deleted:bool=True):

        """Retrieves all entries from the specified form's database."""
        self._check_form_exists(form_name)

        documents = self.databases[form_name].all()

        if not documents or len(documents) == 0:
            return None

        if isinstance(limit_users, str):
            documents = [x for x in documents if x['metadata'][self.created_by_field] == limit_users]

        if exclude_deleted:
            documents = [x for x in documents if x['metadata'][self.is_deleted_field] == False]

        return documents

    def get_one_document(self, form_name:str, document_id:str, limit_users:Union[bool, str]=False, exclude_deleted:bool=True):
        """Retrieves a single entry that matches the search query."""
        self._check_form_exists(form_name)

        document = self.databases[form_name].get(doc_id=document_id)

        if not document:
            return None

        if isinstance(limit_users, str) and document['metadata'][self.created_by_field] != limit_users:
            return None

        if exclude_deleted and document['metadata'][self.is_deleted_field] == True:
            return None

        return document

    def restore_document(self, form_name:str, search_query):
        """Restores soft deleted entries that match the search query."""
        self._check_form_exists(form_name)
        for doc_id in [d.doc_id for d in self.databases[form_name].search(search_query)]:
            self.databases[form_name].update({self.is_deleted_field: False}, doc_ids=[doc_id])

            # Placeholder for logger

    def backup_collection(self, form_name:str):
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

    def restore_collection_from_backup(self, form_name:str, backup_filename:str, backup_before_overwriting:bool=True):
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