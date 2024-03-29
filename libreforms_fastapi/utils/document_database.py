import os, shutil, json
from bson import ObjectId
from fuzzywuzzy import fuzz
from datetime import datetime
from zoneinfo import ZoneInfo

from tinydb import (
    Query, 
)

from typing import (
    Union,
)
from abc import ABC, abstractmethod

from libreforms_fastapi.utils.logging import set_logger

# This import is used to afix digital signatures to records
from libreforms_fastapi.utils.certificates import sign_record, verify_record_signature

from libreforms_fastapi.utils.custom_tinydb import (
    CustomEncoder,
    CustomTinyDB,
)


class CollectionDoesNotExist(Exception):
    """Exception raised when attempting to access a collection that does not exist."""
    def __init__(self, form_name):
        message = f"The collection '{form_name}' does not exist."
        super().__init__(message)

class DocumentDoesNotExist(Exception):
    """Exception raised when attempting to access a document that does not exist."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' in collection '{form_name}' does not exist."
        super().__init__(message)

class DocumentIsDeleted(Exception):
    """Exception raised when attempting to access a document that has been deleted."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' in collection '{form_name}' has been deleted and cannot be edited."
        super().__init__(message)

class DocumentIsNotDeleted(Exception):
    """Exception raised when attempting to restore a document that is not deleted."""
    def __init__(self, form_name, document_id):
        message = f"The document with ID '{document_id}' in collection '{form_name}' is not deleted and cannot be restored."
        super().__init__(message)

class InsufficientPermissions(Exception):
    """Exception raised when attempting to access a document that user lacks permissions for."""
    def __init__(self, form_name, document_id, username):
        message = f"User '{username}' has insufficient permissions to perform the requested operation on document " \
            f"with ID '{document_id}' in collection '{form_name}'."
        super().__init__(message)

class SignatureError(Exception):
    """Exception raised when attempting to sign a document but the process fails."""
    def __init__(self, form_name, document_id, username):
        message = f"User '{username}' has failed to sign the document " \
            f"with ID '{document_id}' in collection '{form_name}'."
        super().__init__(message)

class DocumentAlreadyHasValidSignature(Exception):
    """Exception raised when attempting to sign a document but it's been signed and the signature is valid."""
    def __init__(self, form_name, document_id, username):
        message = f"User '{username}' has failed to sign the document " \
            f"with ID '{document_id}' in collection '{form_name}'. Document already signed and valid."
        super().__init__(message)

class NoChangesProvided(Exception):
    """Exception raised when attempting to update a document but none of the data has changed."""
    def __init__(self, form_name, document_id,):
        message = f"Failed to update the document with ID '{document_id}' in collection '{form_name}'. " \
            "No new data was provided."
        super().__init__(message)


SignatureError
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


def get_document_database(
    form_names_callable, 
    timezone: ZoneInfo, 
    db_path: str = "instance/", 
    use_logger=True, 
    env="development",
    use_mongodb=False,
    mongodb_uri=None,
):
    """
    This is a factory function that will return one of Document Database manangement classes 
    defined below. The goal of adding the wrapper / intermediate structure here is to reduce
    coupling and facilitate easier testing.
    """
    if use_mongodb:
        if not mongodb_uri or mongodb_uri=="":
            raise Exception("Please pass a value MongoDB URI")
        return ManageMongoDB(
            form_names_callable=form_names_callable, 
            timezone=timezone, 
            db_path=db_path, 
            use_logger=use_logger, 
            env=env,
            mongodb_uri=mongodb_uri,
        )
    # Default to a TinyDB database
    return ManageTinyDB(
        form_names_callable=form_names_callable, 
        timezone=timezone, 
        db_path=db_path, 
        use_logger=use_logger, 
        env=env,
    )


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

        self.env = env
        self.log_name = "tinydb.log"
        self.use_logger = use_logger

        if self.use_logger:
            self.logger = set_logger(
                environment=self.env, 
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
            self.databases[form_name] = CustomTinyDB(self._get_db_path(form_name), cls=CustomEncoder)

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

    def create_document(
        self, 
        form_name:str, 
        json_data,
        # data_dict, 
        metadata={}
    ):
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

    def update_document(
        self, 
        form_name:str, 
        document_id:str, 
        json_data:str,
        # updated_data_dict:dict, 
        metadata={}, 
        limit_users:Union[bool, str]=False, 
        exclude_deleted:bool=True
    ):
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

        # Here we validate and coerce document into its proper types
        # FormModel = get_form_config(form_name=form_name, update=True)
        # _type_safe_data = FormModel.model_validate(document['data'])
        # _data_dict = _type_safe_data.model_dump()


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

        # If there are no unchanged fields, then raise an exception, 
        # see https://github.com/signebedi/libreforms-fastapi/issues/74
        if len(dropping_unchanged_data.keys()) == 0:
            raise NoChangesProvided(form_name, document_id)

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

        # Update only the fields that are provided in json_data and metadata, not replacing the entire 
        # document. The partial approach will minimize the room for mistakes from overwriting entire documents.
        _ = self.databases[form_name].update(document, doc_ids=[document_id])

        if self.use_logger:
            self.logger.info(f"Updated document for {form_name} with document_id {document_id}")

        return document

    def sign_document(
        self, 
        form_name:str, 
        document_id:str, 
        username:str, 
        public_key=None, 
        private_key_path=None, 
        metadata={}, 
        exclude_deleted=True,
        verify_on_sign=True,
        unsign=False,
    ):
        """
        Manage signatures existing form in specified form's database.

        This is a metadata-only method. The actual form data should not be touched.
        
        """

        self._check_form_exists(form_name)

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

        if username != document['metadata'][self.created_by_field]:
            if self.use_logger:
                self.logger.warning(f"Insufficient permissions to {'unsign' if unsign else 'sign'} document for {form_name} with document_id {document_id}")
            raise InsufficientPermissions(form_name, document_id, username)

        # If we are trying to unsign the document, then we remove the signature, update the document, and return.
        if unsign:
            
            # If the document is not signed, raise a no changes exception
            if not document['metadata'][self.signature_field]:
                raise NoChangesProvided(form_name, document_id)

            signature = None

        else:

            # Before we even begin, we verify whether a signature exists and only proceed if it doesn't. Otherwise, 
            # we raise a DocumentAlreadyHasValidSignature exception. The idea here is to avoid spamming signatures if
            # there has been no substantive change to the data since a past signature. This will allow the logic here
            # to proceed if there is no signature, or if the data has changed since the last signature.
            has_document_already_been_signed = verify_record_signature(record=document, username=username, env=self.env, public_key=public_key, private_key_path=private_key_path)

            if has_document_already_been_signed:
                raise DocumentAlreadyHasValidSignature(form_name, document_id, username)

            # Now we afix the signature
            try:
                r, signature = sign_record(record=document, username=username, env=self.env, private_key_path=private_key_path)

                if verify_on_sign:
                    verify = verify_record_signature(record=r, username=username, env=self.env, public_key=public_key, private_key_path=private_key_path)
                    assert (verify)
                    # print ("\n\n\n", a)
            except:
                raise SignatureError(form_name, document_id, username)

        current_timestamp = datetime.now(self.timezone)

        # Build the journal
        journal = document['metadata'].get(self.journal_field)
        journal.append (
            {
                self.signature_field: signature,
                self.last_modified_field: current_timestamp.isoformat(),
                self.last_editor_field: metadata.get(self.last_editor_field, None),
                self.ip_address_field: metadata.get(self.ip_address_field, None),
            }
        )


        # Here we update only a few metadata fields ... fields like approval and signature should be
        # handled through separate API calls.
        document['metadata'][self.last_modified_field] = current_timestamp.isoformat()
        document['metadata'][self.last_editor_field] = metadata.get(self.last_editor_field, None)
        document['metadata'][self.ip_address_field] = metadata.get(self.ip_address_field, None)
        document['metadata'][self.journal_field] = journal
        document['metadata'][self.signature_field] = signature


        # Update only the fields that are provided in  metadata, not replacing the entire 
        # document. The partial approach will minimize the room for mistakes from overwriting entire documents.
        _ = self.databases[form_name].update(document, doc_ids=[document_id])

        if self.use_logger:
            self.logger.info(f"User {username} signed document for {form_name} with document_id {document_id}")

        return document


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

    def restore_document(self, form_name:str, document_id:str, limit_users:Union[bool, str]=False, restore=False, metadata:dict={}):
        """Restores soft deleted entries that match the search query."""
        self._check_form_exists(form_name)

        # Pass the restore payload to the delete_document method. This approach significantly 
        # reduces boilerplate but implements a method that developers probably expect in the API.
        document = self.delete_document(
            form_name=form_name, 
            document_id=document_id, 
            limit_users=limit_users, 
            restore=True, 
            metadata=metadata, 
            permanent=False,
        )

        return document

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