import json
from datetime import date
from json import JSONEncoder
from bson import ObjectId

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


# class CustomEncoder(JSONEncoder):
#     """We need to convert date objects to 'YYYY-MM-DD' format"""
#     def default(self, obj):
#         if isinstance(obj, date):
#             return obj.isoformat()
#         # Fall back to the superclass method for other types
#         return JSONEncoder.default(self, obj)

class CustomEncoder(JSONEncoder):
    """Converts date objects to 'YYYY-MM-DD' format."""
    def default(self, obj):
        if isinstance(obj, date):
            return obj.isoformat()
        return super().default(obj)

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

