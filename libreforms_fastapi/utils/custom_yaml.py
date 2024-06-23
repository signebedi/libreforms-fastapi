import yaml
from datetime import datetime, date, time, timedelta



def get_custom_loader(
    # config_file: str,
    initialize_full_loader: bool = False,
    doc_db = None,
    session = None,
    User = None,
    Group = None,
):
    """We create a factory here so that we can pass app-specific data, like users, groups, and forms."""

    class CustomFullLoader(yaml.FullLoader):
        def __init__(self, stream):
            super().__init__(stream)

            self.initialize_full_loader = initialize_full_loader


            # Whitelist all constructors when we are only partially initializing ...
            # viz, when we are only trying to obtain form names.
            if not self.initialize_full_loader:
                def unknown_constructor(loader, suffix, node):
                    return str("")
                self.add_multi_constructor('', unknown_constructor)

            # Register the type constructors
            for key, value in get_basic_yaml_constructors(initialize_full_loader=self.initialize_full_loader).items():
                self.add_constructor(key, value)

            # If we want the full loader initialized, then we will expect that doc_db,
            # session, User, and Group are not None, then add these as data constructors,
            # see https://github.com/signebedi/libreforms-fastapi/issues/150.

            def data_constructor_all_usernames(loader, node):
                if self.initialize_full_loader and User is not None and session is not None:
                    return [""]+[x.to_dict(just_the_basics=True)['username'] for x in session.query(User).all()]
                else:
                    return [""]

            self.add_constructor('!all_usernames', data_constructor_all_usernames)

            def data_constructor_all_group_names(loader, node):
                if self.initialize_full_loader and Group is not None and session is not None:
                    return [""]+[x.to_dict()['name'] for x in session.query(Group).all()]
                else:
                    return [""]

            self.add_constructor('!all_groups', data_constructor_all_group_names)              

            def data_constructor_dynamic_forms(form_name, initialize_full_loader, doc_db):

                def dynamic_method(loader, data):
                    if self.initialize_full_loader and doc_db is not None:
                        return [""]+doc_db._get_existing_document_ids(form_name)
                    else:
                        return [""]

                return dynamic_method
            
            # This little block of code is going to give us a world of difficulty 
            # when we don't pass doc_db but want to validate the yaml ... how do we
            # access the form names other than doc_db._get_form_names()so we can
            # remove `if doc_db is not None:`?
            if doc_db is not None:
                for form_name in doc_db._get_form_names():
                    self.add_constructor(
                        f'!all_forms_{form_name}', 
                        data_constructor_dynamic_forms(
                            form_name, 
                            self.initialize_full_loader, 
                            doc_db=doc_db
                        )
                    )

    return CustomFullLoader


def get_basic_yaml_constructors(
    initialize_full_loader: bool = False,
    **kwargs
):
    """
    This factory is used to build a dictionary of built-in and custom constructors that
    will be used in serialize the internal, dictionary representation of the form config.
    """

    # Default constructors for returning Python types
    def type_constructor_int(loader, node):
        # If initialize_full_loader is not True, then we really 
        # don't need to manage any special constructors at all.
        return int if initialize_full_loader else ""

    def type_constructor_str(loader, node):
        return str if initialize_full_loader else ""

    def type_constructor_date(loader, node):
        return date if initialize_full_loader else ""

    def type_constructor_datetime(loader, node):
        return datetime if initialize_full_loader else ""

    def type_constructor_time(loader, node):
        return time if initialize_full_loader else ""

    def type_constructor_timedelta(loader, node):
        return timedelta if initialize_full_loader else ""

    def type_constructor_list(loader, node):
        return list if initialize_full_loader else ""

    def type_constructor_tuple(loader, node):
        return tuple if initialize_full_loader else ""

    def type_constructor_bytes(loader, node):
        return bytes if initialize_full_loader else ""

    # We create a constructor mapping that we'll use later to 
    # register the constructors.
    constructor_mapping = {
        '!int': type_constructor_int,
        '!str': type_constructor_str,
        '!date': type_constructor_date,
        '!datetime': type_constructor_datetime,
        '!time': type_constructor_time,
        '!timedelta': type_constructor_timedelta,
        '!list': type_constructor_list,
        '!tuple': type_constructor_list,
        '!bytes': type_constructor_bytes,
        **kwargs,
    }

    return constructor_mapping
