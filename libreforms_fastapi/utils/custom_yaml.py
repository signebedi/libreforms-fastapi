import yaml
from datetime import datetime, date, time, timedelta



def get_custom_loader(
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

            else:

                # Register the type constructors
                for key, value in get_yaml_type_constructors().items():
                    self.add_constructor(key, value)

                # If we want the full loader initialized, then we will expect that doc_db,
                # session, User, and Group are not None, then add these as data constructors,
                # see https://github.com/signebedi/libreforms-fastapi/issues/150.

                _all_users = [x.to_dict(just_the_basics=True)['username'] for x in session.query(User).all()]
                _all_groups = [x.to_dict()['name'] for x in session.query(Group).all()]

                def data_constructor_all_usernames(loader, node):
                    if self.initialize_full_loader and User is not None and session is not None:
                        return [""]+_all_users
                    else:
                        return [""]

                self.add_constructor('!all_usernames', data_constructor_all_usernames)


                # Here we add a selection of users by group
                def data_constructor_dynamic_users_by_group(group_name):

                    def dynamic_method(loader, data):
                        if User is not None and Group is not None and session is not None:

                            users_in_group = session.query(User).join(User.groups).filter(Group.name == group_name).all()

                            return [""]+[x.to_dict()['username'] for x in users_in_group]

                        else:
                            return [""]

                    return dynamic_method

                if User is not None and Group is not None:
                    for group_name in _all_groups:
                        self.add_constructor(
                            f'!all_usernames_by_group_{group_name}', 
                            data_constructor_dynamic_users_by_group(group_name)
                        )


                def data_constructor_all_group_names(loader, node):
                    if Group is not None and session is not None:
                        return [""]+_all_groups
                    else:
                        return [""]

                self.add_constructor('!all_groups', data_constructor_all_group_names)              

                def data_constructor_dynamic_forms(form_name):

                    def dynamic_method(loader, data):
                        if self.initialize_full_loader and doc_db is not None:
                            return [""]+doc_db._get_existing_document_ids(form_name)
                        else:
                            return [""]

                    return dynamic_method
                
                if doc_db is not None:
                    for form_name in doc_db._get_form_names():
                        self.add_constructor(
                            f'!all_submissions_{form_name}', 
                            data_constructor_dynamic_forms(form_name)
                        )

    return CustomFullLoader


def get_yaml_type_constructors(**kwargs):
    """
    This factory is used to build a dictionary of built-in and custom constructors that
    will be used in serialize the internal, dictionary representation of the form config.
    """

    # Default constructors for returning Python types
    def type_constructor_int(loader, node):
        # If initialize_full_loader is not True, then we really 
        # don't need to manage any special constructors at all.
        return int

    def type_constructor_str(loader, node):
        return str

    def type_constructor_date(loader, node):
        return date

    def type_constructor_datetime(loader, node):
        return datetime

    def type_constructor_time(loader, node):
        return time

    def type_constructor_timedelta(loader, node):
        return timedelta

    def type_constructor_list(loader, node):
        return list

    def type_constructor_tuple(loader, node):
        return tuple

    def type_constructor_bytes(loader, node):
        return bytes

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
