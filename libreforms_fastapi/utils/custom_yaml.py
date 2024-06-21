from datetime import datetime, date, time, timedelta


def get_yaml_constructors(**kwargs):
    """
    This factory is used to build a dictionary of built-in and custom constructors that
    will be used in building the internal, dictionary representation of the form config.
    """

    # Default constructors for returning Python types
    def type_constructor_int(loader, node):
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
        '!type_datetime': type_constructor_datetime,
        '!type_time': type_constructor_time,
        '!type_timedelta': type_constructor_time,
        '!list': type_constructor_list,
        '!tuple': type_constructor_list,
        '!bytes': type_constructor_bytes,
        **kwargs,
    }
    return constructor_mapping