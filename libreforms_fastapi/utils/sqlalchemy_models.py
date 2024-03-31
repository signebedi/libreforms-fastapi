import os
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import (
    Table,
    Boolean, 
    Column, 
    ForeignKey, 
    Integer,
    String, 
    DateTime,
    JSON,
    LargeBinary,
)
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import relationship, declarative_base, class_mapper

from sqlalchemy_signing import create_signing_class


# This whole section where we need to import the config just to set the time
# zone is very hackish and works against decoupling goals... Utils libraries
# should not be dependent on one another... would a factory function make sense?
# That approach could also allow us to generate the engine and session, because
# we could pass the database uri as well...
from libreforms_fastapi.utils.config import get_config
_env = os.environ.get('ENVIRONMENT', 'development')
config = get_config(_env)
def tz_aware_datetime():
    return datetime.now(config.TIMEZONE)

Base = declarative_base()


# Association table for the many-to-many relationship
user_group_association = Table('user_group_association', Base.metadata,
    Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
    Column('group_id', Integer, ForeignKey('group.id'), primary_key=True)
)

class InsufficientPermissionsError(Exception):
    """Raised when users lack sufficient permissions"""
    pass

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True) 
    email = Column(String(1000))
    password = Column(String(1000))
    username = Column(String(1000), unique=True)
    # groups = Column(JSON, default=['default'])
    groups = relationship('Group', secondary=user_group_association, back_populates='users')
    active = Column(Boolean)
    created_date = Column(DateTime, nullable=False, default=tz_aware_datetime)
    last_login = Column(DateTime, nullable=True, default=tz_aware_datetime)
    locked_until = Column(DateTime, nullable=True, default=tz_aware_datetime)
    public_key = Column(LargeBinary(), nullable=True)
    # public_key = Column(String, nullable=True)
    private_key_ref = Column(String, nullable=True) 
    last_password_change = Column(DateTime, nullable=True, default=tz_aware_datetime)
    failed_login_attempts = Column(Integer, default=0)
    api_key = Column(String(1000), ForeignKey('signing.signature'), nullable=True, unique=True)
    # This opt out, if true, will exclude this user's ID and IP from the statistics
    # gathered from their usage, see https://github.com/signebedi/gita-api/issues/59.
    opt_out = Column(Boolean, nullable=False, default=False)
    site_admin = Column(Boolean, nullable=False, default=False)

    transaction_log = relationship("TransactionLog", order_by="TransactionLog.id", back_populates="user")

    def __repr__(self) -> str:

        # Here we join the group names and represent them as a comma-separated string of values
        groups = ", ".join([x.name for x in self.groups])

        return f"User(id={self.id!r}, name={self.username!r}, email={self.email}, site_admin={'Yes' if self.site_admin else 'No'}, " \
            f"active={'Yes' if self.active else 'No'}, groups={groups})"

    def validate_permission(self, form_name: str, required_permission: str) -> bool:
        """
        Checks if the user has the required permission for a given form across all assigned groups.

        :param form_name: The name of the form.
        :param required_permission: The specific permission to check for.
        :returns: True if at least one of the user's groups grants the required permission.
        :raises InsufficientPermissionsError: If none of the groups grant the required permission.
        """
        for group in self.groups:
            # Utilize Group's method to unpack permissions
            permissions = group.get_permissions()

            # Check if the group grants the required permission for the form
            if form_name in permissions and required_permission in permissions[form_name]:
                return True  # Permission granted by this group

        # If no group grants the permission, raise an error
        raise InsufficientPermissionsError(f"User does not have the required permission: {required_permission} for form: {form_name}")

    def compile_permissions(self) -> dict:
        """The point of this method is to return a dict of user's permissions as a dict based on all their groups"""

        permissions_dict={}
        for group in self.groups:
            permissions = group.get_permissions()
            
            for form_name in permissions.keys():
                if form_name not in permissions_dict.keys():
                    permissions_dict[form_name] = []
                for permission in permissions[form_name]:
                    if permission not in permissions_dict[form_name]:
                        permissions_dict[form_name].append(permission)

        return permissions_dict


# Allow admins to define custom groups, see
# https://github.com/signebedi/libreforms-fastapi/issues/22
class Group(Base):
    __tablename__ = 'group'
    id = Column(Integer, primary_key=True)
    name = Column(String(1000), unique=True)
    permissions = Column(JSON)
    users = relationship('User', secondary=user_group_association, back_populates='groups')

    def get_permissions(self) -> dict:
        """We expect permissions to be a list of permissions in the format of form_name:permission_granted - here, we unpack them"""
        unpack_permissions = {}

        for item in self.permissions:
            i = item.split(":")
            form_name = i[0]
            permission =i[1]

            if form_name not in unpack_permissions.keys():
                unpack_permissions[form_name] = []

            unpack_permissions[form_name].append(permission)

        return unpack_permissions

    # def validate_permission(self, form_name, permission):
    #     permission_dict = self.get_permissions()
    #     if form_name not in permission_dict.keys():
    #         raise InsufficientPermissionsError("User does not have the required permissions")

    #     if permission not in permission_dict[form_name]:
    #         raise InsufficientPermissionsError("User does not have the required permissions")

    #     return True

# Many to one relationship with User table
class TransactionLog(Base):
    __tablename__ = 'transaction_log'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=tz_aware_datetime)
    # date = Column(Date, nullable=False, default=lambda: datetime.utcnow().date())
    endpoint = Column(String(1000))
    remote_addr = Column(String(50), nullable=True)
    query_params = Column(String(2000), nullable=True) # Can we find a way to make this a JSON string or similar format?

    user = relationship("User", back_populates="transaction_log")

# Allow custom approval chains to be defined here
class ApprovalChains(Base):
    __tablename__ = 'approval_chains'
    id = Column(Integer, primary_key=True)
    form_name = Column(String(1000))
    apply_to_single_group = Column(String(100), nullable=True) # Maybe we allow admins to route approvals based on the group of the sender...
    send_to_users_manager = Column(Boolean) # I think that this is probably going to be difficult to implement ...


# Create a custom Signing class from sqlalchemy_signing
Signing = create_signing_class(Base, tz_aware_datetime)