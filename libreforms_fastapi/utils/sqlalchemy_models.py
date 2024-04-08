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
    create_engine,
)
from sqlalchemy.inspection import inspect
from sqlalchemy.orm import (
    relationship, 
    declarative_base, 
    class_mapper, 
    sessionmaker
)

from sqlalchemy_signing import create_signing_class, Signatures

class InsufficientPermissionsError(Exception):
    """Raised when users lack sufficient permissions"""
    pass

# Set the default timezone to UTC
default_tz = ZoneInfo("UTC")

# Instantiatate a declarative base
Base = declarative_base()

def get_sqlalchemy_models(
    sqlalchemy_database_uri: str,
    set_timezone: ZoneInfo = default_tz,
    engine = None,
    SessionLocal = None,
    create_all: bool = True,
    rate_limiting = False,
    rate_limiting_period = 60,
    rate_limiting_max_requests = 100,
):

    def tz_aware_datetime(get_timezone_from_factory: ZoneInfo = set_timezone):
        return datetime.now(get_timezone_from_factory)


    # Create the database engine, see
    # https://fastapi.tiangolo.com/tutorial/sql-databases/#create-the-sqlalchemy-parts
    
    if not engine:
        engine = create_engine(
            sqlalchemy_database_uri,
            connect_args={"check_same_thread": False},
            # The following prevents caching from breaking our rate limitings system, 
            # see https://stackoverflow.com/a/18225372/13301284 
            isolation_level="READ UNCOMMITTED", 
        )
    if not SessionLocal:
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    ####################
    #### MODEL CREATION
    ####################

    # Association table for the many-to-many relationship
    user_group_association = Table('user_group_association', Base.metadata,
        Column('user_id', Integer, ForeignKey('user.id'), primary_key=True),
        Column('group_id', Integer, ForeignKey('group.id'), primary_key=True),
        extend_existing=True
    )


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

        def to_dict(self, exclude_password=True):
            """
            Converts the User instance into a dictionary format, with groups represented
            by their names as a list of strings.
            """
            user_dict = {
                'id': self.id,
                'email': self.email,
                'username': self.username,
                'groups': [group.name for group in self.groups],
                'active': self.active,
                'created_date': self.created_date.isoformat() if self.created_date else None,
                'last_login': self.last_login.isoformat() if self.last_login else None,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
                'public_key': self.public_key.decode('utf-8') if self.public_key else None,  # Assuming public_key is bytes
                'private_key_ref': self.private_key_ref,
                'last_password_change': self.last_password_change.isoformat() if self.last_password_change else None,
                'failed_login_attempts': self.failed_login_attempts,
                'api_key': self.api_key,
                'opt_out': self.opt_out,
                'site_admin': self.site_admin
            }

            if not exclude_password:
                user_dict['password'] = self.password
            
            return user_dict



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


        def to_dict(self, exclude_password=True):
            """
            Converts the Group instance into a dictionary format, with users represented
            by their names as a list of strings.
            """

            group_dict = {
                'id': self.id,
                'name': self.name,
                'permissions': self.permissions,
                'users': [user.username for user in self.users],
            }

            return group_dict

    # Many to one relationship with User table
    class TransactionLog(Base):
        __tablename__ = 'transaction_log'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
        timestamp = Column(DateTime, nullable=False, default=tz_aware_datetime)
        # date = Column(Date, nullable=False, default=lambda: datetime.utcnow().date())
        endpoint = Column(String(1000))
        remote_addr = Column(String(50), nullable=True)
        query_params = Column(JSON, nullable=True) 

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


    # Initialize the signing table
    signatures = Signatures(sqlalchemy_database_uri, byte_len=32, 
        # Pass the rate limiting settings from the params
        rate_limiting=rate_limiting,
        rate_limiting_period=rate_limiting_period, 
        rate_limiting_max_requests=rate_limiting_max_requests,
        Base=Base, # Here we pass the base
        Signing=Signing, # And Signing object we've overwritten
        create_tables=False, # We have already created the tables ourselves
    )

    if create_all:
        Base.metadata.create_all(bind=engine)

    return {
        "User": User,
        "Group": Group,
        "TransactionLog": TransactionLog,
        "ApprovalChains": ApprovalChains,
        "Signing": Signing,
    }, SessionLocal, signatures, engine
