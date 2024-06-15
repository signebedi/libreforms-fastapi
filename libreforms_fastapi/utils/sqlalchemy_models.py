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
    Enum,
    LargeBinary,
    create_engine,
    UniqueConstraint,
    text,
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

# Set the default timezone to America/New_York
default_tz = ZoneInfo("America/New_York")

# Instantiatate a declarative base
Base = declarative_base()


def test_relational_database_connection(sqlalchemy_database_uri):
    """
    Test the connection using the given SQLAlchemy engine.
    This function tries to open a session and execute a simple SELECT statement.
    If the connection is live, it will return True, otherwise, it will return False.
    """
    
    engine = create_engine(
        sqlalchemy_database_uri, 
        connect_args={"check_same_thread": False} if sqlalchemy_database_uri.startswith("sqlite") else {},
        isolation_level="READ UNCOMMITTED", 
        echo=True, 
        pool_pre_ping=True
    )

    SessionLocal = sessionmaker(bind=engine)
    session = SessionLocal()
    try:
        # The SELECT 1 will be executed due to pool_pre_ping if the connection is bad it will raise an error.
        session.execute(text("SELECT 1"))
        session.commit()
        print("Connection test successful.")
        return True
    except Exception as e:
        print(f"Connection test failed: {str(e)}")
        return False
    finally:
        session.close()



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
            connect_args={"check_same_thread": False} if sqlalchemy_database_uri.startswith("sqlite") else {},
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

        relationships = relationship(
            'UserRelationship',
            foreign_keys='UserRelationship.user_id',
            back_populates='user'
        )

        received_relationships = relationship(
            'UserRelationship',
            foreign_keys='UserRelationship.related_user_id',
            back_populates='related_user'
        )

        # Added password reuse tracking, see https://github.com/signebedi/libreforms-fastapi/issues/230
        password_reuses = relationship(
            "PasswordReuse", 
            order_by="PasswordReuse.id", 
            back_populates="user",
            lazy="dynamic",
        )


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

        def to_dict(self, 
            just_the_basics=False, 
            exclude_password=True,
        ):
            """
            Converts the User instance into a dictionary format, with groups represented
            by their names as a list of strings.
            """

            user_dict = {
                'id': self.id,
                'email': self.email,
                'username': self.username,
                'groups': [group.name for group in self.groups]
            }

            if not just_the_basics:
                user_dict['active'] = self.active
                user_dict['created_date'] = self.created_date.isoformat() if self.created_date else None
                user_dict['last_login'] = self.last_login.isoformat() if self.last_login else None
                user_dict['locked_until'] = self.locked_until.isoformat() if self.locked_until else None
                user_dict['public_key'] = self.public_key.decode('utf-8') if self.public_key else None  # Assuming public_key is byte
                user_dict['private_key_ref'] = self.private_key_ref
                user_dict['last_password_change'] = self.last_password_change.isoformat() if self.last_password_change else None
                user_dict['failed_login_attempts'] = self.failed_login_attempts
                user_dict['api_key'] = self.api_key
                user_dict['opt_out'] = self.opt_out
                user_dict['site_admin'] = self.site_admin

            if not exclude_password:
                user_dict['password'] = self.password
            
            return user_dict


    # Added in https://github.com/signebedi/libreforms-fastapi/issues/230
    class PasswordReuse(Base):
        __tablename__ = 'password_reuse'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('user.id'), nullable=False)
        hashed_password = Column(String(1000), nullable=False)
        timestamp = Column(DateTime, nullable=False, default=tz_aware_datetime)

        # Relationship back to the user
        user = relationship("User", back_populates="password_reuses")

        def to_dict(self):
            """Converts a PasswordReuse instance into a dict."""
            return {
                'id': self.id,
                'user_id': self.user_id,
                'hashed_password': self.hashed_password,
                'timestamp': self.timestamp,
            }

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

        def to_dict(self):
            """
            Converts the Log instance into a dictionary format.
            """

            log_dict = {
                "id":self.id,
                "user_id":self.user_id,
                "timestamp":self.timestamp,
                "endpoint":self.endpoint,
                "remote_addr":self.remote_addr,
                "query_params":self.query_params,
            }

            if self.user:
                log_dict["user_details"] = self.user.to_dict()

            return log_dict


    class RelationshipType(Base):
        __tablename__ = 'relationship_types'
        id = Column(Integer, primary_key=True)
        name = Column(String, unique=True)
        reciprocal_name = Column(String, default="")
        description = Column(String)
        exclusive = Column(Boolean, default=False)
        
        relationship_instances = relationship(
            'UserRelationship',
            foreign_keys='UserRelationship.relationship_type_id',
            back_populates='relationship_type'
        )

        def to_dict(self):
            """
            Converts the relationship type instance into a dictionary format.
            """

            relationship_dict = {
                "id":self.id,
                "name":self.name,
                "reciprocal_name":self.reciprocal_name,
                "description":self.description,
                "exclusive":self.exclusive,
            }

            return relationship_dict


    class UserRelationship(Base):
        __tablename__ = 'user_relationships'
        id = Column(Integer, primary_key=True)
        user_id = Column(Integer, ForeignKey('user.id'))
        related_user_id = Column(Integer, ForeignKey('user.id'))
        relationship_type_id = Column(Integer, ForeignKey('relationship_types.id'))

        user = relationship("User", foreign_keys=[user_id], back_populates="relationships")
        related_user = relationship("User", foreign_keys=[related_user_id], back_populates="received_relationships")
        relationship_type = relationship("RelationshipType",foreign_keys=[relationship_type_id], back_populates="relationship_instances")

        def to_dict(self):
            """
            Converts the user relationship instance into a dictionary format.
            """

            relationship_dict = {
                "id":self.id,
                "user":self.user.to_dict(just_the_basics=True),
                "related_user":self.related_user.to_dict(just_the_basics=True),
                "relationship_type":self.relationship_type.to_dict(),
            }

            return relationship_dict



    # Allow custom approval chains to be defined here
    class SignatureRoles(Base):
        __tablename__ = 'signature_roles'
        id = Column(Integer, primary_key=True)
        role_name = Column(String, unique=True)
        role_method = Column(Enum('signature', 'relationship', 'group', 'static'), default='relationship')
        form_name = Column(String)
        preceded_by_id = Column(Integer, ForeignKey('signature_roles.id'), nullable=True)
        succeeded_by_id = Column(Integer, ForeignKey('signature_roles.id'),nullable=True)
        on_approve = Column(Enum('step_up', 'finish'), default='finish')
        on_deny = Column(Enum('restart', 'step_down', 'kill'), default='restart')
        on_return = Column(Enum('restart', 'step_down'), default='restart')
        comments_required = Column(Boolean, default=False)

        last_updated = Column(DateTime, nullable=False, default=tz_aware_datetime, onupdate=tz_aware_datetime)
        created_on = Column(DateTime, nullable=False, default=tz_aware_datetime)

        preceded_by = relationship("SignatureRoles", remote_side=[id], foreign_keys=[preceded_by_id], backref="preceding_role")
        succeeded_by = relationship("SignatureRoles", remote_side=[id], foreign_keys=[succeeded_by_id], backref="succeeding_role")

        group_target = Column(Integer, ForeignKey('group.id'))
        relationship_target = Column(Integer, ForeignKey('relationship_types.id'))
        static_target = Column(Integer, ForeignKey('user.id'))

        def to_dict(self):
            """
            Converts a signature role into a dictionary format.
            """

            role_dict = {
                "id":self.id,
                "role_name":self.role_name,
                "role_method":self.role_method,
                "form_name":self.form_name,
                "on_approve":self.on_approve,
                "on_deny":self.on_deny,
                "on_return":self.on_return,
                "comments_required":self.comments_required,
                "last_updated":self.last_updated,
                "created_on":self.created_on,
                "preceded_by":self.preceded_by,
                "succeeded_by":self.succeeded_by,
            }

            # We exclude the `signature` target option, which is targeted at the
            # owning user..
            if self.role_method == "group":
                role_dict['target'] = self.group_target
            elif self.role_method == "relationship":
                role_dict['target'] = self.relationship_target
            elif self.role_method == "static":
                role_dict['target'] = self.static_target

            return role_dict


    # Create a custom Signing class from sqlalchemy_signing and add a user field
    Signing = create_signing_class(Base, datetime_override=tz_aware_datetime, email_foreign_key_mapping="user.email")
    Signing.user = relationship('User', back_populates='signing_keys', foreign_keys=[Signing.email])

    # Add the relationship to the User class
    User.signing_keys = relationship(
        'Signing',
        foreign_keys=[Signing.email],
        back_populates='user'
    )

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

    return { # This approach is a little bit of syntactic salt to ensure we 
        "User": User, # purposefully merge new models into the mainline code.
        "PasswordReuse": PasswordReuse,
        "Group": Group,
        "TransactionLog": TransactionLog,
        "SignatureRoles": SignatureRoles,
        "Signing": Signing,
        "RelationshipType": RelationshipType,
        "UserRelationship": UserRelationship,
    }, SessionLocal, signatures, engine
