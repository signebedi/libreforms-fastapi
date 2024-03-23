import os
from datetime import datetime
from zoneinfo import ZoneInfo

from sqlalchemy import (
    Boolean, 
    Column, 
    ForeignKey, 
    Integer,
    String, 
    DateTime,
    JSON,
)
from sqlalchemy.orm import relationship, declarative_base

from sqlalchemy_signing import create_signing_class

from libreforms_fastapi.utils.config import yield_config

_env = os.environ.get('ENVIRONMENT', 'development')
config = yield_config(_env)

Base = declarative_base()


def tz_aware_datetime():
    return datetime.now(config.TIMEZONE)

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True) 
    email = Column(String(1000))
    password = Column(String(1000))
    username = Column(String(1000), unique=True)
    active = Column(Boolean)
    created_date = Column(DateTime, nullable=False, default=tz_aware_datetime)
    last_login = Column(DateTime, nullable=True, default=tz_aware_datetime)
    locked_until = Column(DateTime, nullable=True, default=tz_aware_datetime)
    last_password_change = Column(DateTime, nullable=True, default=tz_aware_datetime)
    failed_login_attempts = Column(Integer, default=0)
    # api_key_id = Column(Integer, ForeignKey('signing.id'), nullable=True)
    api_key = Column(String(1000), nullable=True, unique=True)
    # This opt out, if true, will exclude this user's ID and IP from the statistics
    # gathered from their usage, see https://github.com/signebedi/gita-api/issues/59.
    opt_out = Column(Boolean, nullable=False, default=False)
    site_admin = Column(Boolean, nullable=False, default=False)

    transaction_log = relationship("TransactionLog", order_by="TransactionLog.id", back_populates="user")


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

# Allow admins to define custom groups, see
# https://github.com/signebedi/libreforms-fastapi/issues/22
class Group(Base):
    __tablename__ = 'group'
    id = Column(Integer, primary_key=True)
    name = Column(String(1000), unique=True)
    permissions = Column(JSON)

# Allow custom approval chains to be defined here
class ApprovalChains(Base):
    __tablename__ = 'approval_chains'
    id = Column(Integer, primary_key=True)
    form_name = Column(String(1000))
    apply_to_single_group = Column(String(100), nullable=True) # Maybe we allow admins to route approvals based on the group of the sender...
    send_to_users_manager = Column(Boolean) # I think that this is probably going to be difficult to implement ...


# Create a custom Signing class from sqlalchemy_signing
Signing = create_signing_class(Base, tz_aware_datetime)