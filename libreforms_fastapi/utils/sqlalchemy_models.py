from datetime import datetime

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import (
    Boolean, 
    Column, 
    ForeignKey, 
    Integer,
    String, 
    DateTime,
)
from sqlalchemy.orm import relationship

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True) 
    email = Column(String(1000))
    password = Column(String(1000))
    username = Column(String(1000), unique=True)
    active = Column(Boolean)
    created_date = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True, default=datetime.utcnow)
    locked_until = Column(DateTime, nullable=True, default=datetime.utcnow)
    last_password_change = Column(DateTime, nullable=True, default=datetime.utcnow)
    failed_login_attempts = Column(Integer, default=0)
    # api_key_id = Column(Integer, ForeignKey('signing.id'), nullable=True)
    api_key = Column(String(1000), nullable=True, unique=True)
    # This opt out, if true, will exclude this user's ID and IP from the statistics
    # gathered from their usage, see https://github.com/signebedi/gita-api/issues/59.
    opt_out = Column(Boolean, nullable=False, default=True)
    site_admin = Column(Boolean, nullable=False, default=False)

    usage_log = relationship("TransactionLog", order_by="TransactionLog.id", back_populates="user")

    
# Many to one relationship with User table
class TransactionLog(Base):
    __tablename__ = 'transaction_log'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('user.id'), nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    # date = Column(Date, nullable=False, default=lambda: datetime.utcnow().date())
    endpoint = Column(String(1000))
    remote_addr = Column(String(50), nullable=True)
    query_params = Column(String(1000), nullable=True)  # Can we find a way to make this a JSON string or similar format?

    user = relationship("User", back_populates="transaction_log")
