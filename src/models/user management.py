```python
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field
from pydantic import EmailStr, validator
import re


class UserBase(SQLModel):
    """Base user model with common fields."""
    
    email: EmailStr = Field(unique=True, index=True, description="User email address")
    username: str = Field(min_length=3, max_length=50, unique=True, index=True, description="Unique username")
    first_name: str = Field(min_length=1, max_length=100, description="User's first name")
    last_name: str = Field(min_length=1, max_length=100, description="User's last name")
    is_active: bool = Field(default=True, description="Whether the user account is active")
    is_verified: bool = Field(default=False, description="Whether the user email is verified")

    @validator('username')
    def validate_username(cls, v):
        """Validate username contains only alphanumeric characters and underscores."""
        if not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must contain only letters, numbers, and underscores')
        return v


class User(UserBase, table=True):
    """User database model."""
    
    __tablename__ = "users"
    
    id: Optional[int] = Field(default=None, primary_key=True, description="User ID")
    password_hash: str = Field(description="Hashed password")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Account creation timestamp")
    updated_at: Optional[datetime] = Field(default=None, description="Last update timestamp")
    last_login: Optional[datetime] = Field(default=None, description="Last login timestamp")


class UserCreate(UserBase):
    """Model for creating a new user."""
    
    password: str = Field(min_length=8, max_length=128, description="User password")
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v


class UserRead(UserBase):
    """Model for reading user data."""
    
    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    last_login: Optional[datetime] = None


class UserUpdate(SQLModel):
    """Model for updating user data."""
    
    email: Optional[EmailStr] = None
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username contains only alphanumeric characters and underscores."""
        if v is not None and not re.match(r'^[a-zA-Z0-9_]+$', v):
            raise ValueError('Username must contain only letters, numbers, and underscores')
        return v


class UserPasswordUpdate(SQLModel):
    """Model for updating user password."""
    
    current_password: str = Field(description="Current password for verification")
    new_password: str = Field(min_length=8, max_length=128, description="New password")
    
    @validator('new_password')
    def validate_password(cls, v):
        """Validate password strength."""
        if not re.search(r'[A-Z]', v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not re.search(r'[a-z]', v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not re.search(r'\d', v):
            raise ValueError('Password must contain at least one digit')
        return v
```