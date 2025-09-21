```python
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
import bcrypt
from typing import Dict, List, Optional


class User:
    """User model class"""
    def __init__(self, user_id: int, username: str, email: str, password_hash: str, 
                 created_at: datetime = None, is_active: bool = True):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.created_at = created_at or datetime.now()
        self.is_active = is_active


class UserRepository:
    """Mock user repository"""
    def find_by_id(self, user_id: int) -> Optional[User]:
        pass
    
    def find_by_username(self, username: str) -> Optional[User]:
        pass
    
    def find_by_email(self, email: str) -> Optional[User]:
        pass
    
    def save(self, user: User) -> User:
        pass
    
    def delete(self, user_id: int) -> bool:
        pass
    
    def find_all(self) -> List[User]:
        pass


class UserManagement:
    """User management component"""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository
    
    def create_user(self, username: str, email: str, password: str) -> User:
        """Create a new user"""
        if self.user_repository.find_by_username(username):
            raise ValueError("Username already exists")
        
        if self.user_repository.find_by_email(email):
            raise ValueError("Email already exists")
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user = User(
            user_id=None,
            username=username,
            email=email,
            password_hash=password_hash
        )
        
        return self.user_repository.save(user)
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self.user_repository.find_by_id(user_id)
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        return self.user_repository.find_by_username(username)
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password"""
        user = self.user_repository.find_by_username(username)
        if not user or not user.is_active:
            return None
        
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return user
        
        return None
    
    def update_user(self, user_id: int, **kwargs) -> Optional[User]:
        """Update user information"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return None
        
        for key, value in kwargs.items():
            if hasattr(user, key) and key != 'user_id':
                setattr(user, key, value)
        
        return self.user_repository.save(user)
    
    def delete_user(self, user_id: int) -> bool:
        """Delete user by ID"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return False
        
        return self.user_repository.delete(user_id)
    
    def deactivate_user(self, user_id: int) -> bool:
        """Deactivate user account"""
        user = self.update_user(user_id, is_active=False)
        return user is not None
    
    def activate_user(self, user_id: int) -> bool:
        """Activate user account"""
        user = self.update_user(user_id, is_active=True)
        return user is not None
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Change user password"""
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return False
        
        if not bcrypt.checkpw(old_password.encode('utf-8'), user.password_hash.encode('utf-8')):
            return False
        
        new_password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        updated_user = self.update_user(user_id, password_hash=new_password_hash)
        return updated_user is not None
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        return self.user_repository.find_all()


@pytest.fixture
def mock_user_repository():
    """Fixture for mock user repository"""
    return Mock(spec=UserRepository)


@pytest.fixture
def user_management(mock_user_repository):
    """Fixture for user management instance"""
    return UserManagement(mock_user_repository)


@pytest.fixture
def sample_user():
    """Fixture for sample user"""
    return User(
        user_id=1,
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$hashed_password",
        created_at=datetime(2023, 1, 1),
        is_active=True
    )


@pytest.fixture
def sample_users():
    """Fixture for multiple sample users"""
    return [
        User(1, "user1", "user1@example.com", "$2b$12$hash1", datetime(2023, 1, 1), True),
        User(2, "user2", "user2@example.com", "$2b$12$hash2", datetime(2023, 1, 2), True),
        User(3, "user3", "user3@example.com", "$2b$12$hash3", datetime(2023, 1, 3), False)
    ]


class TestUserManagement:
    """Test cases for UserManagement class"""
    
    def test_create_user_success(self, user_management, mock_user_repository):
        """Test successful user creation"""
        mock_user_repository.find_by_username.return_value = None
        mock_user_repository.find_by_email.return_value = None
        
        created_user = User(1, "newuser", "new@example.com", "hashed_password")
        mock_user_repository.save.return_value = created_user
        
        with patch('bcrypt.hashpw') as mock_hashpw, patch('bcrypt.gensalt') as mock_gensalt:
            mock_gensalt.return_value = b'salt'
            mock_hashpw.return_value = b'hashed_password'
            
            result = user_management.create_user("newuser", "new@example.com", "password123")
        
        assert result == created_user
        mock_user_repository.find_by_username.assert_called_once_with("newuser")
        mock_user_repository.find_by_email.assert_called_once_with("new@example.com")
        mock_user_repository.save.assert_called_once()
    
    def test_create_user_username_exists(self, user_management, mock_user_repository, sample_user):
        """Test user creation with existing username"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        with pytest.raises(ValueError, match="Username already exists"):
            user_management.create_user("testuser", "new@example.com", "password123")
    
    def test_create_user_email_exists(self, user_management, mock_user_repository, sample_user):
        """Test user creation with existing email"""
        mock_user_repository.find_by_username.return_value = None
        mock_user_repository.find_by_email.return_value = sample_user
        
        with pytest.raises(ValueError, match="Email already exists"):
            user_management.create_user("newuser", "test@example.com", "password123")
    
    def test_get_user_by_id_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user retrieval by ID"""
        mock_user_repository.find_by_id.return_value = sample_user
        
        result = user_management.get_user_by_id(1)
        
        assert result == sample_user
        mock_user_repository.find_by_id.assert_called_once_with(1)
    
    def test_get_user_by_id_not_found(self, user_management, mock_user_repository):
        """Test user retrieval by ID when user not found"""
        mock_user_repository.find_by_id.return_value = None
        
        result = user_management.get_user_by_id(999)
        
        assert result is None
        mock_user_repository.find_by_id.assert_called_once_with(999)
    
    def test_get_user_by_username_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user retrieval by username"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = user_management.get_user_by_username("testuser")
        
        assert result == sample_user
        mock_user_repository.find_by_username.assert_called_once_with("testuser")
    
    def test_get_user_by_username_not_found(self, user_management, mock_user_repository):
        """Test user retrieval by username when user not found"""
        mock_user_repository.find_by_username.return_value = None
        
        result = user_management.get_user_by_username("nonexistent")
        
        assert result is None
        mock_user_repository.find_by_username.assert_called_once_with("nonexistent")
    
    def test_authenticate_user_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user authentication"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        with patch('bcrypt.checkpw') as mock_checkpw:
            mock_checkpw.return_value = True
            
            result = user_management.authenticate_user("testuser", "password123")
        
        assert result == sample_user
        mock_checkpw.assert_called_once_with(b'password123', b'$2b$12$hashed_password')
    
    def test_authenticate_user_wrong_password(self, user_management, mock_user_repository, sample_user):
        """Test user authentication with wrong password"""
        mock_user_repository.find_by_username.return_value = sample_user
        
        with patch('bcrypt.checkpw') as mock_checkpw:
            mock_checkpw.return_value = False
            
            result = user_management.authenticate_user("testuser", "wrongpassword")
        
        assert result is None
    
    def test_authenticate_user_not_found(self, user_management, mock_user_repository):
        """Test user authentication when user not found"""
        mock_user_repository.find_by_username.return_value = None
        
        result = user_management.authenticate_user("nonexistent", "password123")
        
        assert result is None
    
    def test_authenticate_user_inactive(self, user_management, mock_user_repository, sample_user):
        """Test user authentication when user is inactive"""
        sample_user.is_active = False
        mock_user_repository.find_by_username.return_value = sample_user
        
        result = user_management.authenticate_user("testuser", "password123")
        
        assert result is None
    
    def test_update_user_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user update"""
        mock_user_repository.find_by_id.return_value = sample_user
        updated_user = User(1, "testuser", "newemail@example.com", "$2b$12$hashed_password")
        mock_user_repository.save.return_value = updated_user
        
        result = user_management.update_user(1, email="newemail@example.com")
        
        assert result == updated_user
        assert sample_user.email == "newemail@example.com"
        mock_user_repository.save.assert_called_once_with(sample_user)
    
    def test_update_user_not_found(self, user_management, mock_user_repository):
        """Test user update when user not found"""
        mock_user_repository.find_by_id.return_value = None
        
        result = user_management.update_user(999, email="newemail@example.com")
        
        assert result is None
        mock_user_repository.save.assert_not_called()
    
    def test_update_user_ignore_user_id(self, user_management, mock_user_repository, sample_user):
        """Test user update ignores user_id field"""
        mock_user_repository.find_by_id.return_value = sample_user
        mock_user_repository.save.return_value = sample_user
        
        user_management.update_user(1, user_id=999, email="newemail@example.com")
        
        assert sample_user.user_id == 1  # Should not change
        assert sample_user.email == "newemail@example.com"
    
    def test_delete_user_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user deletion"""
        mock_user_repository.find_by_id.return_value = sample_user
        mock_user_repository.delete.return_value = True
        
        result = user_management.delete_user(1)
        
        assert result is True
        mock_user_repository.delete.assert_called_once_with(1)
    
    def test_delete_user_not_found(self, user_management, mock_user_repository):
        """Test user deletion when user not found"""
        mock_user_repository.find_by_id.return_value = None
        
        result = user_management.delete_user(999)
        
        assert result is False
        mock_user_repository.delete.assert_not_called()
    
    def test_deactivate_user_success(self, user_management, mock_user_repository, sample_user):
        """Test successful user deactivation"""
        mock_user_repository.find_by_id.return_value = sample_user
        deactivated_user = User(1, "testuser", "test@example.com", "$2b$12$hashed_password", is_active=False)
        mock_user_repository.save.return_value = deactivated_user
        
        result = user_management.deactivate_user(1)
        
        assert result is True
        assert sample_user.is_active is False
    
    def test_deactivate_user_not_found(self, user_management, mock_user_repository):
        """Test user deactivation when user not found"""
        mock_user_repository.find_by_id.return_value = None
        
        result = user_management.deactivate_user(999)
        
        assert result is False
    
    def test_activate_user_success(self, user_management, mock_user_repository,