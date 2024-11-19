import os
import pandas as pd
from typing import Tuple, Optional
from dataclasses import dataclass
import streamlit as st
import logging
import random
import string
import time
from datetime import datetime
from streamlit_option_menu import option_menu

# Constants
SESSION_TIMEOUT_MINUTES = 30
ALLOWED_FILE_TYPES = ["pdf", "docx"]
DEPARTMENTS = ["Operations", "Finance", "Marketing"]
DOCUMENT_TYPES = ["General Guidelines", "Airlines Guidelines"]
BASE_UPLOAD_DIR = "uploads"
EMPLOYEE_DATA_FILE = "employee_data.csv"  # Path to store employee data
UPLOADED_DOCS_FILE = "uploaded_docs.csv"  # Path to store uploaded document data
FLIGHTS = ["E-190", "B737-NG/MAX", "A320", "B7474"]

# Custom CSS for light theme and modern look
st.markdown("""
<style>
    /* Overall App Background and Text Color */
    .stApp {
        background-color: #ADD8E6; /* Light grey background */
        color: #000000; /* Black text */
    }
    /* Text Input Fields */
    .stTextInput > div > div > input {
        background-color: #FFFFFF; /* White input background */
        color: #000000; /* Black text */
        border: 2px solid #808080; /* Light grey border */
        border-radius: 4px;
        padding: 8px 12px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        outline: none;  /* Remove default focus outline */
    }
    /* Buttons */
    .stButton > button {
        background-color: #008CBA; /* Blue background */
        color: #FFFFFF; /* White text */
        border: none;
        padding: 10px 24px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
        margin: 4px 2px;
        cursor: pointer;
        border-radius: 4px;
    }
    /* Sidebar */
    .stSidebar {
        background-color: #ADD8E6; /* White sidebar */
        color: #000000; /* Black text */
        border-right: 1px solid #CCCCCC; /* Light grey border */
    }
    /* Sidebar Widgets */
    .stSidebar .stButton > button {
        background-color: #ADD8E6; /* Consistent button color in sidebar */
        color: #FFFFFF;

    }
    /* Messages or Info Boxes */
    .stMessage {
        background-color: #E0E0E0; /* Light grey message background */
        color: #000000; /* Black text */
        border-left: 4px solid #008CBA; /* Blue border for emphasis */
        padding: 10px;
        border-radius: 4px;
    }
    /* Headers */
    .stApp h1, .stApp h2, .stApp h3, .stApp h4, .stApp h5, .stApp h6 {
        color: #333333; /* Dark grey headers */
    }
    /* Selectbox/Dropdown Styling */
    .stSelectbox > div > div > select {
        background-color: #FFFFFF;
        color: #000000;
        border: 2px solid #808080;
        border-radius: 4px;
        padding: 8px 12px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);  /* Enhanced shadow */
    }
    /* Selectbox Container */
    .stSelectbox > div {
        border: 2px solid #808080;  /* Matching border */
        border-radius: 4px;
        background-color: #FFFFFF;
    }

    /* Selectbox on Hover */
    .stSelectbox > div:hover {
        border-color: #008CBA;  /* Blue border on hover */
    }

    /* Selectbox when Focused */
    .stSelectbox > div[data-baseweb="select"] > div:focus {
        border-color: #008CBA;
        box-shadow: 0 0 0 2px rgba(0, 140, 186, 0.2);  /* Blue glow effect */
    }
    /* Links */
    .stApp a {
        color: #008CBA; /* Blue links */
        text-decoration: none;
    }
    .stApp a:hover {
        text-decoration: underline;
    }
    /* Tables */
    .stApp table {
        background-color: #FFFFFF !important; /* White background */
        color: #000000; /* Black text for readability */
        border-radius: 4px;
        padding: 8px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1); /* Optional shadow for a card effect */
    }
    .stApp th, .stApp td {
        border: 1px solid #CCCCCC;
        padding: 8px;
        text-align: left;
    }
    .stApp th {
        background-color: #F2F2F2;
    }
    /* Adjust Scrollbar (Optional) */
    ::-webkit-scrollbar {
        width: 12px;
    }
    ::-webkit-scrollbar-track {
        background: #F5F5F5;
    }
    ::-webkit-scrollbar-thumb {
        background-color: #CCCCCC;
        border-radius: 6px;
        border: 3px solid #F5F5F5;
    }
</style>
""", unsafe_allow_html=True)

# Add new constant for theme storage
THEME_SETTINGS_FILE = "theme_settings.json"

import bcrypt

def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


class ThemeManager:
    """Class to handle theme-related operations."""

    @staticmethod
    def initialize_theme():
        """Initialize theme settings in session state."""
        if "theme" not in st.session_state:
            st.session_state.theme = "light"
        ThemeManager.apply_theme(st.session_state.theme)

    @staticmethod
    def toggle_theme():
        """Toggle between light and dark themes."""
        # Toggle the theme value in session state
        st.session_state.theme = "dark" if st.session_state.theme == "light" else "light"
        # Apply new theme styles
        ThemeManager.apply_theme(st.session_state.theme)

    @staticmethod
    def apply_theme(theme):
        """Apply theme-specific styles."""
        if theme == "dark":
            st.markdown("""
                    <style>
                        /* Dark theme styles */
                        .stApp {
                            background-color: #1E1E1E;
                            color: #FFFFFF;
                        }
                        /* Form Labels in dark mode */
                        .css-81oif8, .css-1aehpvj, .css-16huue1, .css-a51556 {
                            color: #FFFFFF !important;
                        }
                        .stTextInput > div > div > input {
                            background-color: #2D2D2D;
                            color: #FFFFFF;
                            border-color: #404040;
                        }
                        .stTextInput label {
                            color: var(--text-color);
                        }
                        .stTextInput input::placeholder {
                            color: rgba(255,255,255,0.6) !important;
                        }
                        .stTextInput input {
                            color: var(--text-color) !important;
                        }
                        .stTabs [data-baseweb="tab-list"] button[role="tab"] {
                            color: var(--text-color);
                        }
                        .stSelectbox > div > div > select {
                            background-color: #2D2D2D;
                            color: #FFFFFF;
                            border-color: #404040;
                        }
                        .stSelectbox label,
                        .stSlider label,
                        .stTextInput label,
                        .stTextarea label,
                        .stNumberInput label,
                        .stDateInput label,
                        .stTimeInput label {
                         color: white !important;    
                        }
                        .stButton > button {
                            background-color: #0E4C92;
                            color: #FFFFFF;
                        }
                        .stSidebar {
                            background-color: #2D2D2D;
                            color: #FFFFFF;
                        }
                        /* Tables in dark mode */
                        .stTable {
                            background-color: #2D2D2D;
                            color: #FFFFFF;
                        }
                        th {
                            background-color: #404040 !important;
                            color: #FFFFFF !important;
                        }
                        td {
                            background-color: #2D2D2D !important;
                            color: #FFFFFF !important;
                        }
                        /* Headers in dark mode */
                        h1, h2, h3, h4, h5, h6 {
                            color: #FFFFFF !important;
                        }
                        /* Links in dark mode */
                        a {
                            color: #6EA8FE !important;
                        }
                        /* Form elements in dark mode */
                        .stMarkdown {
                            color: #FFFFFF;
                        }
                        /* File uploader in dark mode */
                        .uploadedFile {
                            color: #FFFFFF !important;
                        }
                        /* Select box text in dark mode */
                        .css-1d0tddh {
                            color: #FFFFFF !important;
                        }
                    </style>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
                    <style>
                        /* Light theme styles */
                        .stApp {
                            background-color: #ADD8E6;
                            color: #000000;
                        }
                        /* Form Labels in light mode */
                        .css-81oif8, .css-1aehpvj, .css-16huue1, .css-a51556 {
                            color: #000000 !important;
                        }
                        .stTextInput > div > div > input {
                            background-color: #FFFFFF;
                            color: #000000;
                            border: 2px solid #808080;
                        }
                        .stSelectbox > div > div > select {
                            background-color: #FFFFFF;
                            color: #000000;
                            border: 2px solid #808080;
                        }
                        .stButton > button {
                            background-color: #008CBA;
                            color: #FFFFFF;
                        }
                        .stSidebar {
                            background-color: #ADD8E6;
                            color: #000000;
                        }
                        /* Tables in light mode */
                        .stTable {
                            background-color: #FFFFFF !important;
                            color: #000000 !important;
                        }
                        th {
                            background-color: #F2F2F2 !important;
                            color: #000000 !important;
                        }
                        td {
                            background-color: #FFFFFF !important;
                            color: #000000 !important;
                        }
                        /* Headers in light mode */
                        h1, h2, h3, h4, h5, h6 {
                            color: #333333 !important;
                        }
                        /* Links in light mode */
                        a {
                            color: #008CBA !important;
                        }
                        /* Form elements in light mode */
                        .stMarkdown {
                            color: #000000;
                        }
                        /* File uploader in light mode */
                        .uploadedFile {
                            color: #000000 !important;
                        }
                        /* Select box text in light mode */
                        .css-1d0tddh {
                            color: #000000 !important;
                        }
                    </style>
                """, unsafe_allow_html=True)

@dataclass
class UserCredentials:
    """Data class to store user credentials and information."""
    employee_code: str
    password: str


@dataclass
class UserData:
    """Data class to store admin data from environment."""
    admin_employee_codes: list
    admin_passwords: list
    admin_names: list

    @classmethod
    def from_env(cls) -> 'UserData':
        """Create UserData instance from environment variables."""
        return cls(
            admin_employee_codes=os.getenv("ADMIN_CODES", "").split(","),
            admin_passwords=os.getenv("ADMIN_PASSWORDS", "").split(","),
            admin_names=os.getenv("ADMIN_NAMES", "").split(",")
        )

def generate_temp_password():
    """Generate a random 8-character temporary password."""
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(8))

class SessionManager:
    """Class to handle session management."""

    @staticmethod
    def initialize_session_state():
        """Initialize session state variables."""
        st.session_state.setdefault("logged_in", False)
        st.session_state.setdefault("login_time", None)
        st.session_state.setdefault("user_name", None)

    @staticmethod
    def clear_session():
        """Clear all session state variables and redirect to login page."""
        st.session_state.logged_in = False
        st.session_state.login_time = None
        st.session_state.user_name = None
        st.session_state.page = "login"


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='password_changes.log'
)


@dataclass
class PasswordChangeResult:
    """Data class to store password change operation results"""
    success: bool
    message: str
    error_code: Optional[str] = None


class PasswordManager:
    """Class to handle password-related operations on first time login"""

    def __init__(self, employee_data_file: str):
        self.employee_data_file = employee_data_file
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Ensure the employee data file exists"""
        if not os.path.exists(self.employee_data_file):
            raise FileNotFoundError(f"Employee data file not found: {self.employee_data_file}")

    def _validate_passwords(self, temp_password: str, new_password: str, confirm_password: str) -> Tuple[bool, str]:
        """
        Validate password requirements
        Returns: (is_valid: bool, error_message: str)
        """
        # Strip all passwords for consistent comparison
        temp_password = str(temp_password).strip()
        new_password = str(new_password).strip()
        confirm_password = str(confirm_password).strip()

        if not all([temp_password, new_password, confirm_password]):
            return False, "All password fields are required."

        if new_password != confirm_password:
            return False, "New password and confirm password do not match."

        if len(new_password) < 8:
            return False, "New password must be at least 8 characters long."

        # Add more password complexity requirements as needed
        has_number = any(char.isdigit() for char in new_password)
        has_letter = any(char.isalpha() for char in new_password)
        if not (has_number and has_letter):
            return False, "New password must contain both letters and numbers."

        return True, ""

    def change_password(self, employee_code: str, temp_password: str, new_password: str,
                        confirm_password: str) -> PasswordChangeResult:
        """
        Change user password with validation and error handling
        """
        try:
            # Validate passwords
            is_valid, error_message = self._validate_passwords(temp_password, new_password, confirm_password)
            if not is_valid:
                return PasswordChangeResult(False, error_message, "VALIDATION_ERROR")

            # Read employee data
            df = pd.read_csv(self.employee_data_file)

            # Normalize data
            df['Employee Code'] = df['Employee Code'].astype(str).str.strip()
            df['Password'] = df['Password'].astype(str).str.strip()
            df['Is Temp Password'] = pd.to_numeric(df['Is Temp Password'], errors='coerce').fillna(0).astype(int)

            employee_code = str(employee_code).strip()
            temp_password = str(temp_password).strip()
            new_password = str(new_password).strip()

            # Find the employee
            employee_mask = df['Employee Code'] == employee_code
            if not employee_mask.any():
                return PasswordChangeResult(False, "Employee not found.", "EMPLOYEE_NOT_FOUND")

            # Verify temporary password
            stored_password = df.loc[employee_mask, 'Password'].iloc[0].strip()
            if stored_password != temp_password:
                return PasswordChangeResult(False, "Invalid temporary password.", "INVALID_TEMP_PASSWORD")

            # Update password and status
            df.loc[employee_mask, 'Password'] = hash_password(new_password)
            df.loc[employee_mask, 'Is Temp Password'] = 0
            df.loc[employee_mask, 'Password Last Changed'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Save changes
            df.to_csv(self.employee_data_file, index=False)

            # Clear session after successful password change
            SessionManager.clear_session()

            return PasswordChangeResult(True, "Password changed successfully.", None)

        except Exception as e:
            error_message = f"Failed to change password: {str(e)}"
            return PasswordChangeResult(False, error_message, "SYSTEM_ERROR")

class ChangePasswordInterface:
    """Interface for handling password changes."""

    def __init__(self):
        self.employee_data_file = EMPLOYEE_DATA_FILE  # Use the global constant
        self.password_manager = PasswordManager(self.employee_data_file)

    def render(self):
        st.title("Change Password")

        if not st.session_state.get("must_change_password", False):
            st.warning("You are not required to change your password at this time.")
            st.stop()

        with st.form("password_change_form"):
            temp_password = st.text_input("Temporary Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            submitted = st.form_submit_button("Change Password")

            if submitted:
                if not all([temp_password, new_password, confirm_password]):
                    st.error("All fields are required.")
                    return

                result = self.password_manager.change_password(
                    st.session_state.employee_code,
                    temp_password,
                    new_password,
                    confirm_password
                )

                if result.success:
                    st.success(result.message)
                    st.info("Please login with your new password.")
                    # Clear session after successful password change
                    SessionManager.clear_session()
                    # Force a rerun to update the interface
                    st.rerun()
                else:
                    st.error(result.message)

class AdminPasswordManager:
    """Class to handle admin password changes."""

    @staticmethod
    def change_admin_password(current_password: str, new_password: str, confirm_password: str) -> Tuple[bool, str]:
        """
        Change admin password with validation
        Returns: (success: bool, message: str)
        """
        try:
            if not all([current_password, new_password, confirm_password]):
                return False, "All password fields are required."

            if new_password != confirm_password:
                return False, "New password and confirm password do not match."

            if len(new_password) < 8:
                return False, "New password must be at least 8 characters long."

            # Validate current password against env variable
            admin_passwords = os.getenv("ADMIN_PASSWORDS", "").split(",")
            admin_codes = os.getenv("ADMIN_CODES", "").split(",")

            idx = admin_codes.index(st.session_state.employee_code)
            if current_password != admin_passwords[idx]:
                return False, "Current password is incorrect."

            # Update password in environment
            admin_passwords[idx] = new_password
            os.environ["ADMIN_PASSWORDS"] = ",".join(admin_passwords)

            # Log password change
            logging.info(f"Admin password changed for employee code: {st.session_state.employee_code}")

            return True, "Password changed successfully."

        except Exception as e:
            logging.error(f"Error changing admin password: {str(e)}")
            return False, f"Error changing password: {str(e)}"


class SettingsInterface:
    """Class to handle settings interface."""

    def __init__(self):
        self.password_manager = AdminPasswordManager()
        self.theme_manager = ThemeManager()

    def render(self):
        """Render the complete settings interface."""
        st.title("Settings")
        # Create tabs for different settings sections
        tab1, tab2 = st.tabs(["Password Settings", "Theme Settings"])

        with tab1:
            self.render_password_change()

        with tab2:
            self.render_theme_settings()

    def render_password_change(self):
        """Render password change form."""
        st.subheader("Change Password")

        with st.form("admin_password_change_form"):
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            if st.form_submit_button("Change Password"):
                success, message = self.password_manager.change_admin_password(
                    current_password, new_password, confirm_password
                )
                if success:
                    st.success(message)
                    # Clear session after password change
                    SessionManager.clear_session()
                    st.rerun()
                else:
                    st.error(message)

    def render_theme_settings(self):
        """Render theme settings."""
        st.subheader("Theme Settings")
        current_theme = st.session_state.theme
        st.write(f"Current theme: {current_theme.capitalize()}")

        if st.button(f"Switch to {('Dark' if current_theme == 'light' else 'Light')} Theme"):
            self.theme_manager.toggle_theme()

class NormalUserPasswordManager:
    """Class to handle normal user password changes."""

    def __init__(self):
        self.employee_data_file = EMPLOYEE_DATA_FILE

    def change_password(self, employee_code: str, current_password: str, new_password: str, confirm_password: str) -> \
    Tuple[bool, str]:
        """Change normal user password with validation."""
        try:
            if not all([current_password, new_password, confirm_password]):
                return False, "All password fields are required."

            if new_password != confirm_password:
                return False, "New password and confirm password do not match."

            if len(new_password) < 8:
                return False, "New password must be at least 8 characters long."

            # Add password complexity check
            has_number = any(char.isdigit() for char in new_password)
            has_letter = any(char.isalpha() for char in new_password)
            if not (has_number and has_letter):
                return False, "New password must contain both letters and numbers."

            # Read employee data
            if not os.path.exists(self.employee_data_file):
                return False, "Employee database not found."

            df = pd.read_csv(self.employee_data_file)

            # Ensure all relevant columns exist
            required_columns = ['Employee Code', 'Password', 'Is Temp Password']
            if not all(col in df.columns for col in required_columns):
                return False, "Invalid employee database format."

            # Convert employee code to string and strip whitespace for comparison
            df['Employee Code'] = df['Employee Code'].astype(str).str.strip()
            employee_code = str(employee_code).strip()

            # Find the employee
            employee_mask = df['Employee Code'] == employee_code
            if not employee_mask.any():
                return False, "Employee not found."

            # Verify current password
            df['Password'] = df['Password'].astype(str).str.strip()
            stored_password = df.loc[employee_mask, 'Password'].iloc[0].strip()
            current_password = str(current_password).strip()

            if stored_password != current_password:
                return False, "Current password is incorrect."

            # Update password
            df.loc[employee_mask, 'Password'] = new_password.strip()
            df.loc[employee_mask, 'Is Temp Password'] = 0
            df.loc[employee_mask, 'Password Last Changed'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Save the entire DataFrame back to CSV
            try:
                df.to_csv(self.employee_data_file, index=False)
            except Exception as e:
                logging.error(f"Error saving to CSV: {str(e)}")
                return False, "Failed to save new password."

            # Log password change
            logging.info(f"Password changed for employee code: {employee_code}")

            return True, "Password changed successfully."

        except Exception as e:
            logging.error(f"Error changing password: {str(e)}")
            return False, f"Error changing password: {str(e)}"


class NormalUserSettingsInterface:
    """Class to handle normal user settings interface."""

    def __init__(self):
        self.password_manager = NormalUserPasswordManager()
        self.theme_manager = ThemeManager()

    def render(self):
        """Render the complete settings interface for normal users."""
        st.title("Settings")

        # Create tabs for different settings sections
        tab1, tab2 = st.tabs(["Password Settings", "Theme Settings"])

        with tab1:
            self.render_password_change()

        with tab2:
            self.render_theme_settings()

    def render_password_change(self):
        """Render password change form for normal users."""
        st.subheader("Change Password")

        with st.form("normal_user_password_change_form"):
            st.markdown("""
            #### Password Requirements:
            - At least 8 characters long
            - Must contain both letters and numbers
            """)
            current_password = st.text_input("Current Password", type="password")
            new_password = st.text_input("New Password", type="password")
            confirm_password = st.text_input("Confirm New Password", type="password")

            if st.form_submit_button("Change Password"):
                if not st.session_state.get("employee_code"):
                    st.error("Session error: Employee code not found. Please log in again.")
                    SessionManager.clear_session()
                    st.rerun()
                else:
                    success, message = self.password_manager.change_password(
                        st.session_state.employee_code,
                        current_password,
                        new_password,
                        confirm_password
                    )
                    if success:
                        st.success(message)
                        # Add a small delay before clearing session
                        time.sleep(1)
                        SessionManager.clear_session()
                        st.rerun()
                    else:
                        st.error(message)

    def render_theme_settings(self):
        """Render theme settings."""
        st.subheader("Theme Settings")
        current_theme = st.session_state.theme
        st.write(f"Current theme: {current_theme.capitalize()}")

        if st.button(f"Switch to {('Dark' if current_theme == 'light' else 'Light')} Theme"):
            self.theme_manager.toggle_theme()
            st.rerun()

class LoginInterface:
    """Class to handle login interface and authentication."""

    def __init__(self):
        self.user_data = UserData.from_env()

    def render_login_form(self) -> Optional[UserCredentials]:
        """Render login form and return credentials if submitted."""
        st.title("Flight Crew Assistant Admin Login")

        # Create columns for the image and the login form
        col1, col2 = st.columns([1, 1])

        # Image in the first column
        with col1:
            st.image("login_background1.jpg", use_container_width=True)

        # Input fields in the second column, centered
        with col2:
            employee_code = st.text_input("Employee Code", max_chars=8, placeholder="Enter your employee code")
            password = st.text_input("Password", type="password", max_chars=16, placeholder="Enter your password")
            if st.button("Login"):
                return UserCredentials(employee_code, password)

        return None

    def authenticate(self, credentials: UserCredentials) -> Tuple[bool, str, str]:
        user_data = self.user_data

        try:
            # Normalize input credentials
            employee_code = str(credentials.employee_code).strip()
            password = str(credentials.password).strip()

            # Check if the user is an admin
            if employee_code in user_data.admin_employee_codes:
                idx = user_data.admin_employee_codes.index(employee_code)
                if password == user_data.admin_passwords[idx]:
                    # Set session data for admin
                    st.session_state.logged_in = True
                    st.session_state.login_time = datetime.now()
                    st.session_state.user_name = user_data.admin_names[idx]
                    st.session_state.user_type = "admin"
                    st.session_state.page = "admin"
                    return True, "", "admin"
                return False, "Invalid password.", "admin"

        # Check if the user is a normal user

            if os.path.exists(EMPLOYEE_DATA_FILE):
                employees_df = pd.read_csv(EMPLOYEE_DATA_FILE)

                # Convert employee code to string for comparison
                employees_df['Employee Code'] = employees_df['Employee Code'].astype(str).str.strip()
                employees_df['Password'] = employees_df['Password'].astype(str).str.strip()
                employees_df['Is Temp Password'] = pd.to_numeric(employees_df['Is Temp Password'],
                                                                 errors='coerce').fillna(0).astype(int)
                employee = employees_df[employees_df["Employee Code"] == employee_code]

                if not employee.empty:
                    stored_password = str(employee["Password"].iloc[0]).strip()
                    is_temp_password = bool(employee["Is Temp Password"].iloc[0])

                    if verify_password(password, stored_password):
                        # Set common session state variables
                        st.session_state.logged_in = True
                        st.session_state.login_time = datetime.now()
                        st.session_state.user_name = employee["Name"].iloc[0]
                        st.session_state.employee_code = employee_code
                        st.session_state.user_type = "normal"

                        # Set page based on password status
                        if is_temp_password:
                            st.session_state.page = "change_password"
                            st.session_state.must_change_password = True
                        else:
                            st.session_state.page = "normal"
                            st.session_state.must_change_password = False
                        return True, "", "normal"
                    return False, "Invalid password.", "normal"
                return False, "Invalid employee code.", "normal"
            return False, "Employee database not found.", "normal"
        except Exception as e:
            st.error(f"Authentication error: {str(e)}")
            return False, f"Authentication error: {str(e)}", "normal"

# noinspection PyTypeChecker

class AdminInterface:
    """Class to handle the admin interface."""
    def __init__(self):
        self.settings_interface = SettingsInterface()
        ThemeManager.initialize_theme()
    def render(self):

        """Render the admin interface."""
        col1, col2 = st.columns([5,1])
        with col1:
            st.markdown(f"<h3 style='margin-top:0px;'>Welcome, {st.session_state.user_name}</h3>",
                        unsafe_allow_html=True)
        with col2:
            st.button("Logout", on_click=SessionManager.clear_session)

        st.sidebar.image("login_background.jpg", use_container_width=True)

        # Sidebar user information
        with st.sidebar:
            st.title("SkyLabs Developments")

            tab = option_menu(
                              menu_title="Navigation",
                              options=["My Crew Assistant", "Department", "Upload Employees", "View Employees",
                                       "View Uploaded Documents","Settings"],
                              icons=["people", "building", "upload", "eye", "file-earmark","gear"],
                              # Optional: Add relevant icons
                              menu_icon="list",  # Optional: Set menu icon style
                              default_index=0
                              )
        if tab == "Settings":
            self.settings_interface.render()
        else:
            # Handle other existing tabs...
            if tab == "My Crew Assistant":
                self.render_crew_assistant()
            elif tab == "Department":
                self.render_department_upload()
            elif tab == "Upload Employees":
                self.render_upload_employees()
            elif tab == "View Employees":
                self.render_view_employees()
            elif tab == "View Uploaded Documents":
                self.render_view_uploaded_documents()

    def render_crew_assistant(self):
        # Initialize session state
        if "chat_answers_history" not in st.session_state:
            st.session_state["chat_answers_history"] = []
        if "user_prompt_history" not in st.session_state:
            st.session_state["user_prompt_history"] = []
        if "chat_history" not in st.session_state:
            st.session_state["chat_history"] = []

        st.header("F/C Assistant - Informed Critical Decision")

        # Add some spacing
        st.write("")  # This adds a blank line for better spacing

        # Add aircraft selection with a mandatory placeholder
        aircraft_options = ["Select an aircraft", "E-190", "B737-NG/MAX", "A320", "B7474"]  # Added "B747"
        selected_aircraft = st.selectbox("Select Aircraft", options=aircraft_options)

        # Add some spacing
        st.write("")  # This adds a blank line for better spacing

        # Create two columns for a more modern layout
        col1, col2 = st.columns([4, 1])

        with col1:
            prompt = st.text_input("Prompt", placeholder="Enter your message here...")

        with col2:
            st.write("")
            if st.button("Submit", key="submit"):
                if selected_aircraft == "Select an aircraft":
                    st.warning("Please select an aircraft before submitting a prompt.")
                else:
                    user_prompt = prompt.strip()
                    if not user_prompt:
                        user_prompt = """
    Could you provide detailed examples for no go situations with various different systems inoperative, such as but not limited to APU inop, radio altimeter malfunction, auto-land inop, restricted flight level due to a specific system inop, etc., all in different scenarios with detailed explanations, please.
    """

    def render_department_upload(self):
        """Render document upload section for departments."""
        col1, _ = st.columns([4, 1])
        with col1:
            department = option_menu("Select Department", DEPARTMENTS, orientation='horizontal')
            st.subheader(f"Upload Document for {department}")
            flight_type = st.selectbox("Flight Type", FLIGHTS)
            doc_type = st.selectbox("Document Type", DOCUMENT_TYPES)
            document_name = st.text_input("Enter Document Name")
            uploaded_file = st.file_uploader("Choose a file", type=ALLOWED_FILE_TYPES)

            if uploaded_file and document_name.strip():
                doc_dir = os.path.join(BASE_UPLOAD_DIR, department.lower(), flight_type,
                                       doc_type.lower().replace(" ", "_"))
                os.makedirs(doc_dir, exist_ok=True)
                file_path = os.path.join(doc_dir, uploaded_file.name)
                with open(file_path, "wb") as f:
                    f.write(uploaded_file.getbuffer())

                # Log upload details
                new_entry = pd.DataFrame({
                    "Sl.no": [
                        1 if not os.path.exists(UPLOADED_DOCS_FILE) else len(pd.read_csv(UPLOADED_DOCS_FILE)) + 1],
                    "Department": [department],
                    "Flight Type": [flight_type],
                    "Document Type": [doc_type],
                    "File Name": [document_name],
                    "Uploaded Date": [datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
                    "File Path": [file_path]
                })
                if os.path.exists(UPLOADED_DOCS_FILE):
                    existing_data = pd.read_csv(UPLOADED_DOCS_FILE)
                    updated_data = pd.concat([existing_data, new_entry], ignore_index=True)
                else:
                    updated_data = new_entry

                # Save the updated data without the index column
                updated_data.to_csv(UPLOADED_DOCS_FILE, index=False)

                st.success("File uploaded successfully.")

    def render_upload_employees(self):
        """Render section to upload new employees."""
        col1, _ = st.columns([4, 1])
        with col1:
            st.title("Upload New Employees")
            st.markdown("""
            ### Instructions:        
            1. Upload a CSV file with the format: Employee Code, Name, Email ID, Department")
            2. Make sure there are no empty rows
            """)
            uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])

            if uploaded_file:
                try:
                    new_employees = pd.read_csv(uploaded_file, header=None)
                    new_employees.columns = ["Employee Code", "Name", "Email ID", "Department"]

                    # Basic validation
                    if new_employees.empty:
                        st.error("The uploaded file is empty.")
                        return

                    # Validate for unique employee codes
                    if len(new_employees["Employee Code"]) != len(new_employees["Employee Code"].unique()):
                        st.error("Duplicate employee code found in the uploaded file.")
                        return

                    # Generate temporary passwords and add required columns
                    new_employees["Password"] = [generate_temp_password() for _ in range(len(new_employees))]
                    new_employees["Is Temp Password"] = True
                    new_employees["Creation Date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                    # Check for existing duplicates in the employee data
                    if os.path.exists(EMPLOYEE_DATA_FILE):
                        existing_employees = pd.read_csv(EMPLOYEE_DATA_FILE)
                        duplicate_codes = existing_employees["Employee Code"].isin(new_employees["Employee Code"])
                        if duplicate_codes.any():
                            st.error("Duplicate employee code found in the existing data.")
                            return

                        updated_employees = pd.concat([existing_employees, new_employees], ignore_index=True)
                    else:
                        updated_employees = new_employees

                    # Validate department names (case-insensitive)
                    new_employees["Department"] = new_employees["Department"].str.capitalize()
                    if not new_employees["Department"].isin([d.capitalize() for d in DEPARTMENTS]).all():
                        st.error("Invalid department name found in the uploaded file.")
                        return

                    # Check if the file exists first
                    if os.path.exists(EMPLOYEE_DATA_FILE):
                        # If the file exists, read the existing data
                        existing_employees = pd.read_csv(EMPLOYEE_DATA_FILE)

                        # Concatenate the new employees with the existing ones
                        updated_employees = pd.concat([existing_employees, new_employees], ignore_index=True)
                    else:
                        # If the file doesn't exist, use the new employees data as-is
                        updated_employees = new_employees

                    # Save the updated employee data
                    updated_employees.to_csv(EMPLOYEE_DATA_FILE, index=False)

                    st.success("Employees uploaded successfully.")

                except Exception as e:
                    st.error(f"Error processing file: {e}")

    def render_view_employees(self):
        """Render section to view employees by department."""
        col1, _ = st.columns([4, 1])
        with col1:
            st.title("View Employees")
            department = st.selectbox("Select Department", ["All"] + DEPARTMENTS)
            if os.path.exists(EMPLOYEE_DATA_FILE):
                employees = pd.read_csv(EMPLOYEE_DATA_FILE)

                # Reset index before adding Sl.No
                employees.reset_index(drop=True, inplace=True)

                columns_to_display = ["Employee Code", "Name", "Email ID", "Department"]
                employees = employees[columns_to_display]

                if department != "All":
                    employees = employees[employees["Department"].str.capitalize() == department.capitalize()]
                if 'Sl.No' not in employees.columns:
                    employees.insert(0, 'Sl.no', range(1, len(employees) + 1))
                st.markdown(
                    employees.to_html(escape=False, index=False),
                    unsafe_allow_html=True
                )
            else:
                st.info("No employee data found.")

    def render_view_uploaded_documents(self):
        """Render section to view uploaded documents by department."""
        col1, _ = st.columns([5, 1])
        with col1:
            st.title("View Uploaded Documents")
            department = st.selectbox("Select Department", ["All"] + DEPARTMENTS)
            if os.path.exists(UPLOADED_DOCS_FILE):
                docs = pd.read_csv(UPLOADED_DOCS_FILE)
                docs = docs.sort_values(by="Uploaded Date", ascending=False)

                if department != "All":
                    docs = docs[docs["Department"].str.lower() == department.lower()]

                docs.reset_index(drop=True, inplace=True)

                # Remove existing Sl.No column if it exists
                if 'Sl.No' in docs.columns:
                    docs = docs.drop('Sl.No', axis=1)

                # Add new Sl.No column
                docs.insert(0, 'Sl.No', range(1, len(docs) + 1))

                # Create hyperlinks in the DataFrame
                docs['View Document'] = docs.apply(
                    lambda x: f'<a href="{x["File Path"]}" target="_blank">View {x["File Name"]}</a>',
                    axis=1
                )

                # Ensure columns exist before displaying
                required_columns = ["Sl.No", "Department", "Flight Type", "Document Type", "File Name", "Uploaded Date",
                                    "View Document"]
                missing_columns = [col for col in required_columns if col not in docs.columns]
                if missing_columns:
                    st.error(f"Missing columns in data: {', '.join(missing_columns)}")
                    return

                # Display the DataFrame with HTML
                st.markdown(
                    docs[required_columns].to_html(escape=False, index=False),
                    unsafe_allow_html=True
                )
            else:
                st.info("No uploaded documents found.")

class NormalInterface:
    def __init__(self):
        self.settings_interface = NormalUserSettingsInterface()
        ThemeManager.initialize_theme()
    def render_normal_user_interface(self):
        """Render the interface for normal users."""
        # Create columns for header layout
        col1, col2 = st.columns([5, 1])
        with col1:
            st.markdown(f"<h3 style='margin-top:0px;'>Welcome, {st.session_state.user_name}</h3>",
                    unsafe_allow_html=True)
        with col2:
            st.button("Logout", on_click=SessionManager.clear_session)

        # Add sidebar with company logo
        st.sidebar.image("login_background.jpg", use_container_width=True)

        # Sidebar navigation menu
        with st.sidebar:
            st.title("SkyLabs Developments")

            tab = option_menu(
                menu_title="Navigation",
                options=["My Crew Assistant","Settings"],
                icons=["people","gear"],
                menu_icon="list",
                default_index=0
            )
        if tab == "Settings":
            self.settings_interface.render()
        else:
            # Handle different tab views
            if tab == "My Crew Assistant":
                self.render_crew_assistant()


    def render_crew_assistant(self):
        """Render crew assistant interface"""
        st.header("F/C Assistant - Informed Critical Decision")

        # Add some spacing
        st.write("")

        # Add aircraft selection with a mandatory placeholder
        aircraft_options = ["Select an aircraft"] + FLIGHTS
        selected_aircraft = st.selectbox("Select Aircraft", options=aircraft_options)

        # Add some spacing
        st.write("")

        # Create two columns for a more modern layout
        col1, col2 = st.columns([4, 1])

        with col1:
            prompt = st.text_input("Prompt", placeholder="Enter your message here...")

        with col2:
            st.write("")
            if st.button("Submit", key="submit"):
                if selected_aircraft == "Select an aircraft":
                    st.warning("Please select an aircraft before submitting a prompt.")
                else:
                    user_prompt = prompt.strip()
                    if not user_prompt:
                        st.warning("Please enter a prompt.")



def main():
    SessionManager.initialize_session_state()

    # If not logged in, show login page
    if not st.session_state.logged_in:
        login_interface = LoginInterface()
        credentials = login_interface.render_login_form()

        if credentials:
            success, message, user_type = login_interface.authenticate(credentials)
            if success:
                st.rerun()  # Force a rerun to update the interface
            else:
                st.error(message)

    # If logged in, show appropriate interface based on user type
    else:
        if st.session_state.user_type == "admin":
            admin_interface = AdminInterface()
            admin_interface.render()
        elif st.session_state.user_type == "normal":
            if st.session_state.get("must_change_password", False):
                change_password_interface = ChangePasswordInterface()
                change_password_interface.render()
            else:
                normal_interface = NormalInterface()
                normal_interface.render_normal_user_interface()



if __name__ == "__main__":
    main()
