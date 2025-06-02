"""Sample file with performance issues for PyCQ analyzer testing."""

import time
import string
import random


# CWE-1046: Creation of Immutable Text Using String Concatenation
def build_large_string(size):
    """Build a large string inefficiently."""
    # Inefficient string concatenation
    result = ""
    for i in range(size):
        result = result + str(i) + " "  # Inefficient: creates a new string each time
    return result


# More efficient alternative would be:
def build_large_string_efficient(size):
    """Build a large string efficiently using list and join."""
    parts = []
    for i in range(size):
        parts.append(str(i))
    return " ".join(parts)


# CWE-1050: Excessive Platform Resource Consumption within a Loop
def resource_intensive_loop(iterations):
    """Loop with excessive resource consumption."""
    result = []
    for i in range(iterations):
        # Create a large random string on each iteration
        random_str = "".join(random.choices(string.ascii_letters, k=10000))
        # Sleep briefly to simulate work
        time.sleep(0.001)
        # Append to result (growing memory usage)
        result.append(random_str)
    return len("".join(result))


# CWE-1089: Large Data with Excessive Indices
class InMemoryDatabase:
    """In-memory database simulation with excessive indexing."""

    def __init__(self):
        """Initialize database with data and excessive indices."""
        self.data = []
        # Multiple indices (excessive for a small dataset)
        self.index_by_id = {}
        self.index_by_name = {}
        self.index_by_age = {}
        self.index_by_email = {}
        self.index_by_city = {}
        self.index_by_state = {}

    def add_record(self, record):
        """Add a record with updating all indices."""
        self.data.append(record)

        # Update all indices (expensive operation)
        self.index_by_id[record.get("id")] = record
        self.index_by_name[record.get("name")] = record
        self.index_by_age[record.get("age")] = record
        self.index_by_email[record.get("email")] = record
        self.index_by_city[record.get("city")] = record
        self.index_by_state[record.get("state")] = record

    def find_by_id(self, id_value):
        """Find record by ID."""
        return self.index_by_id.get(id_value)

    def find_by_name(self, name):
        """Find record by name."""
        return self.index_by_name.get(name)


# CWE-1043: Data Element Aggregating Excessive Non-Primitive Elements
class ComplexDataStructure:
    """Class with excessively nested non-primitive data types."""

    def __init__(self):
        """Initialize complex data structure."""
        self.level1 = {
            "data": {},
            "level2": {
                "data": {},
                "level3": {
                    "data": {},
                    "level4": {
                        "data": {},
                        "level5": {
                            "data": {},
                            "level6": {
                                "data": {},
                            },
                        },
                    },
                },
            },
        }

    def set_data(self, level, key, value):
        """Set data at specific level."""
        if level == 1:
            self.level1["data"][key] = value
        elif level == 2:
            self.level1["level2"]["data"][key] = value
        elif level == 3:
            self.level1["level2"]["level3"]["data"][key] = value
        elif level == 4:
            self.level1["level2"]["level3"]["level4"]["data"][key] = value
        elif level == 5:
            self.level1["level2"]["level3"]["level4"]["level5"]["data"][key] = value
        elif level == 6:
            self.level1["level2"]["level3"]["level4"]["level5"]["level6"]["data"][
                key
            ] = value

    def get_data(self, level, key):
        """Get data from specific level."""
        if level == 1:
            return self.level1["data"].get(key)
        elif level == 2:
            return self.level1["level2"]["data"].get(key)
        elif level == 3:
            return self.level1["level2"]["level3"]["data"].get(key)
        elif level == 4:
            return self.level1["level2"]["level3"]["level4"]["data"].get(key)
        elif level == 5:
            return self.level1["level2"]["level3"]["level4"]["level5"]["data"].get(key)
        elif level == 6:
            return self.level1["level2"]["level3"]["level4"]["level5"]["level6"][
                "data"
            ].get(key)
        return None


# CWE-1094: Excessive Index Range Scan
def search_in_large_list(data_list, value):
    """Search in a list without proper indices."""
    # Inefficient linear search through potentially large list
    for item in data_list:
        if item.get("value") == value:
            return item
    return None


# CWE-1060: Excessive Server-Side Data Accesses
def process_user_data(user_id):
    """Process user data with excessive data access operations."""
    # This simulates multiple database calls for a single operation
    # that could be consolidated

    # Get basic info (separate call)
    user_info = get_user_info(user_id)

    # Get preferences (separate call)
    preferences = get_user_preferences(user_id)

    # Get history (separate call)
    history = get_user_history(user_id)

    # Get settings (separate call)
    settings = get_user_settings(user_id)

    # Get permissions (separate call)
    permissions = get_user_permissions(user_id)

    # Get friends (separate call)
    friends = get_user_friends(user_id)

    # Get activity (separate call)
    activity = get_user_activity(user_id)

    # Combine all data
    result = {
        "info": user_info,
        "preferences": preferences,
        "history": history,
        "settings": settings,
        "permissions": permissions,
        "friends": friends,
        "activity": activity,
    }

    return result


# Simulated data access methods
def get_user_info(user_id):
    return {"id": user_id, "name": f"User{user_id}"}


def get_user_preferences(user_id):
    return {"theme": "dark", "notifications": True}


def get_user_history(user_id):
    return {"last_login": "2023-01-01", "activities": []}


def get_user_settings(user_id):
    return {"language": "en", "timezone": "UTC"}


def get_user_permissions(user_id):
    return {"admin": False, "moderator": False}


def get_user_friends(user_id):
    return [user_id + 1, user_id + 2, user_id + 3]


def get_user_activity(user_id):
    return {"posts": [], "comments": []}
