"""Sample file with reliability issues for PyCQ analyzer testing."""

import threading


# CWE-476: NULL Pointer Dereference (Python equivalent)
def null_pointer_dereference(obj):
    """Try to access attribute on None."""
    # This will raise AttributeError if obj is None
    return obj.attribute


# CWE-252: Unchecked Return Value
def unchecked_return_value():
    """Function that doesn't check return values."""
    result = risky_operation()
    # Should check if result is valid before proceeding
    process_data(result)  # This could fail if result is invalid
    return "Done"


def risky_operation():
    """Operation that might fail and return None."""
    import random

    if random.random() < 0.5:
        return None
    return {"data": "valid data"}


def process_data(data):
    """Process some data, expects valid data."""
    return data["data"]  # Will fail if data is None


# CWE-835: Infinite Loop
def potential_infinite_loop(values):
    """Function with potential infinite loop."""
    i = 0
    # Missing proper exit condition
    while i < len(values):
        if values[i] < 0:
            i -= 1  # This can lead to an infinite loop
        else:
            i += 1
    return "Completed"


# CWE-662: Improper Synchronization
class SharedResource:
    """Class with improper synchronization."""

    def __init__(self):
        """Initialize shared resource."""
        self.value = 0
        # Missing lock: self.lock = threading.Lock()

    def increment(self):
        """Increment the shared value without proper synchronization."""
        # Missing lock acquisition
        current = self.value
        # Simulating some work
        import time

        time.sleep(0.001)
        self.value = current + 1
        # Missing lock release

    def get_value(self):
        """Get the shared value."""
        return self.value


# CWE-703: Improper Check or Handling of Exceptional Conditions
def exception_handling_issues():
    """Function with improper exception handling."""
    try:
        # Some risky operation
        result = 1 / 0  # Will raise ZeroDivisionError
        return result
    except:
        # Bare except clause catches all exceptions
        # and masks the actual error
        return -1
        # No logging of the actual exception


# CWE-665: Improper Initialization
class ImproperlyInitialized:
    """Class with improper initialization."""

    def __init__(self, value):
        """Initialize with missing initialization of attributes."""
        self.value = value
        # Missing initialization of:
        # self.status = "initialized"

    def get_status(self):
        """Get status attribute which might not exist."""
        return self.status  # May raise AttributeError


# CWE-456: Missing Initialization of a Variable
def missing_initialization():
    """Function with missing variable initialization."""
    # result is used before being initialized
    if some_condition():
        result = "valid result"

    # If some_condition() is False, result is undefined here
    return result  # May raise UnboundLocalError


def some_condition():
    """Arbitrary condition."""
    import random

    return random.choice([True, False])


# CWE-457: Use of Uninitialized Variable
def use_uninitialized_list(input_data):
    """Function using potentially uninitialized list."""
    items = None  # Initialized to None

    if input_data:
        items = input_data.get("items")

    # items could still be None here
    for item in items:  # TypeError if items is None
        print(item)


# CWE-681: Incorrect Conversion between Numeric Types
def incorrect_conversion(value):
    """Function with incorrect numeric conversion."""
    float_value = float(value)
    # Potential loss of precision when converting to int
    int_value = int(float_value)
    return int_value


# CWE-682: Incorrect Calculation
def incorrect_calculation(a, b):
    """Function with incorrect calculation."""
    # Incorrect order of operations
    result = a + b / 2  # This divides b by 2 then adds a
    # Should be (a + b) / 2 to find the average
    return result


# CWE-833: Deadlock
class DeadlockDemo:
    """Class demonstrating potential deadlock."""

    def __init__(self):
        """Initialize with two locks."""
        self.lock_a = threading.Lock()
        self.lock_b = threading.Lock()

    def operation_a(self):
        """First operation that acquires locks in one order."""
        with self.lock_a:
            # Simulating some work
            import time

            time.sleep(0.001)
            with self.lock_b:
                return "Operation A completed"

    def operation_b(self):
        """Second operation that acquires locks in reverse order."""
        with self.lock_b:  # Potential deadlock: locks acquired in different order
            # Simulating some work
            import time

            time.sleep(0.001)
            with self.lock_a:
                return "Operation B completed"
