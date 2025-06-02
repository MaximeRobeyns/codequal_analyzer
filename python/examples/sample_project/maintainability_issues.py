"""Sample file with maintainability issues for PyCQ analyzer testing."""


# CWE-561: Dead code
def unused_function():
    """This function is never called."""
    return "I am never called"


# CWE-1041: Redundant code through copy-paste with minor modifications
def process_data(data):
    """Process some data."""
    result = []
    for item in data:
        if item > 10:
            item = item * 2
            result.append(item)
    return result


def process_items(items):
    """Process some items (duplicated logic)."""
    output = []
    for item in items:
        if item > 10:
            item = item * 2
            output.append(item)
    return output


# CWE-1121: Excessive McCabe cyclomatic complexity
def complex_function(a, b, c, d, e, f, g, h):  # CWE-1064: Too many parameters
    """Function with high cyclomatic complexity."""
    result = 0
    if a > 0:
        if b > 0:
            if c > 0:
                result = a + b + c
            else:
                if d > 0:
                    result = a + b + d
                else:
                    result = a + b
        else:
            if e > 0:
                if f > 0:
                    result = a + e + f
                else:
                    result = a + e
            else:
                if g > 0:
                    if h > 0:
                        result = a + g + h
                    else:
                        result = a + g
                else:
                    result = a
    else:
        if h > 0:
            result = h
        else:
            if g > 0:
                result = g
            else:
                if f > 0:
                    result = f
                else:
                    result = 0
    return result


# CWE-1047: Circular dependency structure is created when this module
# imports from modules that import this module


# CWE-1055: Multiple inheritance
class BaseA:
    """Base class A."""

    def method_a(self):
        """Method A."""
        return "A"


class BaseB:
    """Base class B."""

    def method_b(self):
        """Method B."""
        return "B"


class BaseC:
    """Base class C."""

    def method_c(self):
        """Method C."""
        return "C"


# Multiple inheritance from multiple concrete classes
class Derived(BaseA, BaseB, BaseC):
    """Derived class with multiple inheritance."""

    def method_d(self):
        """Method D."""
        return self.method_a() + self.method_b() + self.method_c() + "D"


# CWE-1080: Excessive file length (this file intentionally contains many issues)


# CWE-1075: Unconditional jump
def unconditional_jump(value):
    """Function with unconditional control flow transfer."""
    if value > 0:
        print("Positive")
    else:
        print("Non-positive")
        goto_end = True

    if goto_end:  # This simulates a "goto" without using actual goto
        return

    # Unreachable code
    print("This will never be reached")


# Global variable usage
GLOBAL_COUNTER = 0


def increment_counter():
    """Function using global variable."""
    global GLOBAL_COUNTER
    GLOBAL_COUNTER += 1
    return GLOBAL_COUNTER


# CWE-1052: Excessive use of literals
def config_system():
    """Function with hard-coded literals."""
    server_address = "192.168.1.100"  # Should be in config
    port = 8080  # Should be in config
    timeout = 30  # Should be in config
    max_connections = 100  # Should be in config
    retry_limit = 5  # Should be in config
    return {
        "server": server_address,
        "port": port,
        "timeout": timeout,
        "max_connections": max_connections,
        "retry_limit": retry_limit,
    }
