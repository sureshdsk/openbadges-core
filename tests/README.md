# Test Suite for openbadges-core

This directory contains the comprehensive test suite for openbadges-core.

## Structure

```
tests/
├── conftest.py                 # Shared fixtures and pytest configuration
├── unit/                       # Unit tests (isolated component tests)
│   ├── test_models.py         # Profile, Achievement, Credential models
│   ├── test_crypto.py         # Signing and verification
│   ├── test_serialization.py  # JSON-LD serialization
│   └── test_validation.py     # Credential validation
└── integration/                # Integration tests (end-to-end workflows)
    └── test_end_to_end.py     # Complete credential lifecycle tests
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run specific test categories
```bash
# Unit tests only
pytest tests/unit/

# Integration tests only
pytest tests/integration/

# Specific test file
pytest tests/unit/test_models.py

# Specific test class
pytest tests/unit/test_models.py::TestProfileModel

# Specific test method
pytest tests/unit/test_models.py::TestProfileModel::test_minimal_profile
```

### Run tests with markers
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run only crypto tests
pytest -m crypto

# Exclude slow tests
pytest -m "not slow"
```

### Coverage reports
```bash
# Generate HTML coverage report
pytest --cov=openbadges_core --cov-report=html

# View report
open htmlcov/index.html

# Terminal coverage report
pytest --cov=openbadges_core --cov-report=term-missing
```

### Verbose output
```bash
# Show all test details
pytest -vv

# Show print statements
pytest -s

# Show local variables on failure
pytest -l

# Stop on first failure
pytest -x
```

## Test Categories

### Unit Tests (`tests/unit/`)

**Purpose**: Test individual components in isolation

**Characteristics**:
- Fast execution
- No external dependencies
- Test single function/class
- Use fixtures for test data

**Files**:
- `test_models.py`: Pydantic model validation, field types, nested models
- `test_crypto.py`: Key generation, signing, verification, error cases
- `test_serialization.py`: JSON-LD serialization, deserialization, round-trips
- `test_validation.py`: Credential validation rules, error collection

### Integration Tests (`tests/integration/`)

**Purpose**: Test complete workflows and component interaction

**Characteristics**:
- Test multiple components together
- Realistic scenarios
- End-to-end workflows

**Files**:
- `test_end_to_end.py`: Complete badge issuance, signing, serialization, verification

## Fixtures

Shared fixtures are defined in `conftest.py`:

### Profile Fixtures
- `basic_issuer`: Simple issuer profile
- `detailed_issuer`: Full-featured issuer
- `learner_profile`: Learner/recipient profile

### Achievement Fixtures
- `basic_achievement`: Simple achievement
- `detailed_achievement`: Achievement with alignments and results

### Subject Fixtures
- `basic_subject`: Simple achievement subject
- `detailed_subject`: Subject with results and dates

### Credential Fixtures
- `basic_credential`: Minimal valid credential
- `detailed_credential`: Full-featured credential
- `expired_credential`: Expired credential for validation tests

### Crypto Fixtures
- `ed25519_keypair`: Ed25519 key pair
- `rsa_keypair`: RSA key pair
- `ed25519_signer`: Configured Ed25519 signer
- `rsa_signer`: Configured RSA signer

### Data Fixtures
- `valid_contexts`: Standard OpenBadges contexts
- `valid_types`: Standard credential types

## Writing New Tests

### Unit Test Example

```python
def test_my_feature(basic_credential):
    """Test description."""
    # Arrange
    expected_value = "something"

    # Act
    result = basic_credential.some_method()

    # Assert
    assert result == expected_value
```

### Integration Test Example

```python
def test_complete_workflow():
    """Test end-to-end scenario."""
    # Create all components
    issuer = Profile(...)
    achievement = Achievement(...)
    subject = AchievementSubject(...)
    credential = OpenBadgeCredential(...)

    # Sign
    private_key, public_key = Ed25519Signer.generate_key_pair()
    signer = Ed25519Signer(private_key, "...")
    signed = signer.sign(credential)

    # Verify
    assert verify_credential(signed, public_key)

    # Serialize
    json_ld = to_json_ld(signed)

    # Round-trip
    restored = from_json_ld(json_ld, OpenBadgeCredential)
    assert verify_credential(restored, public_key)
```

### Using Fixtures

```python
def test_with_fixture(basic_credential, ed25519_signer):
    """Test using predefined fixtures."""
    signed = ed25519_signer.sign(basic_credential)
    assert signed.proof is not None
```

### Parametrized Tests

```python
import pytest

@pytest.mark.parametrize("value,expected", [
    ("A", True),
    ("B+", True),
    ("F", False),
])
def test_grade_validation(value, expected):
    """Test multiple input combinations."""
    result = validate_grade(value)
    assert result == expected
```

## Test Markers

Mark tests with decorators:

```python
import pytest

@pytest.mark.unit
def test_something():
    """Unit test."""
    pass

@pytest.mark.integration
def test_workflow():
    """Integration test."""
    pass

@pytest.mark.slow
def test_long_running():
    """Slow test."""
    pass

@pytest.mark.crypto
def test_signing():
    """Cryptography test."""
    pass
```

## Best Practices

1. **One assertion per test** (when practical)
2. **Clear test names** that describe what is being tested
3. **Use fixtures** for common test data
4. **Test edge cases** and error conditions
5. **Independent tests** - no test should depend on another
6. **Fast tests** - unit tests should run quickly
7. **Document complex tests** with comments
8. **Use parametrize** for multiple similar test cases

## CI/CD Integration

For continuous integration:

```yaml
# Example GitHub Actions
- name: Run tests
  run: |
    pytest --cov=openbadges_core --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    file: ./coverage.xml
```

## Debugging Failed Tests

```bash
# Show full error output
pytest -vv

# Drop into debugger on failure
pytest --pdb

# Only run failed tests from last run
pytest --lf

# Run failed tests first, then rest
pytest --ff
```

## Test Coverage Goals

Target coverage: **>= 90%**

Current coverage areas:
- ✅ Models: Profile, Achievement, Subject, Credential
- ✅ Cryptography: Ed25519, RSA signing and verification
- ✅ Serialization: JSON-LD serialization/deserialization
- ✅ Validation: Credential validation rules
- ✅ Integration: End-to-end workflows

## Adding New Test Files

When adding new modules to openbadges_core:

1. Create corresponding test file in `tests/unit/`
2. Add fixtures to `conftest.py` if needed
3. Write unit tests for all public functions
4. Add integration tests if the module interacts with others
5. Update this README if new test categories are added
