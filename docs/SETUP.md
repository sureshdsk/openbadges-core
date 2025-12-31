# Setup Guide for openbadges-core

## Installation

### 1. Install the package

```bash
# For development
pip install -e .

# With dev dependencies
pip install -e ".[dev]"
```

### 2. Verify installation

```bash
python -c "import openbadges_core; print(openbadges_core.__version__)"
```

## Quick Test

Run the basic example to verify everything works:

```bash
python examples/basic_usage.py
```

Expected output:
```
Creating issuer profile...
Creating achievement...
Creating credential subject...
Creating credential...
Validating credential...
Credential is valid: True

Generating Ed25519 key pair...
Signing credential...
Verifying signature...
Signature verified successfully!

Serializing to JSON-LD...

Credential JSON-LD:
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
  ],
  "type": [
    "VerifiableCredential",
    "OpenBadgeCredential"
  ],
  ...
}
```

## Running Tests

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=openbadges_core --cov-report=html
```

## Development Workflow

### 1. Make changes to the code

Edit files in `openbadges_core/`

### 2. Test your changes

```bash
# Run specific test
pytest tests/test_basic.py::TestBasicCredential::test_create_credential -v

# Run all tests
pytest tests/ -v
```

### 3. Format code

```bash
# Format with black
black openbadges_core/

# Check with ruff
ruff check openbadges_core/
```

### 4. Type check

```bash
mypy openbadges_core/
```

### 5. Version Management

The project uses `bump-my-version` for semantic versioning. To bump the version:

```bash
# Bump patch version (0.1.0 → 0.1.1)
bump-my-version bump patch

# Bump minor version (0.1.0 → 0.2.0)
bump-my-version bump minor

# Bump major version (0.1.0 → 1.0.0)
bump-my-version bump major
```

What happens automatically:
- Updates version in `pyproject.toml` and `openbadges_core/__init__.py`
- Creates a git commit with message: `Bump version: {old} → {new}`
- Creates a git tag named `v{new_version}`

Requirements:
- Working directory must be clean (no uncommitted changes)
- Push tags manually: `git push --tags`

Preview changes without applying:
```bash
bump-my-version bump patch --dry-run --verbose
```

## Using in Your Project

### Example: Django Integration

1. Install openbadges-core in your Django project:
```bash
pip install /path/to/openbadges-core
```

2. Create a badge service:

```python
# myapp/services/badges.py
from datetime import datetime, timezone
from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.crypto import Ed25519Signer
from openbadges_core.models.achievement import Criteria

class BadgeService:
    def __init__(self, private_key, issuer_profile):
        self.signer = Ed25519Signer(
            private_key=private_key,
            verification_method=f"{issuer_profile.id}#key-1"
        )
        self.issuer = issuer_profile

    def issue_badge(self, user, achievement_def):
        # Create subject
        subject = AchievementSubject(
            id=f"mailto:{user.email}",
            achievement=achievement_def
        )

        # Create credential
        credential = OpenBadgeCredential(
            context=[
                "https://www.w3.org/ns/credentials/v2",
                "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
            ],
            type=["VerifiableCredential", "OpenBadgeCredential"],
            issuer=self.issuer,
            issuance_date=datetime.now(timezone.utc),
            credential_subject=subject
        )

        # Sign and return
        return self.signer.sign(credential)
```

3. Use in views:

```python
# myapp/views.py
from django.http import JsonResponse
from openbadges_core.serialization import to_dict
from .services.badges import BadgeService

def issue_badge(request, user_id, achievement_id):
    badge_service = BadgeService(private_key, issuer_profile)
    credential = badge_service.issue_badge(user, achievement)
    return JsonResponse(to_dict(credential))
```

### Example: FastAPI Integration

```python
from fastapi import FastAPI
from openbadges_core import OpenBadgeCredential
from openbadges_core.serialization import to_dict

app = FastAPI()

@app.post("/badges/issue")
async def issue_badge(user_id: str, achievement_id: str):
    # Create and sign credential
    credential = create_badge(user_id, achievement_id)
    return to_dict(credential)
```

## Next Steps

1. Read the [README.md](../README.md) for comprehensive documentation
2. Check [examples/](../examples/) for more usage patterns
3. Review the [OpenBadges 3.0 Specification](https://www.imsglobal.org/spec/ob/v3p0/)
4. Start building your badge system!

## Troubleshooting

### Import errors

If you get import errors, ensure the package is installed:
```bash
pip install -e .
```

### Validation errors

Check that your credential includes all required fields:
- `type` (must include "VerifiableCredential" and "OpenBadgeCredential")
- `issuer`
- `credential_subject` (with `achievement`)
- `context`

### Signing errors

Ensure your private key is in the correct format:
- Ed25519: 32-byte seed or Ed25519PrivateKey object
- RSA: RSAPrivateKey object or PEM-encoded bytes
