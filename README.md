# OpenBadges Core

A modern, simplified Python implementation of the [OpenBadges 3.0 specification](https://www.imsglobal.org/spec/ob/v3p0/) built on the W3C Verifiable Credentials Data Model v2.0.

## Features

- **Standards Compliant**: Full implementation of OpenBadges 3.0 / W3C Verifiable Credentials
- **Type Safe**: Built with Pydantic v2 for automatic validation and type safety
- **Cryptographic Security**: Support for Ed25519 and RSA signature algorithms
- **Multiple Formats**: JSON-LD and JWT (JSON Web Token) serialization
- **JWT Support**: W3C VC-JWT format for compact, signed credentials
- **Extensible**: Clean architecture for building custom badge systems
- **Framework Agnostic**: Works with any Python application (Django, Flask, FastAPI, etc.)

## Installation

```bash
# Install from local directory (for development)
pip install -e .

# Or install with development dependencies
pip install -e ".[dev]"
```

## Quick Start

### Creating a Simple Badge

```python
from datetime import datetime, timezone
from openbadges_core import Achievement, AchievementSubject, OpenBadgeCredential, Profile
from openbadges_core.models.achievement import Criteria
from openbadges_core.crypto import Ed25519Signer

# Create issuer profile
issuer = Profile(
    id="https://example.edu/issuers/1",
    type="Profile",
    name="Example University",
    email="badges@example.edu"
)

# Define achievement
achievement = Achievement(
    id="https://example.edu/achievements/python-expert",
    type="Achievement",
    name="Python Expert Badge",
    description="Awarded for demonstrating expert-level Python skills",
    criteria=Criteria(
        narrative="Complete advanced Python projects and certification exam"
    ),
    creator=issuer
)

# Create credential subject (learner)
subject = AchievementSubject(
    id="did:example:learner123",
    type="AchievementSubject",
    achievement=achievement
)

# Create the credential
credential = OpenBadgeCredential(
    context=[
        "https://www.w3.org/ns/credentials/v2",
        "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"
    ],
    type=["VerifiableCredential", "OpenBadgeCredential"],
    issuer=issuer,
    issuance_date=datetime.now(timezone.utc),
    credential_subject=subject,
    name="Python Expert Badge"
)
```

### Signing and Verifying Credentials

```python
from openbadges_core.crypto import Ed25519Signer, verify_credential

# Generate key pair
private_key, public_key = Ed25519Signer.generate_key_pair()

# Sign the credential
signer = Ed25519Signer(
    private_key=private_key,
    verification_method="https://example.edu/issuers/1#key-1"
)
signed_credential = signer.sign(credential)

# Verify the signature
is_valid = verify_credential(signed_credential, public_key)
print(f"Signature valid: {is_valid}")
```

### Serializing to JSON-LD

```python
from openbadges_core.serialization import to_json_ld

# Export as JSON-LD
json_ld = to_json_ld(signed_credential)
print(json_ld)
```

### JWT Format (Compact Credentials)

```python
from openbadges_core.crypto import Ed25519JWTSigner, JWTVerifier
from openbadges_core.serialization import to_jwt, from_jwt

# Generate JWT signing key
private_key, public_key = Ed25519JWTSigner.generate_key_pair()

# Create JWT signer
jwt_signer = Ed25519JWTSigner(private_key, key_id="key-2025-01")

# Encode credential as compact JWT
jwt_string = to_jwt(credential, jwt_signer)
print(f"JWT: {jwt_string[:80]}...")

# Verify and decode JWT
verifier = JWTVerifier(public_key)
verified_credential = from_jwt(jwt_string, verifier)
print(f"Verified! Issued to: {verified_credential.credential_subject.id}")
```

### Validation

```python
from openbadges_core.validation import validate_credential

# Validate credential structure
is_valid = validate_credential(credential, strict=True)
```

## Core Components

### Models

- **`OpenBadgeCredential`** (alias `AchievementCredential`): Main verifiable credential
- **`Achievement`**: Definition of what can be earned
- **`Profile`**: Issuer or learner identity
- **`AchievementSubject`**: The learner who earned the achievement
- **`Proof`**: Cryptographic proof of authenticity

### Cryptography

- **`Ed25519Signer`**: Sign credentials with Ed25519 (Linked Data Proofs)
- **`RSASigner`**: Sign credentials with RSA (Linked Data Proofs)
- **`Ed25519JWTSigner`**: Sign credentials as JWTs with Ed25519
- **`RSAJWTSigner`**: Sign credentials as JWTs with RSA
- **`JWTVerifier`**: Verify JWT signatures
- **`verify_credential()`**: Verify Linked Data Proof signatures

### Serialization

- **`to_json_ld()`**: Convert credentials to JSON-LD format
- **`from_json_ld()`**: Parse JSON-LD into credential objects
- **`to_jwt()`**: Encode credentials as W3C VC-JWT format
- **`from_jwt()`**: Decode and verify JWT credentials

### Validation

- **`validate_credential()`**: Validate credential structure and requirements
- **`CredentialValidator`**: Advanced validation with detailed error reporting

## Project Structure

```
openbadges-core/
├── openbadges_core/
│   ├── models/              # Pydantic models for OB 3.0 entities
│   │   ├── achievement.py   # Achievement, Criteria, Alignment
│   │   ├── credential.py    # OpenBadgeCredential
│   │   ├── profile.py       # Profile (issuer/learner)
│   │   ├── subject.py       # AchievementSubject, Result
│   │   ├── proof.py         # Proof, Evidence
│   │   └── base.py          # Base types and enums
│   ├── crypto/              # Signing and verification
│   │   ├── signer.py        # Ed25519Signer, RSASigner
│   │   ├── verifier.py      # CredentialVerifier
│   │   └── jwt_signer.py    # Ed25519JWTSigner, RSAJWTSigner, JWTVerifier
│   ├── serialization/       # Serialization utilities
│   │   ├── json_ld.py       # JSON-LD format
│   │   └── jwt.py           # JWT format (W3C VC-JWT)
│   ├── validation/          # Validation logic
│   │   └── validator.py
│   └── exceptions.py        # Custom exceptions
├── examples/
│   ├── basic_usage.py       # Simple badge creation
│   ├── advanced_usage.py    # Advanced features
│   └── jwt_example.py       # JWT encoding/decoding
└── tests/                   # Test suite
```

## Advanced Usage

### Creating Credentials with Results

```python
from openbadges_core.models.subject import Result
from openbadges_core.models.base import ResultType

subject = AchievementSubject(
    id="mailto:learner@example.com",
    achievement=achievement,
    result=[
        Result(
            type="Result",
            result_type=ResultType.LetterGrade,
            value="A"
        ),
        Result(
            type="Result",
            result_type=ResultType.GradePointAverage,
            value="3.95"
        )
    ],
    credits_earned=12.0
)
```

### Adding Evidence

```python
from openbadges_core.models.proof import Evidence

credential = OpenBadgeCredential(
    # ... other fields ...
    evidence=[
        Evidence(
            type="Evidence",
            name="Final Project",
            description="Capstone project demonstrating mastery",
            narrative="Completed a comprehensive project..."
        )
    ]
)
```

### Alignment to Competency Frameworks

```python
from openbadges_core.models.achievement import Alignment
from openbadges_core.models.base import AlignmentTargetType

achievement = Achievement(
    # ... other fields ...
    alignment=[
        Alignment(
            target_name="Data Analysis Competency",
            target_url="https://competencies.example.org/data-analysis",
            target_framework="National Competency Framework",
            target_type=AlignmentTargetType.Competency
        )
    ]
)
```

## Integration Examples

### Django Integration

```python
from django.http import JsonResponse
from openbadges_core import OpenBadgeCredential
from openbadges_core.serialization import to_json_ld

def issue_badge(request, user_id):
    # Create credential...
    credential = create_badge_for_user(user_id)

    # Sign it
    signed = signer.sign(credential)

    # Return as JSON-LD
    return JsonResponse(
        json.loads(to_json_ld(signed)),
        content_type="application/ld+json"
    )
```

### FastAPI Integration

```python
from fastapi import FastAPI
from openbadges_core import OpenBadgeCredential
from openbadges_core.serialization import to_dict

app = FastAPI()

@app.post("/badges/issue")
async def issue_badge(user_id: str):
    credential = create_badge_for_user(user_id)
    signed = signer.sign(credential)
    return to_dict(signed)
```

## Development

### Running Examples

```bash
# Install in development mode
pip install -e ".[dev]"

# Run basic example
python examples/basic_usage.py

# Run advanced example
python examples/advanced_usage.py
```

### Running Tests

```bash
pytest tests/
```

### Code Quality

```bash
# Format code
black openbadges_core/

# Lint
ruff check openbadges_core/

# Type check
mypy openbadges_core/
```

## JWT vs JSON-LD Formats

OpenBadges credentials can be serialized in two formats:

### JSON-LD Format
- **Human-readable**: Easy to read and debug
- **Linked Data**: Full semantic context with @context
- **Proof embedded**: Includes Linked Data Proof object
- **Best for**: Storage, display, semantic web applications

### JWT Format (VC-JWT)
- **Compact**: URL-safe, single string token
- **Self-contained**: Signature in JWT structure
- **Portable**: Works with existing JWT infrastructure
- **Best for**: API responses, mobile apps, tokens

```python
# Same credential, two formats
json_ld_size = len(to_json_ld(credential))   # ~800 bytes
jwt_size = len(to_jwt(credential, signer))   # ~1000 bytes (with signature)

# Both are W3C compliant and interoperable
```

## Specification Compliance

This library implements:

- ✅ OpenBadges 3.0 Core Specification
- ✅ W3C Verifiable Credentials Data Model v2.0
- ✅ W3C VC-JWT (JSON Web Token format for VCs)
- ✅ JSON-LD 1.1
- ✅ Linked Data Proofs (Ed25519, RSA)
- ✅ JWT Signatures (EdDSA, RS256)

## Contributing

Contributions welcome! This is a core library focused on the OpenBadges 3.0 specification.

## License

MIT License

## Resources

- [OpenBadges 3.0 Specification](https://www.imsglobal.org/spec/ob/v3p0/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [OpenBadges Implementation Guide](https://www.imsglobal.org/spec/ob/v3p0/impl)
- [1EdTech Open Badges](https://www.1edtech.org/standards/open-badges)

## Support

For issues and questions, please open an issue on GitHub.
