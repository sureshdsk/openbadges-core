# openbadges-core Architecture

## Overview

openbadges-core is a modern, type-safe Python implementation of the OpenBadges 3.0 specification. It provides core functionality for creating, signing, validating, and verifying digital credentials.

## Design Principles

1. **Standards Compliance**: Strict adherence to OpenBadges 3.0 and W3C Verifiable Credentials v2.0
2. **Type Safety**: Full type hints with Pydantic v2 for runtime validation
3. **Minimalism**: Core functionality only - no framework dependencies
4. **Extensibility**: Clean architecture for building custom badge systems
5. **Security**: Cryptographic signing and verification built-in

## Package Structure

```
openbadges_core/
├── __init__.py                 # Public API exports
├── exceptions.py               # Custom exceptions
│
├── models/                     # Pydantic data models
│   ├── base.py                # Base types, enums, BaseModel
│   ├── achievement.py         # Achievement, Criteria, Alignment
│   ├── profile.py             # Profile, Image, Address
│   ├── subject.py             # AchievementSubject, Result
│   ├── credential.py          # OpenBadgeCredential, EndorsementCredential
│   └── proof.py               # Proof, Evidence, CredentialStatus
│
├── crypto/                     # Cryptographic operations
│   ├── signer.py              # Ed25519Signer, RSASigner (Linked Data Proofs)
│   ├── verifier.py            # CredentialVerifier
│   └── jwt_signer.py          # Ed25519JWTSigner, RSAJWTSigner, JWTVerifier
│
├── serialization/              # Serialization formats
│   ├── json_ld.py             # to_json_ld(), from_json_ld()
│   └── jwt.py                 # to_jwt(), from_jwt() (W3C VC-JWT)
│
└── validation/                 # Credential validation
    └── validator.py           # CredentialValidator
```

## Core Models

### Inheritance Hierarchy

```
pydantic.BaseModel
└── openbadges_core.models.base.BaseModel
    ├── Profile                  # Issuer/learner identity
    ├── Achievement              # What can be earned
    ├── AchievementSubject       # Who earned it
    ├── OpenBadgeCredential      # The verifiable credential
    ├── Proof                    # Cryptographic signature
    ├── Evidence                 # Supporting evidence
    ├── Criteria                 # Earning criteria
    ├── Alignment                # Framework alignment
    ├── Result                   # Achievement results
    └── ...
```

### Data Flow

```
1. Creation Flow:
   Profile → Achievement → AchievementSubject → OpenBadgeCredential

2. Signing Flow:
   OpenBadgeCredential → CredentialSigner → Proof → Signed Credential

3. Verification Flow:
   Signed Credential → CredentialVerifier → Verification Result

4. Serialization Flow (JSON-LD):
   OpenBadgeCredential → to_json_ld() → JSON-LD String
   JSON-LD String → from_json_ld() → OpenBadgeCredential

5. JWT Flow:
   OpenBadgeCredential → JWTSigner → to_jwt() → Compact JWT String
   JWT String → JWTVerifier → from_jwt() → OpenBadgeCredential
```

## Key Components

### 1. Models (models/)

**Purpose**: Type-safe data structures representing OpenBadges entities

**Key Files**:
- `base.py`: Base model class, enums (AchievementType, ResultType, etc.)
- `credential.py`: Main OpenBadgeCredential model
- `achievement.py`: Achievement definitions
- `profile.py`: Issuer/learner profiles

**Design Pattern**: Pydantic models with:
- Automatic validation
- JSON-LD field aliasing (`@context` → `context`)
- Type coercion
- Nested model support

### 2. Cryptography (crypto/)

**Purpose**: Sign and verify credentials cryptographically

**Supported Formats**:
1. **Linked Data Proofs** (signer.py, verifier.py)
   - Embedded proof objects in JSON-LD
   - Ed25519Signature2020, RsaSignature2018

2. **JWT Signatures** (jwt_signer.py)
   - W3C VC-JWT format
   - EdDSA (Ed25519), RS256 (RSA)

**Supported Algorithms**:
- **Ed25519** (Recommended): Fast, secure elliptic curve signatures
- **RSA**: Traditional public-key signatures

**Key Classes**:

*Linked Data Proofs:*
- `CredentialSigner`: Abstract base for signers
- `Ed25519Signer`: Ed25519 implementation
- `RSASigner`: RSA implementation
- `CredentialVerifier`: Signature verification

*JWT Signatures:*
- `JWTSigner`: Abstract base for JWT signers
- `Ed25519JWTSigner`: JWT with EdDSA algorithm
- `RSAJWTSigner`: JWT with RS256 algorithm
- `JWTVerifier`: JWT signature verification

**Security Features**:
- Canonical document representation
- Timestamp inclusion (iat, exp, nbf)
- Verification method tracking
- Proof purpose specification
- Key ID support (kid header)

### 3. Serialization (serialization/)

**Purpose**: Convert between Python objects and multiple formats

**Formats Supported**:

1. **JSON-LD** (json_ld.py)
   - Human-readable JSON with semantic context
   - Linked Data compatible
   - Proof object embedded

2. **JWT** (jwt.py)
   - Compact URL-safe token
   - Self-contained with signature
   - W3C VC-JWT compliant

**Key Functions**:

*JSON-LD:*
- `to_json_ld()`: Model → JSON-LD string
- `from_json_ld()`: JSON-LD → Model instance
- `compact()`: JSON-LD compaction (with pyld)
- `expand()`: JSON-LD expansion (with pyld)

*JWT:*
- `to_jwt()`: Model → Compact JWT string
- `from_jwt()`: JWT → Model instance with verification

**Features**:
- Automatic `@context` handling (JSON-LD)
- JWT claims mapping (iss, sub, aud, exp, nbf, iat, jti)
- Field aliasing (snake_case ↔ camelCase)
- None value exclusion
- Pretty printing support (JSON-LD)

### 4. Validation (validation/)

**Purpose**: Validate credential structure and requirements

**Key Classes**:
- `CredentialValidator`: Main validation engine

**Validation Checks**:
- Required fields present
- Required types included
- Date logic (validFrom < validUntil)
- Credential subject has achievement
- Expiration status

**Modes**:
- `strict=True`: Raise ValidationError on failure
- `strict=False`: Return boolean, collect errors

## Extension Points

### 1. Custom Signature Algorithms

Extend `CredentialSigner`:

```python
from openbadges_core.crypto.signer import CredentialSigner

class MyCustomSigner(CredentialSigner):
    def sign(self, credential):
        # Custom signing logic
        pass

    def _create_signature(self, data):
        # Create signature
        pass
```

### 2. Custom Validation Rules

Extend `CredentialValidator`:

```python
from openbadges_core.validation.validator import CredentialValidator

class CustomValidator(CredentialValidator):
    def _validate_custom_rules(self):
        # Add custom validation
        if not self.credential.name:
            self.errors.append("Name is required")
```

### 3. Additional Models

Extend `BaseModel`:

```python
from openbadges_core.models.base import BaseModel, URI
from pydantic import Field

class MyCustomModel(BaseModel):
    id: URI = Field(..., description="Unique identifier")
    # Add custom fields
```

## Integration Patterns

### Django Integration

```python
# models.py
from django.db import models
from openbadges_core.serialization import to_dict, from_json_ld
from openbadges_core import OpenBadgeCredential

class Badge(models.Model):
    credential_json = models.JSONField()

    @property
    def credential(self):
        return from_json_ld(self.credential_json, OpenBadgeCredential)

    @credential.setter
    def credential(self, value):
        self.credential_json = to_dict(value)
```

### FastAPI Integration

```python
# main.py
from fastapi import FastAPI
from openbadges_core import OpenBadgeCredential
from openbadges_core.serialization import to_dict

app = FastAPI()

@app.post("/badges/issue")
async def issue_badge(user_id: str) -> dict:
    credential = create_badge(user_id)
    return to_dict(credential)
```

### Flask Integration

```python
# app.py
from flask import Flask, jsonify
from openbadges_core.serialization import to_dict

app = Flask(__name__)

@app.route('/badges/<user_id>')
def get_badge(user_id):
    credential = get_user_badge(user_id)
    return jsonify(to_dict(credential))
```

## Performance Considerations

### 1. Model Validation

Pydantic validation happens automatically:
- **Cost**: O(n) where n = number of fields
- **Optimization**: Use `model_construct()` for trusted data

### 2. Signing

Signing performance by algorithm:
- **Ed25519**: ~1ms per signature (fast)
- **RSA-2048**: ~10ms per signature (slower)

### 3. JSON-LD Processing

- `to_json_ld()`: Fast (native Python)
- `compact()/expand()`: Slower (requires pyld, network for contexts)
- **Recommendation**: Cache compacted/expanded forms

## Security Considerations

### 1. Key Management

**DO**:
- Store private keys securely (HSM, key vault)
- Use environment variables for key paths
- Rotate keys periodically

**DON'T**:
- Hard-code private keys
- Commit keys to version control
- Share keys between environments

### 2. Signature Verification

**Always**:
- Verify signatures before trusting credentials
- Check expiration dates
- Validate issuer identity
- Check revocation status (if applicable)

### 3. Input Validation

Pydantic provides automatic validation, but:
- Sanitize user input
- Validate URIs point to expected domains
- Check embedded vs. referenced resources

## Testing Strategy

### Unit Tests
- Model validation
- Signing/verification
- Serialization round-trips
- Validation logic

### Integration Tests
- End-to-end credential flow
- Multiple signature algorithms
- Framework integrations

### Test Fixtures
- Sample profiles, achievements, credentials
- Valid and invalid test cases
- Edge cases (expired credentials, missing fields)

## JWT Architecture

### Overview

The library supports W3C VC-JWT format as an alternative to JSON-LD credentials. JWT credentials are compact, URL-safe, and self-contained with embedded signatures.

### JWT Claims Mapping

The W3C VC-JWT specification defines how Verifiable Credentials map to JWT claims:

```
OpenBadgeCredential Field → JWT Claim
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
issuer.id                 → iss (issuer)
credential_subject.id     → sub (subject)
id                        → jti (JWT ID)
issuance_date             → iat (issued at)
expiration_date           → exp (expiration time)
valid_from                → nbf (not before)
aud                       → aud (audience)
[full credential]         → vc (VC claim)
```

### JWT Structure

A JWT credential has three parts (header.payload.signature):

**Header:**
```json
{
  "alg": "EdDSA",           // Algorithm (EdDSA or RS256)
  "kid": "key-2025-01",     // Optional key ID
  "typ": "JWT"              // Type
}
```

**Payload:**
```json
{
  "vc": {                   // Full credential
    "@context": [...],
    "type": [...],
    "credentialSubject": {...},
    // ... rest of credential
  },
  "iss": "https://issuer.edu",
  "sub": "did:example:123",
  "jti": "https://issuer.edu/creds/456",
  "iat": 1703462400,
  "exp": 1735084800
}
```

**Signature:** EdDSA or RS256 signature over header + payload

### Implementation Details

**JWT Signing Flow:**
1. Credential → `_credential_to_jwt_payload()` → Extract JWT claims
2. JWT payload → `JWTSigner.sign()` → Sign with private key
3. Return compact JWT string (base64url encoded)

**JWT Verification Flow:**
1. JWT string → `JWTVerifier.verify()` → Verify signature with public key
2. Decode payload → Extract `vc` claim
3. `vc` data → `OpenBadgeCredential.model_validate()` → Reconstruct credential

**Key Features:**
- **Algorithm Support**: EdDSA (Ed25519), RS256 (RSA-2048)
- **Key Rotation**: Support for `kid` (key ID) header
- **Expiration**: Automatic `exp` and `nbf` validation
- **Standards**: Full W3C VC-JWT specification compliance

### Comparison: JWT vs Linked Data Proofs

| Feature | JWT | Linked Data Proof |
|---------|-----|-------------------|
| Format | Compact string | JSON-LD object |
| Signature | JWT structure | Embedded proof object |
| Size | ~1000 bytes | ~800 bytes |
| Readability | Base64-encoded | Human-readable |
| Web compatibility | URL-safe | Requires encoding |
| Semantic web | Limited | Full RDF support |
| Use case | APIs, tokens | Storage, display |

### Security Considerations

1. **Signature Verification**: Always verify signatures in production
2. **Key Management**: Protect private keys, use HSMs for production
3. **Expiration**: Set appropriate `exp` times, validate `nbf`
4. **Algorithm Whitelist**: Only allow EdDSA and RS256
5. **Key Rotation**: Use `kid` for smooth key transitions

## Future Enhancements

Potential additions:
1. ✅ **JWT Support**: W3C VC-JWT format (COMPLETED)
2. **Revocation**: Status list 2021 implementation
3. **DID Support**: Decentralized identifier integration
4. **CLR Support**: Comprehensive Learner Record
5. **Batch Operations**: Issue multiple credentials efficiently
6. **Caching**: Smart caching for contexts and schemas
7. **SD-JWT**: Selective Disclosure JWT for privacy

## Contributing Guidelines

When adding features:
1. Follow existing patterns (BaseModel for models, abstract base classes for extensibility)
2. Add type hints to all functions
3. Write docstrings (Google style)
4. Add tests for new functionality
5. Update relevant documentation
6. Keep dependencies minimal

## Dependencies

### Core Dependencies
- `pydantic>=2.0.0`: Data validation and models
- `cryptography>=41.0.0`: Cryptographic operations
- `pyld>=2.0.3`: JSON-LD processing
- `python-dateutil>=2.8.0`: Date/time handling
- `PyJWT>=2.8.0`: JWT encoding/decoding for VC-JWT format

### Development Dependencies
- `pytest`: Testing framework
- `black`: Code formatting
- `ruff`: Linting
- `mypy`: Type checking

## Resources

- [OpenBadges 3.0 Spec](https://www.imsglobal.org/spec/ob/v3p0/)
- [W3C VC Data Model](https://www.w3.org/TR/vc-data-model-2.0/)
- [Pydantic Documentation](https://docs.pydantic.dev/)
- [Cryptography Library](https://cryptography.io/)
