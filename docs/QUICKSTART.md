# Quick Start Guide - openbadges-core

Get started with openbadges-core in 5 minutes!

## Installation

```bash
# Clone or navigate to the project
cd /path/to/openbadges-core

# Install dependencies
pip install -e .

# Or with uv (faster)
uv pip install -e .
```

## Create Your First Badge (5 steps)

### Step 1: Import the library

```python
from datetime import datetime, timezone
from openbadges_core import (
    Achievement,
    AchievementSubject,
    OpenBadgeCredential,
    Profile
)
from openbadges_core.models.achievement import Criteria
from openbadges_core.crypto import Ed25519Signer, verify_credential
```

### Step 2: Define your issuer

```python
issuer = Profile(
    id="https://myorg.example/issuers/1",
    name="My Organization",
    email="badges@myorg.example"
)
```

### Step 3: Create an achievement

```python
achievement = Achievement(
    id="https://myorg.example/achievements/completion",
    name="Course Completion Badge",
    description="Successfully completed the Python fundamentals course",
    criteria=Criteria(
        narrative="Complete all modules and pass the final exam with 80% or higher"
    )
)
```

### Step 4: Issue the credential

```python
# Create the subject (learner)
subject = AchievementSubject(
    id="mailto:learner@example.com",
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
    name="Course Completion Badge"
)
```

### Step 5: Sign and export

```python
# Generate keys (do this once, store securely!)
private_key, public_key = Ed25519Signer.generate_key_pair()

# Sign the credential
signer = Ed25519Signer(
    private_key=private_key,
    verification_method=f"{issuer.id}#key-1"
)
signed_credential = signer.sign(credential)

# Export as JSON-LD
from openbadges_core.serialization import to_json_ld
json_output = to_json_ld(signed_credential)
print(json_output)
```

## Verify a Badge

```python
from openbadges_core.crypto import verify_credential

# Verify the signature
is_valid = verify_credential(signed_credential, public_key)
print(f"Signature valid: {is_valid}")  # True
```

## Complete Example

Run the included example:

```bash
python examples/basic_usage.py
```

Output:
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
  "@context": [...],
  "type": ["VerifiableCredential", "OpenBadgeCredential"],
  ...
}
```

## Common Use Cases

### 1. Issue Badge on Course Completion

```python
def issue_completion_badge(user_email, course_name):
    achievement = Achievement(
        id=f"https://myorg.example/achievements/{course_name}",
        name=f"{course_name} Completion",
        description=f"Completed {course_name}",
        criteria=Criteria(narrative="Complete all course requirements")
    )

    subject = AchievementSubject(
        id=f"mailto:{user_email}",
        achievement=achievement
    )

    credential = OpenBadgeCredential(
        context=["https://www.w3.org/ns/credentials/v2",
                 "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json"],
        type=["VerifiableCredential", "OpenBadgeCredential"],
        issuer=ISSUER_PROFILE,  # Pre-configured
        issuance_date=datetime.now(timezone.utc),
        credential_subject=subject
    )

    return SIGNER.sign(credential)  # Pre-configured signer
```

### 2. Badge with Grade Results

```python
from openbadges_core.models.subject import Result
from openbadges_core.models.base import ResultType

subject = AchievementSubject(
    id="mailto:student@example.com",
    achievement=achievement,
    result=[
        Result(
            type="Result",
            result_type=ResultType.LetterGrade,
            value="A"
        ),
        Result(
            type="Result",
            result_type=ResultType.Percent,
            value="95"
        )
    ]
)
```

### 3. Badge with Expiration

```python
from datetime import timedelta

credential = OpenBadgeCredential(
    # ... other fields ...
    valid_from=datetime.now(timezone.utc),
    valid_until=datetime.now(timezone.utc) + timedelta(days=365)  # 1 year
)
```

### 4. Save to Database (Django example)

```python
from openbadges_core.serialization import to_dict

# Create and sign credential
credential = create_badge(user)

# Save to database
Badge.objects.create(
    user=user,
    credential_data=to_dict(credential),
    issued_at=credential.issuance_date
)
```

### 5. API Endpoint (FastAPI example)

```python
from fastapi import FastAPI
from openbadges_core.serialization import to_dict

app = FastAPI()

@app.post("/users/{user_id}/badges/{achievement_id}")
async def issue_badge(user_id: str, achievement_id: str):
    credential = create_and_sign_badge(user_id, achievement_id)
    return to_dict(credential)
```

## Next Steps

1. **Read the full documentation**: [README.md](../README.md)
2. **Understand the architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
3. **Run advanced examples**: `python examples/advanced_usage.py`
4. **Explore the models**: Check `openbadges_core/models/`
5. **Set up key management**: Securely store your signing keys
6. **Integrate with your app**: See integration examples in README

## Key Management Best Practices

**Development**:
```python
# Generate and save keys once
private_key, public_key = Ed25519Signer.generate_key_pair()

# Save private key (KEEP SECRET!)
with open('private_key.pem', 'wb') as f:
    from cryptography.hazmat.primitives import serialization
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    f.write(pem)
```

**Production**:
- Use environment variables
- Store keys in a key vault (AWS KMS, Azure Key Vault, HashiCorp Vault)
- Never commit keys to version control
- Use different keys per environment

## Troubleshooting

### Import Error
```
ModuleNotFoundError: No module named 'openbadges_core'
```
**Solution**: Install the package: `pip install -e .`

### Validation Error
```
ValidationError: Credential validation failed
```
**Solution**: Ensure all required fields are present (type, issuer, credential_subject)

### Signature Verification Failed
```
VerificationError: Invalid signature
```
**Solution**: Ensure you're using the correct public key that matches the private key used for signing

## Support

- **Documentation**: [README.md](../README.md)
- **Examples**: [examples/](../examples/)
- **Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md)
- **Issues**: Report on GitHub

## Resources

- [OpenBadges 3.0 Specification](https://www.imsglobal.org/spec/ob/v3p0/)
- [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
- [Pydantic Documentation](https://docs.pydantic.dev/)

Happy badging! 🎓
