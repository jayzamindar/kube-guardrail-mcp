"""Shared strict base models and RFC 1123 Kubernetes validation constraints."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints


class StrictBaseModel(BaseModel):
    """Base model enforcing fintech-grade zero-trust parameters:
    - Immutable (frozen=True) to prevent in-memory tampering
    - Forbid extra fields to prevent payload injection attacks
    - Whitespace stripped automatically
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        str_strip_whitespace=True,
    )


# RFC 1123 DNS Label format for K8s Namespaces (1-63 alphanumeric/dash chars)
NamespaceStr = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=63,
        pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?$",
    ),
]

# RFC 1123 Subdomain format for K8s Workload / Deployment names (1-253 chars)
WorkloadNameStr = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=253,
        pattern=r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$",
    ),
]
