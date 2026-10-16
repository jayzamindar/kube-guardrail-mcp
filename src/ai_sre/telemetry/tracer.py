"""OpenTelemetry tracing provider with automatic in-memory / console / OTLP fallback."""

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Final

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    ConsoleSpanExporter,
    SimpleSpanProcessor,
)
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import Status, StatusCode, Tracer

logger = logging.getLogger("ai_sre.telemetry.tracer")

DEFAULT_SERVICE_NAME: Final[str] = "ai-sre-cluster-manager"
_GLOBAL_PROVIDER: TracerProvider | None = None
_GLOBAL_TRACER: Tracer | None = None
_IN_MEMORY_EXPORTER: InMemorySpanExporter | None = None


def setup_telemetry(
    service_name: str = DEFAULT_SERVICE_NAME,
    use_in_memory: bool = False,
) -> tuple[Tracer, InMemorySpanExporter | None]:
    """Initializes OpenTelemetry TracerProvider with OTLP, in-memory, or console exporter."""
    global _GLOBAL_PROVIDER, _GLOBAL_TRACER, _IN_MEMORY_EXPORTER

    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)
    exporter_instance: InMemorySpanExporter | None = None

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")

    if use_in_memory:
        exporter_instance = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter_instance))
        logger.info("Configured OpenTelemetry InMemorySpanExporter for testing.")
    elif otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import-not-found]
                OTLPSpanExporter,
            )

            otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint)
            provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
            logger.info("Configured OpenTelemetry OTLPSpanExporter at %s", otlp_endpoint)
        except Exception as e:
            logger.warning("Failed to initialize OTLPSpanExporter (%s). Fallback to console.", e)
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        # Default local development: In-Memory exporter to avoid cluttering stdio in MCP JSON-RPC
        exporter_instance = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(exporter_instance))
        logger.info("Initialized default in-memory OTel exporter for local MCP session.")

    _GLOBAL_PROVIDER = provider
    _GLOBAL_TRACER = provider.get_tracer(service_name)
    _IN_MEMORY_EXPORTER = exporter_instance

    return _GLOBAL_TRACER, _IN_MEMORY_EXPORTER


def get_tracer() -> Tracer:
    """Returns the initialized global Tracer instance."""
    global _GLOBAL_TRACER, _GLOBAL_PROVIDER
    if _GLOBAL_TRACER is None or _GLOBAL_PROVIDER is None:
        tracer, _ = setup_telemetry()
        return tracer
    return _GLOBAL_TRACER


@asynccontextmanager
async def trace_operation(
    name: str,
    attributes: dict[str, Any] | None = None,
) -> AsyncIterator[trace.Span]:
    """Async context manager for instrumenting tool operations with distributed tracing spans."""
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as span:
        if attributes:
            for k, v in attributes.items():
                if v is not None:
                    span.set_attribute(k, str(v) if isinstance(v, (dict, list)) else v)
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as exc:
            span.record_exception(exc)
            span.set_status(Status(StatusCode.ERROR, str(exc)))
            raise
