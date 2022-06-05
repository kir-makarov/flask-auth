from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource


def configure_tracer() -> None:
    tracer_provider = TracerProvider(
        resource=Resource.create({SERVICE_NAME: "auth-service"})
    )
    trace.set_tracer_provider(tracer_provider)
    trace.get_tracer_provider().add_span_processor(
        BatchSpanProcessor(
            JaegerExporter(
                agent_host_name='jaeger',
                agent_port=6831,
            )
        )
    )
    # Чтобы видеть трейсы в консоли
    trace.get_tracer_provider().add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))