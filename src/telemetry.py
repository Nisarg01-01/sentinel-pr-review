import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def setup_telemetry(service_name: str = "sentinel") -> trace.Tracer:
    connection_string = os.environ.get("APPLICATIONINSIGHTS_CONNECTION_STRING")

    if connection_string:
        from azure.monitor.opentelemetry import configure_azure_monitor
        configure_azure_monitor(connection_string=connection_string)
        print(f"Telemetry enabled — sending traces to Application Insights")
    else:
        print("Telemetry disabled — set APPLICATIONINSIGHTS_CONNECTION_STRING to enable")

    return trace.get_tracer(service_name)
