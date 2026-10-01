FROM ghcr.io/berriai/litellm:main-latest

WORKDIR /app

# Install llm-guard and runtime dependencies
RUN pip install --no-cache-dir llm-guard torch transformers

# Copy configuration and guardrail files
COPY litellm_config.yaml /app/config.yaml
COPY custom_guardrail.py /app/custom_guardrail.py

EXPOSE 4000

CMD ["--config", "/app/config.yaml", "--port", "4000"]
