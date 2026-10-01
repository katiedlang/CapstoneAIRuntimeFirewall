FROM ghcr.io/berriai/litellm:main-latest

WORKDIR /app

# Install dependencies
RUN pip install --no-cache-dir llm-guard torch transformers

# Pre-download default Hugging Face models for llm-guard so it doesn't crash on the first request
RUN python -c "from llm_guard.input_scanners import PromptInjection; PromptInjection()"
RUN python -c "from llm_guard.output_scanners import Sensitive; Sensitive(entity_types=['EMAIL_ADDRESS', 'CREDIT_CARD', 'US_SSN'])"

# Copy configuration and guardrail script
COPY litellm_config.yaml /app/config.yaml
COPY custom_guardrail.py /app/custom_guardrail.py

EXPOSE 4000

CMD ["--config", "/app/config.yaml", "--port", "4000"]
