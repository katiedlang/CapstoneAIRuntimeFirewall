import asyncio
from litellm.integrations.custom_guardrail import CustomGuardrail
from llm_guard.input_scanners import PromptInjection
from llm_guard.output_scanners import Sensitive

class EnterpriseThreatGuardrail(CustomGuardrail):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Initialize input and output scanners
        self.input_injection_scanner = PromptInjection(threshold=0.80)
        self.output_sensitive_scanner = Sensitive(entity_types=["EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN"])

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """Scans incoming user prompts for prompt injection attacks."""
        messages = data.get("messages", [])
        if not messages:
            return data

        # Extract latest message text
        user_prompt = messages[-1].get("content", "")
        
        if isinstance(user_prompt, str) and user_prompt.strip():
            # Run blocking llm-guard scanner in executor to avoid blocking LiteLLM event loop
            loop = asyncio.get_event_loop()
            sanitized_prompt, is_valid, risk_score = await loop.run_in_executor(
                None, self.input_injection_scanner.scan, user_prompt
            )

            if not is_valid:
                raise Exception(f"Security Alert: Prompt injection detected (Risk Score: {risk_score})")

        return data

    async def async_post_call_hook(self, user_api_key_dict, response_data, data):
        """Scans LLM output for sensitive PII and redacts if detected."""
        try:
            if "choices" in response_data and len(response_data["choices"]) > 0:
                message = response_data["choices"][0].get("message", {})
                content = message.get("content", "")

                if isinstance(content, str) and content.strip():
                    loop = asyncio.get_event_loop()
                    sanitized_content, is_valid, risk_score = await loop.run_in_executor(
                        None, self.output_sensitive_scanner.scan, content
                    )

                    if not is_valid:
                        response_data["choices"][0]["message"]["content"] = "[REDACTED: SENSITIVE INFORMATION DETECTED]"
        except Exception as e:
            print(f"Post-call guardrail scanning error: {e}")

        return response_data

# Instantiate guardrail instance for LiteLLM registration
enterprise_guardrail = EnterpriseThreatGuardrail()
