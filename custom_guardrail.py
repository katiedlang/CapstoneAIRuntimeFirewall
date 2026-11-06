# run scanning tasks without blocking other async operations
import asyncio

# import LiteLLM's class for creating custom guardrails
from litellm.integrations.custom_guardrail import CustomGuardrail

# functions used to scan incoming text and outgoing responses
from llm_guard import scan_prompt, scan_output

# scanners used to check incoming user messages
from llm_guard.input_scanners import (
    PromptInjection,
    InvisibleText,
    Secrets,
    TokenLimit,
)

# scanner used to check AI responses for sensitive info
from llm_guard.output_scanners import Sensitive

# create firewall using LiteLLM's guardrail class
class EnterpriseThreatGuardrail(CustomGuardrail):

    def __init__(self, **kwargs):
        # initialize the parent class
        super().__init__(**kwargs)

        # ----------------------------
        # INPUT SCANNERS
        # ----------------------------

        # scanners check prompts before they reach the AI
        self.input_scanners = [
            # 0.80 is the detection threshold
            PromptInjection(threshold=0.80),
            # checck for hidden/invisible characters
            InvisibleText(),
            # eetect exposed credentials
            Secrets(),
            # reject prompts exceeding 4096 tokens
            TokenLimit(limit=4096),
        ]

        # ----------------------------
        # OUTPUT SCANNERS
        # ----------------------------

        # checkgenerated responses for sensitive info like email, credit card, ssn
        self.output_scanners = [

            Sensitive(
                entity_types=[
                    "EMAIL_ADDRESS",  
                    "CREDIT_CARD",  
                    "US_SSN",        
                ]
            )
        ]

    # =====================================================
    # INPUT GUARDRAIL
    # Runs before request reaches the LLM
    # =====================================================

    async def async_pre_call_hook(
        self,
        user_api_key_dict,
        cache,
        data,
        call_type
    ):
        # get messages from the request
        messages = data.get("messages", [])

        # no messages, return the request
        if not messages:
            raise ValueError("Security Alert: No messages to scan")

        # find most recent user message
        user_prompt = None
        # search backward for a user message
        for message in reversed(messages):
            if message.get("role") == "user":
                user_prompt = message.get("content", "")
                break

        # block if no user message was found
        if user_prompt is None:
            raise ValueError("Security Alert: No user message found")

        # make sure prompt is a str before scanning
        if not isinstance(user_prompt, str):
            raise ValueError("Security Alert: Unsupported inport format")

        # skip scanning if prompt is empty
        if not user_prompt.strip():
            raise ValueError("Security Alert: Empty user message")

        # get the running event loop for asynchronous scanning
        loop = asyncio.get_running_loop()

        # run input scanners
        # returns the sanitized prompt, pass/fail results, and scores
        (
            sanitized_prompt,
            results_valid,
            results_score
        ) = await loop.run_in_executor(
            None,
            lambda: scan_prompt(
                self.input_scanners,
                user_prompt,
                fail_fast=False
            )
        )
        
        # print scanner results to console for testing info
        print("\n")
        print("=" * 60)
        print("INPUT GUARDRAIL RESULTS")
        print("=" * 60)


        # Display each scanner's pass/fail result and score
        for scanner_name in results_valid:

            print(
                f"{scanner_name}: "
                f"valid={results_valid[scanner_name]} "
                f"risk={results_score[scanner_name]}"
            )

        # determine which scanners blocked request
        # collect scanners that marked the prompt invalid
        failed_scanners = [
            scanner_name
            for scanner_name, valid
            in results_valid.items()
            if not valid
        ]

        # if any scanner failed, block the request
        if (
            failed_scanners == ["InvisibleText"]
            and sanitized_prompt != user_prompt
        ):
            print("Invisible characters removed from prompt")
            failed_scanners = []

        # block if any other scanner detected a threat
        if failed_scanners:
            raise Exception(
                "Security Alert: Input blocked by "
                + ", ".join(failed_scanners)
            )

        # replace original prompt with sanitized prompt if request blocked
        for message in reversed(messages):

            if message.get("role") == "user":
                message["content"] = sanitized_prompt

                break

        # return request so it can continue to the AI
        return data

    # =====================================================
    # OUTPUT GUARDRAIL
    # Runs AFTER the LLM generates a response
    # =====================================================

    async def async_post_call_success_hook(
        self,
        data,
        user_api_key_dict,
        response
    ):
        # store the AI-generated response
        response_data = response

        # scan the response and catch any errors
        try:            
            # get response choices from a dictionary or object
            if isinstance(response_data, dict):
                choices = response_data.get("choices", [])
            else:
                choices = getattr(response_data, "choices", [])

            # if no response exists, return it unchanged
            if not choices:
                raise ValueError("Security Alert: No response choices to scan")

            # get the first AI response message
            if isinstance(choices[0], dict):
                message = choices[0].get("message", {})
            else:
                message = getattr(choices[0], "message", {})

            # get the text from a dictionary or object
            if isinstance(message, dict):
                output_text = message.get("content", "")
            else:
                output_text = getattr(message, "content", "")

            # make sure response has text
            if not isinstance(output_text, str):
                raise ValueError("Security Alert: Invalid response format")

            # skip scanning if the response is empty
            if not output_text.strip():
                raise ValueError("Security Alert: Empty response can not be scanned")

            # get original user prompt
            messages = data.get(
                "messages",
                []
            )
            original_prompt = ""

            # find most recent user message for the output scanner
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    original_prompt = msg.get(
                        "content",
                        ""
                    )
                    break

            # get the event loop to run output scanning
            loop = asyncio.get_running_loop()

            # scan  AI response for sensitive information
            # returns sanitized text, pass/fail results, and scores
            (
                sanitized_output,
                results_valid,
                results_score
            ) = await loop.run_in_executor(
                None,
                lambda: scan_output(
                    self.output_scanners,
                    original_prompt,
                    output_text,
                    fail_fast=False
                )
            )
            # make sure the scanner returned valid results
            if not isinstance(sanitized_output, str):
                raise ValueError("Invalid scanner output")

            # make sure scanner results are available
            if not isinstance(results_valid, dict) or not results_valid:
                raise ValueError("Missing scanner results")

            # make sure every scanner returned True or False
            if not all(
                isinstance(valid, bool)
                for valid in results_valid.values()
            ):
                raise ValueError("Invalid scanner results")

            # make sure every configured scanner reported a result
            expected_scanners = {
                type(scanner).__name__
                for scanner in self.output_scanners
            }

            if not expected_scanners.issubset(results_valid.keys()):
                raise ValueError("Missing output scanner results")

            # print output scanner results for testing
            print("\n")
            print("=" * 60)
            print("OUTPUT GUARDRAIL RESULTS")
            print("=" * 60)

            # print each scanner's pass/fail result and score
            for scanner_name in results_valid:

                print(
                    f"{scanner_name}: "
                    f"valid={results_valid[scanner_name]} "
                    f"risk={results_score[scanner_name]}"
                )

            # block unsafe output if sensitive information was detected
            # collect scanners that marked the response invalid
            failed_scanners = [
                name
                for name, valid in results_valid.items()
                if not valid
            ]

            # block the response if any scanner detects sensitive info
            if failed_scanners:
                sanitized_output = ("Security Alert: Response blocked because sensitive information was detected.")
                
            # replace response with sanitized output
            # handle responses stored as objects or dictionaries
            if hasattr(response_data, "choices"):
                response_data.choices[0].message.content = sanitized_output
            else:
                response_data["choices"][0]["message"]["content"] = sanitized_output
            return response_data

        # catches errors and blocks unsafe responses
        except Exception as error:
            print(f"Output guardrail error: {error}")

            # block the response if scanning fails
            raise RuntimeError(
                "Security Alert: Output security validation failed"
            ) from error

# create the guardrail object used by LiteLLM
enterprise_guardrail = EnterpriseThreatGuardrail()
