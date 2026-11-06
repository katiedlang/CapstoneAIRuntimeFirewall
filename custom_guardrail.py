# run scanning tasks without blocking other asyncronous operations
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
            return data

        # find most recent user message
        user_prompt = ""

        # search backward to find most recent message
        for message in reversed(messages):

            if message.get("role") == "user":

                user_prompt = message.get("content","")
                break

        # make sure prompt is a str before scanning
        if not isinstance(user_prompt, str):

            return data

        # skip scanning if prompt is empty
        if not user_prompt.strip():

            return data

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
            # get response choices
            choices = response_data.get(
                "choices",
                []
            )

            # if no response exists, return it unchanged
            if not choices:
                return response_data

            # get first response message
            message = choices[0].get(
                "message",
                {}
            )

            # get text generated by the AI
            output_text = message.get(
                "content",
                ""
            )

            # make sure response has text
            if not isinstance(
                output_text,
                str
            ):
                return response_data

            # skip scanning if the response is empty
            if not output_text.strip():
                return response_data

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

            # if sensitive information was detected but the output
            # was not changed, replace it with a security warning
            if failed_scanners and sanitized_output == output_text:
                sanitized_output = (
                    "Security Alert: Response blocked because "
                    "sensitive information was detected."
                )
                
            # replace response with sanitized output
            # handle responses stored as objects or dictionaries
            if hasattr(response_data, "choices"):
                response_data.choices[0].message.content = sanitized_output
            else:
                response_data["choices"][0]["message"]["content"] = sanitized_output
            return response_data

        # catches and prints any errors during output scanning
        except Exception as error:
            print(f"Output guardrail error: {error}")
            return response_data

# create the guardrail object used by LiteLLM
enterprise_guardrail = EnterpriseThreatGuardrail()
