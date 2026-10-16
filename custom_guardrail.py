import asyncio

from litellm.integrations.custom_guardrail import CustomGuardrail

from llm_guard import scan_prompt, scan_output

from llm_guard.input_scanners import (
    PromptInjection,
    InvisibleText,
    Secrets,
    TokenLimit,
)

from llm_guard.output_scanners import Sensitive


class EnterpriseThreatGuardrail(CustomGuardrail):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # ----------------------------
        # INPUT SCANNERS
        # ----------------------------

        self.input_scanners = [

            PromptInjection(
                threshold=0.80
            ),

            InvisibleText(),

            Secrets(),

            TokenLimit(
                limit=4096
            ),
        ]

        # ----------------------------
        # OUTPUT SCANNERS
        # ----------------------------

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
    # Runs BEFORE request reaches the LLM
    # =====================================================

    async def async_pre_call_hook(
        self,
        user_api_key_dict,
        cache,
        data,
        call_type
    ):

        messages = data.get("messages", [])

        if not messages:
            return data

        # Find latest user message
        user_prompt = ""

        for message in reversed(messages):

            if message.get("role") == "user":

                user_prompt = message.get(
                    "content",
                    ""
                )

                break


        if not isinstance(user_prompt, str):

            return data


        if not user_prompt.strip():

            return data


        loop = asyncio.get_running_loop()


        # Run all input scanners
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


        print("\n")
        print("=" * 60)
        print("INPUT GUARDRAIL RESULTS")
        print("=" * 60)


        for scanner_name in results_valid:

            print(
                f"{scanner_name}: "
                f"valid={results_valid[scanner_name]} "
                f"risk={results_score[scanner_name]}"
            )


        # Determine which scanners blocked request
        failed_scanners = [

            scanner_name

            for scanner_name, valid
            in results_valid.items()

            if not valid
        ]


        if failed_scanners:

            raise Exception(

                "Security Alert: Input blocked by "
                + ", ".join(failed_scanners)
            )


        # Replace original prompt with sanitized prompt
        for message in reversed(messages):

            if message.get("role") == "user":

                message["content"] = sanitized_prompt

                break


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
        response_data = response

        try:

            choices = response_data.get(
                "choices",
                []
            )

            if not choices:

                return response_data


            message = choices[0].get(
                "message",
                {}
            )


            output_text = message.get(
                "content",
                ""
            )


            if not isinstance(
                output_text,
                str
            ):

                return response_data


            if not output_text.strip():

                return response_data


            # Get original user prompt
            messages = data.get(
                "messages",
                []
            )

            original_prompt = ""


            for msg in reversed(messages):

                if msg.get("role") == "user":

                    original_prompt = msg.get(
                        "content",
                        ""
                    )

                    break


            loop = asyncio.get_running_loop()


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


            print("\n")
            print("=" * 60)
            print("OUTPUT GUARDRAIL RESULTS")
            print("=" * 60)


            for scanner_name in results_valid:

                print(
                    f"{scanner_name}: "
                    f"valid={results_valid[scanner_name]} "
                    f"risk={results_score[scanner_name]}"
                )

            # Block unsafe output if sensitive information was detected
            failed_scanners = [
                name
                for name, valid in results_valid.items()
                if not valid
            ]

            if failed_scanners and sanitized_output == output_text:
                sanitized_output = (
                    "Security Alert: Response blocked because "
                    "sensitive information was detected."
                )
                
            # Replace response with sanitized output
            if hasattr(response_data, "choices"):
                response_data.choices[0].message.content = sanitized_output
            else:
                response_data["choices"][0]["message"]["content"] = sanitized_output

            return response_data


        except Exception as error:

            print(
                f"Output guardrail error: {error}"
            )

            return response_data


enterprise_guardrail = EnterpriseThreatGuardrail()
