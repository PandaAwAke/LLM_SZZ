from openai import OpenAI
import os

class LLM:
    def __init__(self, model):
        if model == "deepseek-chat":
            model = "deepseek-v3.2"
            self.api_key = ""
            self.base_url = f"https://api.deepseek.com"
        
        elif model == "gpt-3.5-turbo-0125": 
            self.api_key = ""
            self.base_url = f""


        # elif model == "gpt-4o-2024-08-06":
        #     self.api_key = ""
        #     self.base_url = f""
            
        
        # elif model == "gpt-4o-mini-2024-07-18":
        #     self.api_key = ""
        #     self.base_url = f""



        self.model = model
        self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)


    def run_model(self, input_text):
        messages = []
        allow_system_prompt = False
        system_prompt = "You are a code vulnerability expert adept at identifying security flaws. Your expertise lies in analyzing commit messages, fixing commits, and understanding the context of the code to pinpoint vulnerabilities. With a keen eye for detail, you excel at sifting through lines of code and version history to detect and mitigate potential security risks."
        if allow_system_prompt:
            messages.append(
                {
                    "role": "system",
                    "content": system_prompt,
                }
            )
            messages.append({"role": "user", "content": input_text})
        else:
            messages.append({"role": "user", "content": system_prompt + input_text})



        response = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            # temperature=temperature,
           
        )

        return response.choices[0].message.content