from utils.model_utils import call_model_without_tools
from prompts.preprocess_prompt import *

from langchain_core.prompts import ChatPromptTemplate

class ExtractAgent:
    def __init__(self, expert_name, attack_name, payload):
        self.expert_name = expert_name
        self.attack_name = attack_name
        self.payload = payload
        self.prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", extract_agent_system_prompt),
                ("human", extract_agent_human_prompt_template_v1),
            ]
        )
    
    def extract(self):
        prompt = self.prompt_template.invoke({"payload": self.payload, "expert_name": self.expert_name, "attack_name": self.attack_name})
        return call_model_without_tools(prompt)