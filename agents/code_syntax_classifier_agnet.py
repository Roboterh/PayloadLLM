from prompts.preprocess_prompt import *
from utils.model_utils import call_model_without_tools

from langchain_core.prompts import ChatPromptTemplate

class CodeSyntaxClassifierAgent:
    def __init__(self, code):
        self.code = code
        self.prompt_template = ChatPromptTemplate.from_messages(
            [
                ("system", code_syntax_classifier_system_prompt),
                ("human", code_syntax_classifier_human_prompt_template),
            ]
        )
    def classify(self):
        prompt = self.prompt_template.invoke({"code": self.code})
        return call_model_without_tools(prompt)