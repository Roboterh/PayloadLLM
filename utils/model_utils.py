import os
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_community.chat_models import ChatZhipuAI
from langchain import hub
from langchain_ollama import ChatOllama


model = ChatOpenAI(model="Qwen3-8B", api_key="ollama", base_url="http://xxxx:8001/v1/") # native model
model_finetune = ChatOpenAI(model="Qwen3-8B-finetune", api_key="ollama", base_url="http://xxxx:8002/v1/") # finetune model
model_temp = ChatOpenAI(model="Qwen3-8B", api_key="ollama", base_url="http://xxxx:8001/v1/", temperature=0.1)


def call_model_without_tools(prompt):
    res = model.invoke(prompt)
    return res.content
    
def prompt_maker(task, lazy_prompt):
    prompt_template = hub.pull("hardkothari/prompt-maker")
    prompt = prompt_template.invoke({"task": task, "lazy_prompt": lazy_prompt})
    # print(prompt)
    prompt_improved = model.invoke(prompt)
    
    return prompt_improved