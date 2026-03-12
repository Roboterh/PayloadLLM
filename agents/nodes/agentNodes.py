import os
import re
import json
import demjson3
import urllib.parse
import operator
import time
from typing import Annotated, Literal, Dict, Any, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, Field
from loguru import logger
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, AnyMessage
from langchain_core.tools import tool
from langgraph.graph import add_messages, END, START, StateGraph, MessagesState
from langgraph.types import Command, Send
from langgraph.errors import Interrupt
from langgraph.prebuilt import create_react_agent, ToolNode

from utils.vectorstore_utils import connection
from prompts.core_prompt import *
from utils.model_utils import *
from agents.tools.agentTools import *
from agents.states.agentStates import *
from agents.forms.agentForms import *
from agents.reactAgents.reactAgents import *

def parser_node(state: OverallState):
    # messages = state["messages"]
    # response = parser_agent.invoke(messages)
    response = parser_agent.invoke(state)
    # print(response)
    return {
        "messages": [
            HumanMessage(content=response["messages"][-1].content, name="parser"),
        ],
    }
    
def classifier_node(state: OverallState):
    retry_count = 5 # the number of retry
    for attempt in range(retry_count):
        try:
            # print(state["httpJson"])
            # response = model.with_structured_output(ClassifyForm).invoke(classifier_prompt3 + state["messages"][-1].content)
            response = model.invoke(classifier_prompt4_without_structure_output1 + state["httpJson"])
            print(response)
            matches = re.findall(r'```json\n(.*?)\n```', response.content, re.DOTALL)

            if matches:
                json_text = matches[0].strip()  # 取第一个 JSON 代码块
                # data = json.loads(json_text)  # 解析 JSON
                data = demjson3.decode(json_text)
                # json_output = json.dumps(data, indent=4, ensure_ascii=False)  # 重新格式化 JSON
                # print(json_output)
                return {
                    "classifierResult": {"SQL": data.get("SQL", {}), "Unknown": data.get("Unknown", {}), "XML": data.get("XML", {}), "JavaScript": data.get("JavaScript", {})},
                }
            else:
                print("No JSON found in the text.")
            
            
            # return {
            #     "classifierResult": {"SQL": response.SQL, "Unknown": response.Unknown, "XML": response.XML, "XSS": response.XSS},
            # }
        except Exception as e:
            # return Send("classifier", {"httpJson": state["httpJson"]})
            print(f"classify failure, try to attempt {attempt + 1} rounds, error messages: {e}")
            time.sleep(1)
        
    
def detector_anomalous_node(state: OverallState):
    print("detector_anomalous_node...")
    print(state)
    # prompt = detector_anomalous_prompt_without_structure_output.replace("{input}", state["httpJson"])
    prompt = detector_anomalous_prompt_without_structure_output_with_fintune_prompt2_0905.replace("{input}", state["httpJson"])
    # response = model.invoke(prompt)
    response = model_finetune.invoke(prompt)
    return {
        "anomalousResult": response.content,
        "flag": "anomalous"
    }

def detector_anomalous_node_for_noDoubleCheck(state: OverallState):
    """消融实验：noDoubleCheck"""
    print("detector_anomalous_node_for_noDoubleCheck...")
    print(state)
    # prompt = detector_anomalous_prompt_without_structure_output.replace("{input}", state["httpJson"])
    prompt = detector_anomalous_prompt_without_structure_output_with_fintune_prompt2_0905.replace("{input}", state["httpJson"])
    # response = model.invoke(prompt)
    response = model_finetune.invoke(prompt)
    return {
        "verify_anomalous_result": response.content,
        "flag": "anomalous"
    }
    # return Command(
    #     update={
    #         "verify_anomalous_result": [response.content],
    #         "originalJson": state["httpJson"],
    #         "flag_category": "anomalous"
    #     },
    #     goto="reporter"
    # )

def detector_anomalous_native_node(state: OverallState):
    print("detector_anomalous_native_node...")
    # prompt = detector_anomalous_prompt_without_structure_output.replace("{input}", state["httpJson"])
    prompt = detector_anomalous_prompt_without_structure_output_with_fintune_prompt2_0905.replace("{input}", state["httpJson"])
    # response = model.invoke(prompt)
    response = model_finetune.invoke(prompt)
    return {
        "anomalousNativeResult": response.content,
        # "flag": "anomalous"
    }

def extractor_node(state: ExtractState):
    print("extractor_node...")
    # error handling
    retry_count = 5 # the number of retry
    for attempt in range(retry_count):
        # prompt = extractor_prompt5_without_structure_output.replace("{expertName}", state["expertName"]).replace("{category}", state["category"]).replace("{input}", state["input"])
        prompt = extractor_prompt6_without_structure_output.replace("{expertName}", state["expertName"]).replace("{category}", state["category"]).replace("{input}", state["input"])
        response = model.invoke(prompt)
        print(response)

        extractor_summary = response.content[response.content.index("Result"):]

        # if "error_syntax" in extractor_summary or "true_syntax" in extractor_summary:
        if ("error_syntax" in extractor_summary and (any(keyword in extractor_summary for keyword in ["null", "XML", "JavaScript", "SQL"])) ) or ("true_syntax" in extractor_summary):
            
            return {
                "contents": [state["input"]],
                # "summarys": [response.content[response.content.index("Output"):]],
                "summarys": [extractor_summary],
                "categorys": [state["category"]]
            }
        print(f"extractor failure, try to attempt {attempt + 1} rounds, error messages: {extractor_summary}")
        time.sleep(1)
    
def sanitize_node(state: OverallState):
    if state["detector_summary_advice"] != []:
        print("detector_summary_advice is not empty, continue to the next round...")
        return {}
    new_contents = []
    new_summarys = []
    new_categorys = []
    new_flags = []
    for i in range(len(state["contents"])):
        if "error_syntax" in state["summarys"][i] or "Error_syntax" in state["summarys"][i] or "false_syntax" in state["summarys"][i] or "False_syntax" in state["summarys"][i]:
            # if "null" not in state["summarys"][i]:
            #     print("sanitizer_node: error_syntax, and the content is null")
            #     if "xml" in state["summarys"][i].lower():
            #         new_categorys.append("XML")
            #     elif "sql" in state["summarys"][i].lower():
            #         new_categorys.append("SQL")
            #     elif "javascript" in state["summarys"][i].lower():
            #         new_categorys.append("JavaScript")
            #         # print("error_syntax")
            #     else:
            #         new_categorys.append("JavaScript")
            #         print("sanitizer_node: error_syntax, and the content is wrong.")
            #     new_contents.append(state["contents"][i])
            #     new_summarys.append(state["summarys"][i])
            #     # new_categorys.append(state["categorys"][i])
            #     new_flags.append("vulnerable")
            # else:
            #     continue
            
            print("sanitizer_node: error_syntax, and the content is null")
            if "xml" in state["summarys"][i].lower():
                new_categorys.append("XML")
            elif "sql" in state["summarys"][i].lower():
                new_categorys.append("SQL")
            elif "javascript" in state["summarys"][i].lower():
                new_categorys.append("JavaScript")
                # print("error_syntax")
            else:
                new_categorys.append("JavaScript")
                print("sanitizer_node: error_syntax, and the content is wrong.")
            new_contents.append(state["contents"][i])
            new_summarys.append(state["summarys"][i])
            # new_categorys.append(state["categorys"][i])
            new_flags.append("vulnerable")
        else:
            new_contents.append(state["contents"][i])
            new_summarys.append(state["summarys"][i])
            new_categorys.append(state["categorys"][i])
            new_flags.append("vulnerable")
        # new_contents.append(state["contents"][i])
        # new_summarys.append(state["summarys"][i])
        # new_categorys.append(state["categorys"][i])

    # detect optional vulnerabilities
    return {
        "contentsSanitized": new_contents,
        "summarysSanitized": new_summarys,
        "categorysSanitized": new_categorys,
        "flag": "vulnerable",
    }
    
def sanitizer_anomalous_pre_node(state: OverallState):
    print("sanitizer_anomalous_pre_node...")
    print(state)
    return {}

def detector_payload_node(state: DetectState):
    # print(state)
    if state["categoryDetect"].lower().startswith("sql"):
        if state["detector_content_advice"] != "none":
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("javascript"):
        if state["detector_content_advice"] != "none":
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("xml"):
        if state["detector_content_advice"] != "none":
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    else:
        response = None
    return {
        # "messages": [
        #     HumanMessage(content=response["messages"][-1].content, name="detector_payload"),
        # ],
        "contentsResult": [response.content],
    }
    
def detector_payload_node_for_no_double_malicious_check(state: DetectState):
    # print(state)
    if state["categoryDetect"].lower().startswith("sql"):
        if state["detector_content_advice"] != "none":
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("javascript"):
        if state["detector_content_advice"] != "none":
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("xml"):
        if state["detector_content_advice"] != "none":
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    else:
        response = None
    return {
        # "messages": [
        #     HumanMessage(content=response["messages"][-1].content, name="detector_payload"),
        # ],
        "contentsResult": [response.content],
        "verifyResult": [response.content],
        "flag": "vulnerable"
    }

def detector_payload_node_for_no_rag(state: DetectState):
    # print(state)
    if state["categoryDetect"].lower().startswith("sql"):
        if state["detector_content_advice"] != "none":
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("javascript"):
        if state["detector_content_advice"] != "none":
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xss_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xss_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    elif state["categoryDetect"].lower().startswith("xml"):
        if state["detector_content_advice"] != "none":
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content=detector_content_advice_prompt.format(detector_content_advice=state["detector_content_advice"]) + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_advice_prompt.replace("{detector_content_advice}", state["detector_content_advice"]).replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
        else:
            # response = detector_xxe_payload_agent.invoke({"messages": HumanMessage(
            #         content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_payload"
            #     )})
            prompt = detector_xxe_payload_cot_prompt.replace("{payload}", state["contentDetect"])
            response = model.invoke(prompt)
    else:
        response = None
    return {
        # "messages": [
        #     HumanMessage(content=response["messages"][-1].content, name="detector_payload"),
        # ],
        "contentsResult": [response.content],
    }

def detector_summary_node(state: DetectState):
    # print(state)
    if state["categoryDetect"].lower().startswith("sql"):
        if state["detector_summary_advice"] != "none":
            response = detector_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    elif state["categoryDetect"].lower().startswith("javascript"):
        if state["detector_summary_advice"] != "none":
            response = detector_xss_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_xss_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    elif state["categoryDetect"].lower().startswith("xml"):
        if state["detector_summary_advice"] != "none":
            response = detector_xxe_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_xxe_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    else:
        response = None
    return {
        # "messages": [
        #     HumanMessage(content=response["messages"][-1].content, name="detector_summary"),
        # ],
        "summarysResult": [response["messages"][-1].content],
    }
    
def detector_summary_node_for_no_double_malicious_check(state: DetectState):
    # print(state)
    if state["categoryDetect"].lower().startswith("sql"):
        if state["detector_summary_advice"] != "none":
            response = detector_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    elif state["categoryDetect"].lower().startswith("javascript"):
        if state["detector_summary_advice"] != "none":
            response = detector_xss_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_xss_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    elif state["categoryDetect"].lower().startswith("xml"):
        if state["detector_summary_advice"] != "none":
            response = detector_xxe_summary_agent.invoke({"messages": HumanMessage(
                    content=detector_summary_advice_prompt.format(detector_summary_advice=state["detector_summary_advice"]) + state["contentDetect"], name="detector_summary"
                )})
        else:
            response = detector_xxe_summary_agent.invoke({"messages": HumanMessage(
                    content="Please check whether the following string contains the corresponding attack behavior:\n" + state["contentDetect"], name="detector_summary"
                )})
    else:
        response = None
    return {
        # "messages": [
        #     HumanMessage(content=response["messages"][-1].content, name="detector_summary"),
        # ],
        "summarysResult": [response["messages"][-1].content],
        "verifyResult": [response["messages"][-1].content],
        "flag": "vulnerable"
    }

def sanitizer_detect_node(state: OverallState):
    print("sanitizer_detect_node...")
    # print(state)
    return {}

def sanitizer_detect_node_for_single_malicious_detector(state: OverallState):
    print("sanitizer_detect_node_for_single_malicious_detector...")
    # print(state)
    return {
        "categoryVerify": state["categoryDetect"],
    }

def sanitizer_detect_anomalous_node(state: OverallState):
    print("sanitizer_detect_anomalous_node...")
    # print(state)
    return {}


# def verifier_node_outdated(state: VerifyState):
#     prompt = verifier_prompt.format(statement=state["originalStatement"], contentResult=state["contentVerify"], summaryResult=state["summaryVerify"])
#     response = model.invoke(prompt)
#     return {
#         "verifyResult": [response],
#         "messages": [
#             HumanMessage(content=response, name="verifier")
#         ]
#     }

def verifier_node(state: VerifyState):
    # # the judgement of the result of the two detectors
    # prompt_consistency = verifier_consistency_prompt.format(category=state["categoryVerify"], contentResult=state["contentVerify"], summaryResult=state["summaryVerify"])
    # response_consistency = model.invoke(prompt_consistency)
    # if "true" or "True" in response_consistency.content:
    #     # if there are consistent, keep going down
    #     prompt = verifier_prompt.format(category=state["categoryVerify"], statement=state["originalStatement"], contentResult=state["contentVerify"], summaryResult=state["summaryVerify"])
    #     response = model.invoke(prompt)
    #     # print(response.content)
    #     return {
    #         "verifyResult": [response.content],
    #         "messages": [
    #             HumanMessage(content=response.content, name="verifier")
    #         ]
    #     }
    # elif "false" or "False" in response_consistency.content:
    #     # if there are inconsistent, fall back to the detector stage
    #     # print(response_consistency)
    #     detector_content_advice_index = response_consistency.content.index("detector_content_advice")
    #     detector_summary_advice_index = response_consistency.content.index("detector_summary_advice")
    #     return Command(
    #         update={
    #             "detector_content_advice": response_consistency[detector_content_advice_index:detector_summary_advice_index],
    #             "detector_summary_advice": response_consistency[detector_summary_advice_index:]
    #         },
    #         goto="sanitizer"
    #     )
    print("verifier_node...")
    retry_count = 5
    for attempt in range(retry_count):
        prompt = verifier_and_consistency_prompt_without_structure_output1.format(category=state["categoryVerify"], statement=state["originalStatement"], contentResult=state["contentVerify"], summaryResult=state["summaryVerify"])
        response = model.invoke(prompt)
        # print(response.content)
        response_content = response.content
        print(f"the response_content of round {attempt}: " + response_content)
        # response_content = "flag=0detector_content_advice: nonedetector_summary_advice:none"
        # return Command(
        #     update={
        #         # "repeat_str": "anomalous_repeat",
        #         # "httpJson_repeat": state["originalStatement"]
        #         # "messages": [],
        #         # "contents": [],
        #         # "summarys": [],
        #         # "categorys": [],
        #         # "contentsSanitized": [],
        #         # "summarysSanitized": [],
        #         # "categorysSanitized": [],
        #         # "contentsResult": [],
        #         # "summarysResult": [],
        #         # "verifyResult": [],
        #         # "classifierResult": {},
        #         # "flag": "",
                
        #         "httpJson": state["httpJson"]
        #     },
        #     goto="sanitizer_anomalous_pre"
        # )
        if "flag=1" in response_content:
            if "attack: false" in response_content:
                print("verifier_node: no malicious behavior detected, fall back to anomalous detect...")
                return Command(
                    update={
                        # "messages": [],
                        # "contents": [],
                        # "summarys": [],
                        # "categorys": [],
                        # "contentsSanitized": [],
                        # "summarysSanitized": [],
                        # "categorysSanitized": [],
                        # "contentsResult": [],
                        # "summarysResult": [],
                        # "verifyResult": [],
                        # "classifierResult": {},
                        # "flag": "",
                        # "httpJson": state["httpJson"]
                    },
                    goto="sanitizer_anomalous_pre"
                )
            return {
                "verifyResult": [response_content],
                "messages": [
                    HumanMessage(content=response_content, name="verifier")
                ]
            }
        elif "flag=0" in response_content:
            detector_content_advice_index = response_content.index("detector_content_advice")
            detector_summary_advice_index = response_content.index("detector_summary_advice")
            return Command(
                update={
                    "detector_content_advice": [response_content[detector_content_advice_index:detector_summary_advice_index]],
                    "detector_summary_advice": [response_content[detector_summary_advice_index:]]
                },
                goto="sanitizer"
            )
        print(f"verify failure, try to attempt {attempt + 1} rounds, error messages: have no flag")
        time.sleep(1)
        # if (attempt + 1) == 10:
        #     exit("verify has no flag")

def verifier_anomalous_node(state: VerifyState):
    print("verifier_anomalous_node...")
    retry_count = 5
    for attempt in range(retry_count):
        prompt = verifier_anomalous_and_consistency_prompt_without_structure_output1.format(statement=state["originalStatement"], contentResult=state["contentVerify"], summaryResult=state["summaryVerify"])
        response = model.invoke(prompt)
        # print(response.content)
        response_content = response.content
        print(f"the response_content of round {attempt}: " + response_content)
        # response_content = "flag=0detector_content_advice: nonedetector_summary_advice:none"
        if "flag=1" in response_content:
            # return {
            #     "verify_anomalous_result": [response_content],
            #     "messages": [
            #         HumanMessage(content=response_content, name="verifier")
            #     ]
            # }
            return Command(
                update={
                    "verify_anomalous_result": [response_content],
                    "messages": [
                        HumanMessage(content=response_content, name="verifier")
                    ]
                },
                goto="sanitizer_verify_node"
            )
        elif "flag=0" in response_content:
            # detector_content_advice_index = response_content.index("detector_content_advice")
            # detector_summary_advice_index = response_content.index("detector_summary_advice")
            # return Command(
            #     update={
            #         "detector_content_advice": [response_content[detector_content_advice_index:detector_summary_advice_index]],
            #         "detector_summary_advice": [response_content[detector_summary_advice_index:]]
            #     },
            #     goto="sanitizer"
            # )
            # result = []
            # result.append(Send("detector_anomalous", {"httpJson": state["httpJson_store"]}))
            # result.append(Send("detector_anomalous_native", {"httpJson": state["httpJson_store"]}))
            return Command(
                update={
                    "repeat_str": "anomalous_repeat",
                    # "httpJson_repeat": state["originalStatement"]
                },
                goto="sanitizer_anomalous_pre"
            )
        print(f"verify failure, try to attempt {attempt + 1} rounds, error messages: have no flag")
        time.sleep(1)
        # if (attempt + 1) == 10:
        #     exit("verify has no flag")

def sanitizer_verify_node(state: OverallState):
    print("sanitizer_verify_node...")
    print(state)
    return {}

def sanitizer_verify_node_for_single_malicious_detector(state: OverallState):
    print("sanitizer_verify_node_for_single_malicious_detector...")
    print(state)
    retry_count = 5
    for attempt in range(retry_count):
        prompt = xiaohong_for_single_detetor_prompt.format(category=state["categorysSanitized"], statement=state["contentsSanitized"], Result=state["verifyResult"])
        response = model.invoke(prompt)
        # print(response.content)
        response_content = response.content
        print(f"the response_content of round {attempt}: " + response_content)
        if "attack: false" in response_content:
            print("sanitizer_verify_node_for_single_malicious_detector: no malicious behavior detected, fall back to anomalous detect...")
            return Command(
                update={
                },
                goto="sanitizer_anomalous_pre"
            )
        elif "attack: true" in response_content:
            return {}
        print(f"verify failure, try to attempt {attempt + 1} rounds, error messages: have no flag")
        time.sleep(1)
    return {}

def _try_parse_json(text: str):
    """
    先用严格 JSON 解析，失败再用 demjson3 宽松解析（可容忍单引号/尾逗号等）。
    成功返回 python 对象，失败返回 None。
    """
    s = text.strip()
    if not s:
        return None

    # 1) 严格 JSON
    try:
        return json.loads(s)
    except Exception:
        pass

    # 2) demjson3 宽松解析（可选）
    try:
        return demjson3.decode(s)
    except Exception:
        return None


def parse_response_json(content: str):
    """
    优先判断 content 是否本身就是 JSON；
    否则再尝试从 ```json ...``` 代码块中提取；
    再否则尝试从文本中抓取第一个 JSON 对象/数组片段。
    """
    # A. content 本身就是 JSON
    data = _try_parse_json(content)
    if data is not None:
        return data

    # B. 代码块 ```json ... ```
    m = re.search(r"```json\s*(.*?)\s*```", content, re.DOTALL | re.IGNORECASE)
    if m:
        json_text = m.group(1).strip()
        data = _try_parse_json(json_text)
        if data is not None:
            return data

        # 你原来那种“反斜杠清理”也可以只在这里兜底用
        cleaned = re.sub(r'\\+', r'\\', json_text)
        data = _try_parse_json(cleaned)
        if data is not None:
            return data

    # C. 最后兜底：从全文提取第一个 {...} 或 [...]
    # 注意：简单正则无法完美处理嵌套括号/字符串里的括号，这里只做最后兜底
    m2 = re.search(r"(\{.*\}|\[.*\])", content, re.DOTALL)
    if m2:
        candidate = m2.group(1).strip()
        data = _try_parse_json(candidate)
        if data is not None:
            return data

    return None

def reporter_node(state: ReportState):
    retry_count = 5 # the number of retry
    for attempt in range(retry_count):
        try:
            if state["flag_category"] == "vulnerable":
                prompt = reporter_prompt1.format(verifyResult=state["verifierResult"], originalJson=state["originalJson"], vulStatement=state["vulStatement"])
                # response = model.with_structured_output(ReportForm).invoke(prompt)
                response = model_temp.invoke(prompt)

                print("reporter_node: vulnerable...")
                print(response)
                
                data = parse_response_json(response.content)
                if data is None:
                    print("reporter_node: response is not JSON and no JSON block found")
                    continue

                # guard
                if "2/" in data.get("statement", "") and "2/" not in state["originalJson"]:
                    print("reporter_node: the statement contains 2/ but the originalJson does not contain 2/, re-report...")
                    continue

                reportResult_tmp = [{
                    "vuln": data.get("vuln"),
                    "position": data.get("position"),
                    "statement": data.get("statement"),
                    "cause": data.get("cause"),
                }]

                return {"reporterResult": reportResult_tmp}
                
                # matches = re.findall(r'```json\n(.*?)\n```', response.content, re.DOTALL)
                # if matches:
                #     json_text = matches[0].strip()  # 取第一个 JSON 代码块
                #     # data = json.loads(json_text)  # 解析 JSON
                #     print(json_text)
                #     cleaned_text = re.sub(r'\\+', r'\\', json_text) # 移除多余的反斜杠
                #     print("cleaned_text:" + cleaned_text)
                #     data = demjson3.decode(cleaned_text)
                #     # json_output = json.dumps(data, indent=4, ensure_ascii=False)  # 重新格式化 JSON
                #     # print(json_output)
                    
                #     # guard
                #     if "2/" in data["statement"] and "2/" not in state["originalJson"]:
                #         print("reporter_node: the statement contains 2/ but the originalJson does not contain 2/, re-report...")
                #         continue
                    
                #     reportResult_tmp = [{"vuln": data["vuln"], "position": data["position"], "statement": data["statement"], "cause": data["cause"]}]
                    
                #     # #### report audit start
                #     # prompt_report_audit = report_audit_prompt.replace("{reportResult}", str(reportResult_tmp))
                #     # response_report_audit = model.invoke(prompt_report_audit)
                #     # print("report_audit response:")
                #     # print(response_report_audit)
                #     # matches_ = re.findall(r'```text\n(.*?)\n```', response_report_audit.content, re.DOTALL)
                #     # if matches_:
                #     #     matches_contence = matches_[0].strip()  # 取第一个 代码块
                #     #     confidence = float(re.search(r"confidence=([\d.]+)", matches_contence).group(1))
                #     #     if "flag=1" in matches_contence and confidence > 0.5:
                #     #         print("report audit passed.")
                #     #         return {
                #     #             "reporterResult": reportResult_tmp, 
                #     #         }
                #     #     elif "flag=0" in matches_contence or confidence > 0.5:
                #     #         print("report audit not passed, need to re-report.")
                #     #         return Command(
                #     #             update={
                #     #                 "contents": [],
                #     #                 "summarys": [],
                #     #                 "categorys": [],
                #     #                 "contentsSanitized": [],
                #     #                 "summarysSanitized": [],
                #     #                 "categorysSanitized": [],
                #     #                 "contentsResult": [],
                #     #                 "summarysResult": [],
                #     #                 "verifyResult": [],
                #     #                 "classifierResult": {},
                #     #                 "reporterResult": [],
                #     #                 "flag": "",
                #     #                 "detector_content_advice": [],
                #     #                 "detector_summary_advice": [],
                #     #                 "httpJson_repeat": []
                #     #             },
                #     #             goto="classifier"
                #     #         )
                #     # #### report audit end
                    
                #     # return {
                #     #     "reporterResult": reportResult_tmp,
                #     # }
                
                #     return {
                #         "reporterResult": reportResult_tmp,
                #     }
            elif state["flag_category"] == "anomalous":
                prompt = reporter_anomalous_prompt2.replace("{verifyResult}", str(state["verifierResult"])).replace("{originalJson}", state["originalJson"])
                # response = model.with_structured_output(AnomalousForm).invoke(prompt)
                response = model.invoke(prompt)
                print("reporter_node: anomalous...")
                print(response)
                
                matches = re.findall(r'```json\n(.*?)\n```', response.content, re.DOTALL)
                if matches:
                    json_text = matches[0].strip()  # 取第一个 JSON 代码块
                    # data = json.loads(json_text)  # 解析 JSON
                    print(json_text)
                    data = demjson3.decode(json_text)
                    print(data)
                    # json_output = json.dumps(data, indent=4, ensure_ascii=False)  # 重新格式化 JSON
                    # print(json_output)
                    
                    # guard
                    if "2/" in data["statement"] and "2/" not in state["originalJson"]:
                        print("reporter_node: the statement contains 2/ but the originalJson does not contain 2/, re-report...")
                        continue
                    
                    reportResult_tmp = [{"result": data["result"], "position": data["position"], "statement": data["statement"], "cause": data["cause"]}]
                    
                    # if reportResult_tmp[0]["result"].lower() == "normal":
                    #     print("reporter_node: anomalous but the result is normal, directly return.")
                    #     return {
                    #         "reporterResult": reportResult_tmp,
                    #     }
                    
                    # #### report audit start
                    # prompt_report_audit = report_audit_prompt.replace("{reportResult}", str(reportResult_tmp))
                    # response_report_audit = model.invoke(prompt_report_audit)
                    # print("report_audit response:")
                    # print(response_report_audit)
                    # matches_ = re.findall(r'```text\n(.*?)\n```', response_report_audit.content, re.DOTALL)
                    # if matches_:
                    #     matches_contence = matches_[0].strip()  # 取第一个 代码块
                    #     confidence = float(re.search(r"confidence=([\d.]+)", matches_contence).group(1))
                    #     if "flag=1" in matches_contence and confidence > 0.5:
                    #         print("report audit passed.")
                    #         return {
                    #             "reporterResult": reportResult_tmp, 
                    #         }
                    #     elif "flag=0" in matches_contence or confidence > 0.5:
                    #         print("report audit not passed, need to re-report.")
                    #         return Command(
                    #             update={
                    #                 "repeat_str": "anomalous_repeat",
                    #             },
                    #             goto="sanitizer_anomalous_pre"
                    #         )
                    # #### report audit end
                    
                    
                    # return {
                    #     "reporterResult": reportResult_tmp,
                    # }            
    
                    return {
                        "reporterResult": reportResult_tmp,
                    }
        except Exception as e:
            print(f"report failure, try to attempt {attempt + 1} rounds, error messages: {e}")
            time.sleep(1)
            # if (attempt + 1) == 10:
            #     exit(e)