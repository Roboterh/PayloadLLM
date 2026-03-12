import os
import re
import json
import urllib.parse
import operator
import threading
from typing import Annotated, Literal, Dict, Any, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, Field
from loguru import logger
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, AnyMessage
from langchain_core.tools import tool
from langgraph.graph import add_messages, END, START, StateGraph, MessagesState
from langgraph.types import Command, Send
from langgraph.prebuilt import create_react_agent, ToolNode

from utils.vectorstore_utils import connection
from prompts.core_prompt import *
from utils.model_utils import *
from agents.tools.agentTools import *
from agents.states.agentStates import *
from agents.forms.agentForms import *
from agents.nodes.agentNodes import *


################ experiments #######################
is_twice_progress_run = False # 判断是否是 first 实验的增量检测流程
is_no_anomalous_double_check = False # 消融实验：noAnomalousDoubleCheck
is_no_malicious_double_check_only_payload_detect = False # 消融实验：noMaliciousDoubleCheck
is_no_malicious_double_check_only_summary_detect = False
is_no_rag = False # 消融实验：noRAG

report_dir = "report_exp/report_xxxx-with-Qwen3-8B-twice"
error_dir = "report_exp/error_log_xxxx-with-Qwen3-8B-twice"


### datasets
# 188
datasets_path = "datasets/anomalousTrafficTest_xxxx.txt"

# 记录本次请求的所有requests
requests_bak = []

members = ["parser", "extractor", "detector", "verifier", "reporter"]

options = members + ["FINISH"]

class Router(TypedDict):
    """Worker to route to next. If no workers needed, route to FINISH."""
    next: Literal["parser", "extractor", "detector", "verifier", "reporter", "FINISH"]
    
    
# def supervisor_node(state: OverallState) -> Command[Literal["parser", "extractor", "detector", "verifier", "reporter", "FINISH"]]:
#     messages = SystemMessage(supervisor_prompt) + state["messages"]
#     response = model.with_structured_output(Router).invoke(messages)
#     goto = response["next"]
#     if goto == "FINISH":
#         goto = END
    
#     return Command(goto=goto, update={"next": goto})


# def parser_node(state: OverallState) -> Command[Literal["supervisor"]]:
#     messages = state["messages"]
#     response = parser_agent.invoke(messages)
#     print("parser_node:\n" + response + "\n")
#     return Command(
#         update={
#             "messages": [
#                 HumanMessage(content=response["messages"][-1].content, name="parser"),
#             ]
#         },
#         goto="supervisor",
#     )

def get_requests_from_datasets():
    global requests_bak
    
    with open(datasets_path, "r") as file:
        raw_requests = file.read()
    # 确保换行符格式一致（适用于 Windows / Linux / macOS）
    raw_requests = raw_requests.replace("\r\n", "\n").strip()

    # 通过 `GET|POST|PUT|DELETE` 作为分割点，但保留匹配的请求方法
    requests = re.split(r"(?=^(?:GET|POST|PUT|DELETE) )", raw_requests, flags=re.MULTILINE)

    # 过滤掉空白项
    requests = [req.strip() for req in requests if req.strip()]
    
    requests_bak = requests
    
def find_deepest_value(data, depth=0, max_depth=[-1], result=[None]):
    """ 递归查找最深层的值（只返回值，不返回 Key） """
    if isinstance(data, dict):
        for value in data.values():
            find_deepest_value(value, depth + 1, max_depth, result)
    elif isinstance(data, list):
        for item in data:
            find_deepest_value(item, depth + 1, max_depth, result)
    else:
        # 处理普通值（字符串、整数等）
        if depth > max_depth[0]:
            max_depth[0] = depth
            result[0] = data  # 只存最深的值
    return result[0]

def find_values(contents, find_values_result):
    if isinstance(contents, dict):
        for key in contents:    
            find_values(contents[key], find_values_result)
    elif isinstance(contents, list):
        # print(contents[0])
        find_values_result.append(contents[0])

def contine_to_extractor_or_anomalous(state: OverallState):
    print("contine_to_extractor...")
    print(state)
    try:
        result = []
        for key in state["classifierResult"]:
            print(key)
            if key != "Unknown" and state["classifierResult"][key] != {}:
                print(key)
                for keykey in state["classifierResult"][key]:
                    print(keykey)
                    # print("classifierResult: " + state["classifierResult"])
                    find_values_result = []
                    find_values(state["classifierResult"][key][keykey], find_values_result)
                    print(find_values_result)
                    for value in find_values_result:
                        print(value)
                        result.append(Send("extractor", {"input": value, "expertName": key, "category": key}))
                    # if isinstance(state["classifierResult"][key][keykey], dict) or isinstance(state["classifierResult"][key][keykey], list):
                    #     result.append(Send("extractor", {"input": find_deepest_value(state["classifierResult"][key][keykey]), "expertName": key, "category": key}))
                    # else:
                    #     result.append(Send("extractor", {"input": state["classifierResult"][key][keykey], "expertName": key, "category": key}))
        
        if len(result) == 0:
            print("no vulnerable content found, go to anomalous sanitizer...")
            result.append(Send("sanitizer_anomalous_pre", {"httpJson": state["httpJson"]}))
        # print("result: " + result)
        return result
    except Exception:
        pass

def contine_to_detector_or_anomalous(state: OverallState):
    print("contine_to_detector_or_anomalous...")
    print(state)
    try:
        result = []
        if state["contentsSanitized"] != [] and state["summarysSanitized"] != []:
            detector_content_advice = state.get("detector_content_advice", "none")
            detector_summary_advice = state.get("detector_summary_advice", "none")
            print("detector_content_advice: " + str(detector_content_advice))
            print("detector_summary_advice: " + str(detector_summary_advice))
            for l in range(len(state["categorysSanitized"])):
                result.append(Send("detector_payload", {"contentDetect": state["contentsSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_content_advice": str(detector_content_advice)}))
                result.append(Send("detector_summary", {"contentDetect": state["summarysSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_summary_advice": str(detector_summary_advice)}))
        elif state["contentsSanitized"] == []:
            print("contentsSanitized is empty...")
            result.append(Send("sanitizer_anomalous_pre", {"httpJson": state["httpJson"]}))
        else:
            print("contine_to_detector_or_anomalous... if-elif condition wrong")
        return result
    except Exception:
        pass
    
def contine_to_detector_or_anomalous_for_no_double_malicious_check_only_payload(state: OverallState):
    print("contine_to_detector_or_anomalous_for_no_double_malicious_check_only_payload...")
    print(state)
    try:
        result = []
        if state["contentsSanitized"] != [] and state["summarysSanitized"] != []:
            detector_content_advice = state.get("detector_content_advice", "none")
            detector_summary_advice = state.get("detector_summary_advice", "none")
            print("detector_content_advice: " + str(detector_content_advice))
            print("detector_summary_advice: " + str(detector_summary_advice))
            for l in range(len(state["categorysSanitized"])):
                result.append(Send("detector_anomalous_for_no_double_check_only_payload", {"contentDetect": state["contentsSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_content_advice": str(detector_content_advice)}))
                # result.append(Send("detector_summary", {"contentDetect": state["summarysSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_summary_advice": str(detector_summary_advice)}))
        elif state["contentsSanitized"] == []:
            print("contentsSanitized is empty...")
            result.append(Send("sanitizer_anomalous_pre", {"httpJson": state["httpJson"]}))
        else:
            print("contine_to_detector_or_anomalous... if-elif condition wrong")
        return result
    except Exception:
        pass

def contine_to_detector_or_anomalous_for_no_double_malicious_check_only_summary(state: OverallState):
    print("contine_to_detector_or_anomalous_for_no_double_malicious_check_only_summary...")
    print(state)
    try:
        result = []
        if state["contentsSanitized"] != [] and state["summarysSanitized"] != []:
            detector_content_advice = state.get("detector_content_advice", "none")
            detector_summary_advice = state.get("detector_summary_advice", "none")
            print("detector_content_advice: " + str(detector_content_advice))
            print("detector_summary_advice: " + str(detector_summary_advice))
            for l in range(len(state["categorysSanitized"])):
                # result.append(Send("detector_payload", {"contentDetect": state["contentsSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_content_advice": str(detector_content_advice)}))
                result.append(Send("detector_anomalous_for_no_double_check_only_summary", {"contentDetect": state["summarysSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_summary_advice": str(detector_summary_advice)}))
        elif state["contentsSanitized"] == []:
            print("contentsSanitized is empty...")
            result.append(Send("sanitizer_anomalous_pre", {"httpJson": state["httpJson"]}))
        else:
            print("contine_to_detector_or_anomalous... if-elif condition wrong")
        return result
    except Exception:
        pass

def contine_to_detect_anomalous(state: OverallState):
    print("contine_to_detect_anomalous...")
    print(state)
    result = []
    if  state.get("repeat_str", "none") == "anomalous_repeat":
        print("anomalous_repeat...")
        result.append(Send("detector_anomalous", {"httpJson": state["httpJson"]}))
        result.append(Send("detector_anomalous_native", {"httpJson": state["httpJson"]}))
        # result.append(Send("detector_anomalous", {"httpJson": state["httpJson_repeat"][-1]}))
        # result.append(Send("detector_anomalous_native", {"httpJson": state["httpJson_repeat"][-1]}))
    else:
        result.append(Send("detector_anomalous", {"httpJson": state["httpJson"]}))
        result.append(Send("detector_anomalous_native", {"httpJson": state["httpJson"]}))
    return result

def contine_to_detector_payload(state: OverallState):
    print("contine_to_detector_payload...")
    detector_content_advice = state.get("detector_content_advice", "none")
    # print(state)
    return [Send("detector_payload", {"contentDetect": state["contentsSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_content_advice": detector_content_advice}) for l in range(len(state["categorysSanitized"]))]

def contine_to_detector_summary(state: OverallState):
    print("contine_to_detector_summary...")
    # print(state)
    detector_summary_advice = state.get("detector_summary_advice", "none")
    return [Send("detector_summary", {"contentDetect": state["summarysSanitized"][l], "categoryDetect": state["categorysSanitized"][l], "detector_summary_advice": detector_summary_advice}) for l in range(len(state["categorysSanitized"]))]

def contine_to_verifier(state: OverallState):
    print("contine_to_verifier...")
    print(state)
    return [Send("verifier", {"categoryVerify": state["categorysSanitized"][l], "originalStatement": state["contentsSanitized"][l], "contentVerify": state["contentsResult"][-1], "summaryVerify": state["summarysResult"][-1]}) for l in range(len(state["categorysSanitized"]))]

def contine_to_anomalous_verifier(state: OverallState):
    print("contine_to_anomalous_verifier...")
    print(state)
    return [Send("verifier_anomalous", {"originalStatement": state["httpJson"], "contentVerify": state["anomalousResult"], "summaryVerify": state["anomalousNativeResult"]})]


def contine_to_reporter(state: OverallState):
    print(state["flag"])
    print(state["flag"][0])
    print(state)
    if state["flag"] == "vulnerable":
        return [Send("reporter", {"verifierResult": state["verifyResult"][l], "originalJson": state["httpJson"], "vulStatement": state["contentsSanitized"], "flag_category": state["flag"]}) for l in range(len(state["verifyResult"]))]
    elif state["flag"] == "anomalous":
        return [Send("reporter", {"verifierResult": state["verify_anomalous_result"], "originalJson": state["httpJson"], "flag_category": state["flag"]})]
    else:
        exit(1)

workflow = StateGraph(OverallState)
workflow.add_edge(START, "classifier")
# workflow.add_node("supervisor", supervisor_node)
# workflow.add_node("parser", parser_node)
workflow.add_node("classifier", classifier_node)
workflow.add_node("detector_anomalous", detector_anomalous_node)
workflow.add_node("detector_anomalous_native", detector_anomalous_native_node)
workflow.add_node("extractor", extractor_node)
workflow.add_node("sanitizer", sanitize_node)
workflow.add_node("sanitizer_anomalous_pre", sanitizer_anomalous_pre_node)
workflow.add_node("detector_payload", detector_payload_node)
workflow.add_node("detector_summary", detector_summary_node)
workflow.add_node("sanitizer_detect_node", sanitizer_detect_node)
workflow.add_node("sanitizer_detect_anomalous_node", sanitizer_detect_anomalous_node)
workflow.add_node("verifier", verifier_node)
workflow.add_node("verifier_anomalous", verifier_anomalous_node)
workflow.add_node("sanitizer_verify_node", sanitizer_verify_node)
workflow.add_node("reporter", reporter_node)
workflow.add_conditional_edges("classifier", contine_to_extractor_or_anomalous, ["extractor", "sanitizer_anomalous_pre"])
workflow.add_edge("extractor", "sanitizer")
if is_no_anomalous_double_check:
    workflow.add_node("detector_anomalous_for_no_double_check", detector_anomalous_node_for_noDoubleCheck)
    workflow.add_edge("sanitizer_anomalous_pre", "detector_anomalous_for_no_double_check")
    workflow.add_edge("detector_anomalous_for_no_double_check", "sanitizer_verify_node")
    
    workflow.add_conditional_edges("sanitizer", contine_to_detector_or_anomalous, ["detector_payload", "detector_summary", "sanitizer_anomalous_pre"])
    workflow.add_edge("detector_payload", "sanitizer_detect_node")
    workflow.add_edge("detector_summary", "sanitizer_detect_node")
    workflow.add_conditional_edges("sanitizer_detect_node", contine_to_verifier, ["verifier"])
    workflow.add_edge("verifier", "sanitizer_verify_node")
    workflow.add_conditional_edges("sanitizer_verify_node", contine_to_reporter, ["reporter"])
elif is_no_malicious_double_check_only_payload_detect:
    workflow.add_node("detector_anomalous_for_no_double_check_only_payload", detector_payload_node_for_no_double_malicious_check)
    workflow.add_node("sanitizer_verify_node_for_single_malicious_detector", sanitizer_verify_node_for_single_malicious_detector)
    workflow.add_conditional_edges("sanitizer", contine_to_detector_or_anomalous_for_no_double_malicious_check_only_payload, ["detector_anomalous_for_no_double_check_only_payload", "sanitizer_anomalous_pre"])
    workflow.add_edge("detector_anomalous_for_no_double_check_only_payload", "sanitizer_verify_node_for_single_malicious_detector")
    workflow.add_conditional_edges("sanitizer_verify_node_for_single_malicious_detector", contine_to_reporter, ["reporter"])
    
    workflow.add_conditional_edges("sanitizer_anomalous_pre", contine_to_detect_anomalous, ["detector_anomalous", "detector_anomalous_native"])
    workflow.add_edge("detector_anomalous", "sanitizer_detect_anomalous_node")
    workflow.add_edge("detector_anomalous_native", "sanitizer_detect_anomalous_node")
    workflow.add_conditional_edges("sanitizer_detect_anomalous_node", contine_to_anomalous_verifier, ["verifier_anomalous"])
    workflow.add_conditional_edges("sanitizer_verify_node", contine_to_reporter, ["reporter"])
elif is_no_malicious_double_check_only_summary_detect:
    workflow.add_node("detector_anomalous_for_no_double_check_only_summary", detector_summary_node_for_no_double_malicious_check)
    workflow.add_node("sanitizer_verify_node_for_single_malicious_detector", sanitizer_verify_node_for_single_malicious_detector)
    workflow.add_conditional_edges("sanitizer", contine_to_detector_or_anomalous_for_no_double_malicious_check_only_summary, ["detector_anomalous_for_no_double_check_only_summary", "sanitizer_anomalous_pre"])
    workflow.add_edge("detector_anomalous_for_no_double_check_only_summary", "sanitizer_verify_node_for_single_malicious_detector")
    workflow.add_conditional_edges("sanitizer_verify_node_for_single_malicious_detector", contine_to_reporter, ["reporter"])
    
    workflow.add_conditional_edges("sanitizer_anomalous_pre", contine_to_detect_anomalous, ["detector_anomalous", "detector_anomalous_native"])
    workflow.add_edge("detector_anomalous", "sanitizer_detect_anomalous_node")
    workflow.add_edge("detector_anomalous_native", "sanitizer_detect_anomalous_node")
    workflow.add_conditional_edges("sanitizer_detect_anomalous_node", contine_to_anomalous_verifier, ["verifier_anomalous"])
    workflow.add_conditional_edges("sanitizer_verify_node", contine_to_reporter, ["reporter"])
    
# elif is_no_rag:
    
else:
    workflow.add_conditional_edges("sanitizer_anomalous_pre", contine_to_detect_anomalous, ["detector_anomalous", "detector_anomalous_native"])
    # workflow.add_conditional_edges("sanitizer", contine_to_detector_payload, ["detector_payload"])
    # workflow.add_conditional_edges("sanitizer", contine_to_detector_summary, ["detector_summary"])
    workflow.add_conditional_edges("sanitizer", contine_to_detector_or_anomalous, ["detector_payload", "detector_summary", "sanitizer_anomalous_pre"])
    workflow.add_edge("detector_payload", "sanitizer_detect_node")
    workflow.add_edge("detector_summary", "sanitizer_detect_node")
    workflow.add_edge("detector_anomalous", "sanitizer_detect_anomalous_node")
    workflow.add_edge("detector_anomalous_native", "sanitizer_detect_anomalous_node")
    workflow.add_conditional_edges("sanitizer_detect_node", contine_to_verifier, ["verifier"])
    workflow.add_conditional_edges("sanitizer_detect_anomalous_node", contine_to_anomalous_verifier, ["verifier_anomalous"])
    workflow.add_edge("verifier", "sanitizer_verify_node")
    # workflow.add_edge("verifier_anomalous", "sanitizer_verify_node")
    workflow.add_conditional_edges("sanitizer_verify_node", contine_to_reporter, ["reporter"])
    # workflow.add_conditional_edges("detector_anomalous", contine_to_reporter, ["reporter"])
workflow.add_edge("reporter", END)
graph = workflow.compile()

def supervisor_test(lower_number, higher_number):
    print("supervisor_test..." + str(lower_number) + "-" + str(higher_number))
    # graph_png = graph.get_graph().draw_mermaid_png()
    # with open("graph_myself.png", "wb") as f:
    #     f.write(graph_png)
    # exit(1)
     
    # events = graph.stream(
    #     {
    #         "messages": [
    #             # (
    #             #     "user",
    #             #     "parse the flow of the HTTP request: \nPOST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nPragma: no-cache\nContent-Length: 146\n\nid=2&nombre=Jam%F3n+Ib%E9rico&precio=85&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25&B1=A%F1adir+al+carrito"
    #             # ),
    #             HumanMessage(content="parse the flow of the HTTP request: \nPOST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nPragma: no-cache\nContent-Length: 146\n\nid=2&nombre=Jam%F3n+Ib%E9rico&precio=85&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25&B1=A%F1adir+al+carrito", name="user"),
    #         ]
    #     },
    #     subgraphs=True,
    # )
    # http_text = "POST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nPragma: no-cache\nContent-Length: 146\n\nid=2&nombre=Jam%F3n+Ib%E9rico&precio=85&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25&B1=A%F1adir+al+carrito"
    # http_text1 = "GET http://localhost:8080/tienda1/index.jsp HTTP/1.1\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)\nPragma: no-cache\nCache-control: no-cache\nAccept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5\nAccept-Language: en\nHost: localhost:8080\nCookie: JSESSIONID=EA414B3E327DED6875848530C864BD8F\nConnection: close"
    # http_text_json = parse_http_request_tool1(http_text)
    # for s in graph.stream(
    # {
    #     "messages": [
    #         HumanMessage(content=http_text_json, name="user"),
    #     ],
    #     "httpJson": http_text_json,
    # },
    # subgraphs=True,
    # ):
    #     # print(s)
    #     print("----")


    # Get already processed request numbers
    processed_nums = get_processed_request_nums()
    twice_need_to_process_nums = get_twice_progress_request_nums()
    
    program_wrong_num = 0
    benign_payload = 0
    malicious_payload = 0
    anomalous_payload = 0
    
    for request_num, request in enumerate(requests_bak, 1):
        # Skip if request has already been processed
        if request_num in processed_nums:
            # logger.info(f"Skipping request_{request_num} as it has already been processed")
            continue
        # if request_num < 15000 or request_num > 17500: # normal: 188 pid 1251759
        # if request_num < 17500 or request_num > 17750: # normal: 188 pid 1246709
        # if request_num < 17750 or request_num > 18000: # normal: 188 pid 1244282
        # if request_num < 18000 or request_num > 20000: # normal: 188 pid 3529705
        # if request_num < 20000 or request_num > 22000: # normal: 188 pid 3531358
        # if request_num < 22000 or request_num > 24000: # normal: 188 pid 3533233
        # if request_num < 24000 or request_num > 26000: # normal: 188 pid 3533888
        # if request_num < 26000 or request_num > 28000: # normal: 188 pid 3534487
        # if request_num < 28000 or request_num > 30000: # normal: 188 pid 3537110
        # if request_num < 30000 or request_num > 32000: # normal: 188 pid 3539143
        # if request_num < 32000 or request_num > 34000: # normal: 188 pid 3574602
        # if request_num < 34000 or request_num > 36000: # normal: 188 pid 3575706
        
        # if request_num < 14000 or request_num > 16000: # anomalous: 188 pid 3562828
        # if request_num < 16000 or request_num > 18000: # anomalous: 188 pid 3570653
        # if request_num < 18000 or request_num > 20000: # anomalous: 188 pid 3572677
        # if request_num < 20000 or request_num > 22000: # anomalous: 188 pid 3578679
        
        # if is_split_run and (request_num < lower_number or request_num > higher_number): # normal: 188 pid 1251759
        #     continue
        if request_num < lower_number or request_num > higher_number:
            continue
        
        if is_twice_progress_run and request_num not in twice_need_to_process_nums:
            continue

        http_text_json = parse_http_request_tool1(request)
        # print(http_text_json)
        # # 减少token消耗
        # ### 仅保留一个http header头 (保留第二个header头)
        # request_split = request_original.split("\n")
        # if request_original.startswith("GET"):
        #     request = request_split[0] + "\n" + request_split[2]
        # else:
        #     request = request_split[0] + "\n" + request_split[2] + "\n" + "\n" + request_split[-1]
        try:
            final_state = graph.invoke(
                {
                    "messages": [
                        HumanMessage(content=http_text_json, name="user"),
                    ],
                    "httpJson": http_text_json,
                },
                subgraphs=True,
            )
        except Exception as e:
            program_wrong_num += 1
            logger.debug("wrong for the request: " + request + str(e))
            save_report(request_num, {}, f"error: program execution failed - {str(e)}", request)
            continue
        print(final_state)
        # print(type(final_state))
        # print(len(final_state))
        # print(final_state[1])
        # print(final_state[1]["httpJson"])
        final_state = final_state[1]
        classifierResult = final_state.get("classifierResult", "none")
        contents = final_state.get("contents", "none")
        contentsResult = final_state.get("contentsResult", "none")
        summarys = final_state.get("summarys", "none")
        summarysResult = final_state.get("summarysResult", "none")
        contentsSanitized = final_state.get("contentsSanitized", "none")
        verifyResult = final_state.get("verifyResult", "none")
        reporterResult = final_state.get("reporterResult", "none")
        if len(classifierResult.get("Unknown", "none")) == 0 and len(classifierResult.get("SQL", "none")) == 0 and len(classifierResult.get("XML", "none")) == 0 and len(classifierResult.get("JavaScript", "none")) == 0:
            # print("classify node wrong...")
            logger.warning("num:" + str(request_num) + ", classify node wrong..." + str(request))
            program_wrong_num += 1
            save_report(request_num, final_state, "error: classify node wrong", request)
            continue
        if final_state.get("flag", "none") == "vulnerable":
            if len(contents) == 0:
                # print("benign payload...")
                logger.info("num:" + str(request_num) + ", benign payload..." + str(request))
                benign_payload += 1
            elif len(contentsSanitized) == 0:
                # print("etract node wrong...")
                logger.warning("num:" + str(request_num) + ", etract node wrong.." + str(request))
                program_wrong_num += 1
                save_report(request_num, final_state, "error: extract node wrong", request)
            elif len(contentsResult) == 0 and len(summarysResult) == 0:
                # print("detect node wrong...")
                logger.warning("num:" + str(request_num) + ", detect node wrong..." + str(request))
                program_wrong_num += 1
                save_report(request_num, final_state, "error: detect node wrong", request)
            elif len(verifyResult) == 0:
                # print("verify node wrong...")
                logger.warning("num:" + str(request_num) + ", verify node wrong..." + str(request))
                program_wrong_num += 1
                save_report(request_num, final_state, "error: verify node wrong", request)
            elif len(reporterResult) == 0:
                logger.warning("num:" + str(request_num) + ", report node wrong..." + str(request) + str(reporterResult))
                program_wrong_num += 1
                save_report(request_num, final_state, "error: report node wrong", request)
            else:
                print(reporterResult)
                malicious_payload += 1
                logger.error("num:" + str(request_num) + ", malicious payload..." + str(request) + str(reporterResult[0]["vuln"]) + " " + str(reporterResult[0]["cause"]))
                save_report(request_num, final_state, "malicious", request)
            # print(reporterResult["vuln"])
            # print(reporterResult["position"])
            # print(reporterResult["statement"])
            # print(reporterResult["cause"])
        elif final_state.get("flag", "none") == "anomalous":
            try:
                print(str(reporterResult[0]["result"]))
            except Exception as e:
                continue
            if reporterResult[0]["result"].lower() == "normal":
                benign_payload += 1
                logger.info("num:" + str(request_num) + ", benign payload..." + str(request))
                save_report(request_num, final_state, "benign", request)
            else:
                anomalous_payload += 1
                # if isinstance(reporterResult[0]["result"], list) or isinstance(reporterResult[0]["cause"], list):
                #     logger.error("anomalous payload..." + str(request) + str(reporterResult[0]["result"]) + " " + reporterResult[0]["cause"][0])
                # elif isinstance(reporterResult[0]["result"], dict) or isinstance(reporterResult[0]["cause"], dict):
                #     logger.error("anomalous payload...(Dict)" + str(request))
                # else:
                #     logger.error("anomalous payload..." + str(request) + str(reporterResult[0]["result"]) + " " + reporterResult[0]["cause"])
                logger.error("num:" + str(request_num) + ", anomalous payload..." + str(request) + str(reporterResult[0]["result"]) + " " + str(reporterResult[0]["cause"]))
                save_report(request_num, final_state, "anomalous", request)
            
            
        print("program_wrong_num: " + str(program_wrong_num), "benign_payload: " + str(benign_payload), "malicious_payload: " + str(malicious_payload), "anomalous_payload: " + str(anomalous_payload), "total: " + str(len(requests_bak)))
    print("program_wrong_num: " + str(program_wrong_num), "benign_payload: " + str(benign_payload), "malicious_payload: " + str(malicious_payload), "anomalous_payload: " + str(anomalous_payload), "total: " + str(len(requests_bak)))
    
    
def convert_message_to_dict(message):
    """Convert HumanMessage object to serializable dictionary"""
    if isinstance(message, (HumanMessage, AIMessage, SystemMessage)):
        return {
            "content": message.content,
            "name": message.name if hasattr(message, "name") else None,
            "type": message.__class__.__name__
        }
    return message

def process_final_state(final_state):
    """Process final_state to make it JSON serializable"""
    if isinstance(final_state, tuple):
        final_state = final_state[1]  # Get the second element of the tuple
    
    processed_state = {}
    for key, value in final_state.items():
        if key == "messages":
            processed_state[key] = [convert_message_to_dict(msg) for msg in value]
        elif isinstance(value, (list, tuple)):
            processed_state[key] = [
                convert_message_to_dict(item) if isinstance(item, (HumanMessage, AIMessage, SystemMessage))
                else item
                for item in value
            ]
        else:
            processed_state[key] = value
            
    return processed_state

def save_report(request_num: int, final_state: dict, category: str, request: str):
    """Save detection report to file"""
    # Create report directories if they don't exist
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(error_dir, exist_ok=True)

    # Process final_state to make it JSON serializable
    processed_final_state = process_final_state(final_state)

    # Prepare report content
    report_content = {
        "original_request": request,
        "detection_result": processed_final_state,
        "category": category
    }

    # Save to appropriate directory based on detection status
    if category in ["malicious", "benign", "anomalous"]:
        filepath = os.path.join(report_dir, f"request_{request_num}.json")
    else:
        filepath = os.path.join(error_dir, f"request_{request_num}.json")

    # Save to file
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report_content, f, indent=2, ensure_ascii=False)

def get_processed_request_nums():
    """Get all request numbers that have already been processed which is successful."""
    processed_nums = set()
    
    # Check both directories for existing reports
    for directory in [report_dir]:
        if not os.path.exists(directory):
            continue
        for filename in os.listdir(directory):
            if filename.startswith("request_") and filename.endswith(".json"):
                try:
                    num = int(filename.replace("request_", "").replace(".json", ""))
                    processed_nums.add(num)
                except ValueError:
                    continue
    # delete error log folder generated by the last run
    if os.path.exists(error_dir):
        for filename in os.listdir(error_dir):
            filepath = os.path.join(error_dir, filename)
            os.remove(filepath)
        os.rmdir(error_dir)
    return processed_nums

def get_twice_progress_request_nums():
    """Get all request numbers that need to be re-processed which is failed."""
    processed_nums = set()
    if is_twice_progress_run:
        # Check both directories for existing reports
        for directory in [twice_report_dir]:
            if not os.path.exists(directory):
                continue
            for filename in os.listdir(directory):
                if filename.startswith("request_") and filename.endswith(".json"):
                    try:
                        num = int(filename.replace("request_", "").replace(".json", ""))
                        processed_nums.add(num)
                    except ValueError:
                        continue
    return processed_nums

def parallel_supervisor_test(number_of_chunks):
    """
    使用多线程并行执行supervisor_test函数
    """
    number_of_chunks = int(number_of_chunks)
    
    # 计算数据集总大小
    total_size = len(requests_bak)
    
    # 计算每片的基础大小
    chunk_size = total_size // number_of_chunks
    remainder = total_size % number_of_chunks  # 余数处理，确保数据不丢失
    
    threads = []
    current_start = 1
    
    print(f"将数据集 {total_size} 分成 {number_of_chunks} 片进行并行处理...")
    
    for i in range(number_of_chunks):
        # 计算当前片的结束位置
        # 前remainder片每片多分配1个数据，以处理不能整除的情况
        current_chunk_size = chunk_size + (1 if i < remainder else 0)
        current_end = current_start + current_chunk_size - 1
        
        # 确保最后一个片不会超过总范围
        if current_end > total_size:
            current_end = total_size
        
        print(f"线程 {i} 处理范围: {current_start}-{current_end}")
        
        # 创建线程，传入当前片的范围
        thread = threading.Thread(
            target=supervisor_test,  # 您已有的函数
            args=(current_start, current_end),
            name=f"Thread-{i}"  # 线程命名，便于调试
        )
        
        threads.append(thread)
        thread.start()
        
        # 更新下一片的起始位置
        current_start = current_end + 1
        
        # 如果已经处理完所有数据，提前退出循环
        if current_start > total_size:
            break
        
 #--------------- 多服务器 --------------       
    # # 计算数据集总大小
    # total_start = 1
    # total_end = 25065
    # total_size = total_end - total_start + 1
    
    # # 计算每片的基础大小
    # chunk_size = total_size // number_of_chunks
    # remainder = total_size % number_of_chunks  # 余数处理，确保数据不丢失
    
    # threads = []
    # current_start = 1
    
    # print(f"将数据集 {total_size} 分成 {number_of_chunks} 片进行并行处理...")
    
    # for i in range(number_of_chunks):
    #     # 计算当前片的结束位置
    #     # 前remainder片每片多分配1个数据，以处理不能整除的情况
    #     current_chunk_size = chunk_size + (1 if i < remainder else 0)
    #     current_end = current_start + current_chunk_size - 1
        
    #     # 确保最后一个片不会超过总范围
    #     if current_end > total_end:
    #         current_end = total_end
        
    #     print(f"线程 {i} 处理范围: {current_start}-{current_end}")
        
    #     # 创建线程，传入当前片的范围
    #     thread = threading.Thread(
    #         target=supervisor_test,  # 您已有的函数
    #         args=(current_start, current_end),
    #         name=f"Thread-{i}"  # 线程命名，便于调试
    #     )
        
    #     threads.append(thread)
    #     thread.start()
        
    #     # 更新下一片的起始位置
    #     current_start = current_end + 1
        
    #     # 如果已经处理完所有数据，提前退出循环
    #     if current_start > total_end:
    #         break
#--------------- 多服务器 -------------- 
    
    # 等待所有线程完成
    print("等待所有线程执行完成...")
    for i, thread in enumerate(threads):
        thread.join()
        print(f"线程 {i} 执行完毕")
    
    print("所有线程处理完成！")
