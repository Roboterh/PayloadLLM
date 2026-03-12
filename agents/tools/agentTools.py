import json
import urllib.parse
import operator
from typing import Annotated, Literal, Dict, Any, Optional
from loguru import logger
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, AnyMessage
from langchain_core.tools import tool
from langgraph.graph import add_messages, END, START, StateGraph, MessagesState
from langgraph.types import Command, Send
from langgraph.prebuilt import create_react_agent, ToolNode

from utils.vectorstore_utils import connection
from prompts.core_prompt import *
from utils.model_utils import model

vector_store_payload = connection("payload_index_test")
vector_store_summary = connection("payload_summary_index_test")
vector_store_xss_payload = connection("xss_payload_index_test")
vector_store_xss_summary = connection("xss_payload_summary_index_test")
vector_store_xxe_summary = connection("xxe_payload_summary_index_test")

@tool
def search_payload_tool(
    content: Annotated[str, "The payload to search for similar payloads from existing malicious payloads in the vector store"]
):
    """
    This tool searches for similar payloads from the vector store
    """
    try:
        results = vector_store_payload.similarity_search(
            query=content,
            k=2,
        )
    except Exception as e:
        logger.error(f"Failed to search for similar payloads, error: {e}")
    result_str = f'Successfully searched:\n"""\n{content}\n"""\nStdout: {results}'
    new_results = []
    for result in results:
        new_result = {}
        new_result["source"] = result.metadata["source"].split("/")[-1]
        new_result["seq_num"] = result.metadata["seq_num"]
        new_result["content"] = result.page_content
        new_results.append(new_result)
    return new_results

@tool
def search_payload_summary_tool(
    content: Annotated[str, "The summary of payload to search for similar actions from existing malicious summary of payloads in the vector store"]
):
    """
    This tool searches for similar actions from the vector store
    """
    try:
        results = vector_store_summary.similarity_search(
            query=content,
            k=2,
        )
    except Exception as e:
        logger.error(f"Failed to search for similar summary of payloads, error: {e}")
    result_str = f'Successfully searched:\n"""\n{content}\n"""\nStdout: {results}'
    new_results = []
    for result in results:
        new_result = {}
        new_result["source"] = result.metadata["source"].split("/")[-1]
        new_result["seq_num"] = result.metadata["seq_num"]
        new_result["content"] = result.page_content
        new_results.append(new_result)
    return new_results

@tool
def search_xss_payload_tool(
    content: Annotated[str, "The payload to search for similar payloads from existing malicious payloads in the vector store"]
):
    """
    This tool searches for similar payloads from the vector store
    """
    try:
        results = vector_store_xss_payload.similarity_search(
            query=content,
            k=2,
        )
    except Exception as e:
        logger.error(f"Failed to search for similar payloads, error: {e}")
    result_str = f'Successfully searched:\n"""\n{content}\n"""\nStdout: {results}'
    new_results = []
    for result in results:
        new_result = {}
        new_result["source"] = result.metadata["source"].split("/")[-1]
        new_result["seq_num"] = result.metadata["seq_num"]
        new_result["content"] = result.page_content
        new_results.append(new_result)
    return new_results

@tool
def search_xss_payload_summary_tool(
    content: Annotated[str, "The summary of payload to search for similar actions from existing malicious summary of payloads in the vector store"]
):
    """
    This tool searches for similar actions from the vector store
    """
    try:
        results = vector_store_xss_summary.similarity_search(
            query=content,
            k=2,
        )
    except Exception as e:
        logger.error(f"Failed to search for similar summary of payloads, error: {e}")
    result_str = f'Successfully searched:\n"""\n{content}\n"""\nStdout: {results}'
    new_results = []
    for result in results:
        new_result = {}
        new_result["source"] = result.metadata["source"].split("/")[-1]
        new_result["seq_num"] = result.metadata["seq_num"]
        new_result["content"] = result.page_content
        new_results.append(new_result)
    return new_results

@tool
def search_xxe_payload_summary_tool(
    content: Annotated[str, "The summary of payload to search for similar actions from existing malicious summary of payloads in the vector store"]
):
    """
    This tool searches for similar actions from the vector store
    """
    try:
        results = vector_store_xxe_summary.similarity_search(
            query=content,
            k=2,
        )
    except Exception as e:
        logger.error(f"Failed to search for similar summary of payloads, error: {e}")
    result_str = f'Successfully searched:\n"""\n{content}\n"""\nStdout: {results}'
    new_results = []
    for result in results:
        new_result = {}
        new_result["source"] = result.metadata["source"].split("/")[-1]
        new_result["seq_num"] = result.metadata["seq_num"]
        new_result["content"] = result.page_content
        new_results.append(new_result)
    return new_results

def parse_http_request_tool(
    request_text: Annotated[str, "The HTTP request text to parse and output as JSON"]
):
    """
    This tool parses the standard HTTP request text and outputs the parsed result as JSON
    """
    lines = request_text.split("\n")
    # parse the request line
    request_line = lines[0].strip().split()
    method, url, protocol = request_line[0], request_line[1], request_line[2]
    
    # parse the headers
    headers = {}
    body_index = 0 # the start index of the body
    for i, line in enumerate(lines[1:], start=1):
        line = line.strip()
        if line == "": # flag the end of the headers
            body_index = i + 1
            break
        key, value = line.split(":", 1)
        headers[key.strip()] = value.strip()
        
    # parse the body
    if body_index == 0:
        body = ""
    else:
        body = "\n".join(lines[body_index:]).strip() if body_index < len(lines) else ""
    
    # return the parsed result
    result = {
        # "method": method,
        "url": url,
        # "protocol": protocol,
        # "headers": headers,
        **headers,
        "body": body
    }
    return json.dumps(result, indent=4, ensure_ascii=False)

def parse_http_request_tool1(request_text: str):
    """
    解析标准 HTTP 请求文本，并将结果以 JSON 格式输出，支持：
    1. 提取 URL 查询参数
    2. 解析 Headers
    3. 解析 Body，并支持 application/x-www-form-urlencoded 格式的参数解析
    """
    lines = request_text.split("\n")
    # 解析请求行
    request_line = lines[0].strip().split()
    method, url, protocol = request_line[0], request_line[1], request_line[2]

    # 解析 URL 和查询参数
    parsed_url = urllib.parse.urlparse(url)
    url = url.split("?")[0]
    query_params = urllib.parse.parse_qs(parsed_url.query)

    # 解析 Headers
    all_headers = []
    headers = {}
    body_index = 0  # 记录 Body 开始的索引
    for i, line in enumerate(lines[1:], start=1):
        line = line.strip()
        if line == "":  # Headers 结束
            body_index = i + 1
            break
        # 解析所有Header但只保留第二个
        key, value = line.split(":", 1)
        all_headers.append((key.strip(), value.strip()))

    # 如果存在第二个Header，则存储它
    if len(all_headers) >= 2:
        key, value = all_headers[1]  # 索引1表示第二个元素
        headers[key] = value
        
    # 解析 Body
    if body_index == 0:
        body = ""
        body_params = {}
    else:
        body = "\n".join(lines[body_index:]).strip() if body_index < len(lines) else ""
        # 如果 Content-Type 是 application/x-www-form-urlencoded，则解析表单数据
        try:
            body_params = urllib.parse.parse_qs(body)
        except Exception as e:
            print(f"Parse the http request wrong: {e}")
            body_params = {}

    # 构造解析结果
    ## 仅保留一个http header头 (保留第二个header头)
    result = {
        # "method": method,
        "url": url,
        # "protocol": protocol,
        "query_params": query_params,
        # **query_params,
        "headers": headers,
        # **headers,
        # "body": body,
        "body_params": body_params
        # **body_params
    }
    return json.dumps(result, indent=4, ensure_ascii=False)