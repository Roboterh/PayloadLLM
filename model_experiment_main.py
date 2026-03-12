import json
import os
import re
import threading
import demjson3
from langchain_openai import ChatOpenAI
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_community.chat_models import ChatZhipuAI
from langchain import hub
from langchain_ollama import ChatOllama
from loguru import logger

model = ChatOpenAI(model="gpt-5.2", api_key="xxx", base_url="xxx") # native model
# model_finetune = ChatOpenAI(model="Qwen3-8B-finetune", api_key="ollama", base_url="http://xxxx:8002/v1/") # finetune model
# model_temp = ChatOpenAI(model="Qwen3-8B", api_key="ollama", base_url="http://xxxx:8001/v1/", temperature=0.1)

# 记录本次请求的所有requests
requests_bak = []
datasets_path = "datasets/normalTrafficTest.txt"
report_dir = "report_exp/report_normalTrafficTest-with-GPT-5.2"
error_dir = "report_exp/error_log_normalTrafficTest-with-GPT-5.2"

prompt = """
You are a http traffic expert, you are very good at analyzing http traffic! Your task is to analyze the given http request object and detect whether is anomalous or normal or malicious.
It is worth noting that the http requests are usually url encoded once or even twice, please pay attention to this point when you analyze the http request.
### Abnormal behaviors include the following:
- Find injection location, inserting malicious code into external input parameters to test for injection vulnerabilities, such as using characters like `+` or `|` to detect
- Error Report, intentionally triggering error messages to obtain internal system information, such as "rememberA" "idA" "errorMsgA" "B2A" "apellidosA" "B1A" "loginA" "modoA" "ciudadA" "pwdA" "emailA" "nombreA" "precioA" "dniA" "cantidadA" "ntcA" "B1A" "provinciaA" "cpA" "direccionA" "passwordA", added the character A after the correct parameter
- Download sensitive files, accessing and downloading sensitive files, such as asf-logo-wide.gif~, .bak and .inc, etc.
### Malicious behaviors include the following:
- SQL Injection Attack
- XSS Attack
- XXE Attack
- SSI Attack
- Other Vuln Attack
### Example
Example 1:
request: ...
result: ```json \{"vuln": "normal", "position": "None", "statement": "None", "cause": "...", "type": "normal"\}```
Example 2:
request: ...
result: ```json \{"vuln": "Error Report", "position": "get_parameter.id", "statement": "B1A", "cause": "...", "type": "anomalous"\}```
Example 3:
request: ...
result: ```json \{"vuln": "SQL Injection Attack", "position": "get_parameter.id", "statement": "1' or '1' = '1", "cause": "...", "type": "malicious"\}```

So, please check whether the following request has malicious or anomalous behavior, After detailed analysis, a JSON block is output, containing fields such as vuln, position, statement, and cause.

request: {input}
"""

def call_model_without_tools(prompt):
    res = model.invoke(prompt)
    return res.content
    
def prompt_maker(task, lazy_prompt):
    prompt_template = hub.pull("hardkothari/prompt-maker")
    prompt = prompt_template.invoke({"task": task, "lazy_prompt": lazy_prompt})
    # print(prompt)
    prompt_improved = model.invoke(prompt)
    
    return prompt_improved

# ================= data handle  ================= #
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
            target=workflow,  # 您已有的函数
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
    
    # 等待所有线程完成
    print("等待所有线程执行完成...")
    for i, thread in enumerate(threads):
        thread.join()
        print(f"线程 {i} 执行完毕")
    
    print("所有线程处理完成！")
    
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

def save_report(request_num: int, final_state: dict, category: str, request: str):
    """Save detection report to file"""
    # Create report directories if they don't exist
    os.makedirs(report_dir, exist_ok=True)
    os.makedirs(error_dir, exist_ok=True)

    # # Process final_state to make it JSON serializable
    # processed_final_state = process_final_state(final_state)

    # Prepare report content
    report_content = {
        "original_request": request,
        "detection_result": final_state,
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
        
def parse_http_request_tool1(request_text: str):
    """
    解析标准 HTTP 请求文本，并将结果以 JSON 格式输出，支持：
    1. 提取 URL 查询参数
    2. 解析 Headers
    3. 解析 Body，并支持 application/x-www-form-urlencoded 格式的参数解析
    """
    keep = []
    lines = request_text.split("\n")
    # print(lines[0].strip())
    # 解析请求行
    request_line = lines[0].strip().split()
    keep.append(lines[0])
    # method, url, protocol = request_line[0], request_line[1], request_line[2]

    # 解析 URL 和查询参数
    # parsed_url = urllib.parse.urlparse(url)
    # url = url.split("?")[0]
    # query_params = urllib.parse.parse_qs(parsed_url.query)

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
        
        keep.append(key + ": " + value)
        
    # 解析 Body
    if body_index == 0:
        body = ""
        body_params = {}
    else:
        body = "\n".join(lines[body_index:]).strip() if body_index < len(lines) else ""
        keep.append("\n" + body)
        # 如果 Content-Type 是 application/x-www-form-urlencoded，则解析表单数据
        # try:
        #     body_params = urllib.parse.parse_qs(body)
        # except Exception as e:
        #     print(f"Parse the http request wrong: {e}")
        #     body_params = {}
    print("\n".join(keep))
    return "\n".join(keep)

def save_LL_response(request_num: int, original_res):
    """Save detection report to file"""
    # Create report directories if they don't exist
    llm_dir = report_dir + "/llm"
    os.makedirs(llm_dir, exist_ok=True)

    # # Process final_state to make it JSON serializable
    # processed_final_state = process_final_state(final_state)

    # # Prepare report content
    # report_content = {
    #     "original_request": request,
    #     "detection_result": final_state,
    #     "category": category,
    #     "original_response": original_res
    # }
    
    filepath = os.path.join(llm_dir, f"request_{request_num}.txt")

    # Save to file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(original_res)
# ================= data handle  ================= #

def workflow(lower_number, higher_number):
    program_wrong_num = 0
    benign_payload = 0
    malicious_payload = 0
    anomalous_payload = 0
    
    print("workflow..." + str(lower_number) + "-" + str(higher_number))
    
    # Get already processed request numbers
    processed_nums = get_processed_request_nums()
    processed_nums_len = len(processed_nums)
    # twice_need_to_process_nums = get_twice_progress_request_nums()
    
    for request_num, request in enumerate(requests_bak, 1):
        print("processed_nums_len ===> " + str(processed_nums_len))
        if processed_nums_len >= 36001:
            exit(1)
        
        detect_result = {}
        
        # Skip if request has already been processed
        if request_num in processed_nums:
            # logger.info(f"Skipping request_{request_num} as it has already been processed")
            continue
        if request_num < lower_number or request_num > higher_number:
            continue
        
        # if is_twice_progress_run and request_num not in twice_need_to_process_nums:
        #     continue
        
        try:
            res = call_model_without_tools(prompt.replace("{input}", parse_http_request_tool1(request)))
            print(res)
            save_LL_response(request_num, res)
            
            processed_nums_len += 1
            
            matches = re.findall(r'```json\n(.*?)\n```', res, re.DOTALL)

            if matches:
                json_text = matches[0].strip()  # 取第一个 JSON 代码块
                # data = json.loads(json_text)  # 解析 JSON
                data = demjson3.decode(json_text)
                # json_output = json.dumps(data, indent=4, ensure_ascii=False)  # 重新格式化 JSON
                # print(json_output)
                detect_result =  {"vuln": data.get("vuln", {}), "position": data.get("position", {}), "statement": data.get("statement", {}), "cause": data.get("cause", {}), "type": data.get("type", {})}
            else:
                print("No JSON found in the text.")
            
        except Exception as e:
            program_wrong_num += 1
            logger.debug("wrong for the request: " + request + str(e))
            save_report(request_num, {}, f"error: program execution failed - {str(e)}", request)
            continue
        
        if detect_result.get("type", "none") == "normal" or detect_result.get("vuln", "none") == "normal":
            benign_payload += 1
            logger.info("num:" + str(request_num) + ", benign payload..." + str(request))
            save_report(request_num, detect_result, "benign", request)
        elif detect_result.get("type", "none") == "anomalous":
            anomalous_payload += 1
            logger.error("num:" + str(request_num) + ", anomalous payload..." + str(request) + str(detect_result["vuln"]) + " " + str(detect_result["cause"]))
            save_report(request_num, detect_result, "anomalous", request)
        elif detect_result.get("type", "none") == "malicious":
            malicious_payload += 1
            logger.error("num:" + str(request_num) + ", malicious payload..." + str(request) + str(detect_result["vuln"]) + " " + str(detect_result["cause"]))
            save_report(request_num, detect_result, "malicious", request)
        else:
            program_wrong_num += 1
            logger.debug("wrong for the request(no type): " + request)
            save_report(request_num, {}, "error: no type result...", request)
            
        print("program_wrong_num: " + str(program_wrong_num), "benign_payload: " + str(benign_payload), "malicious_payload: " + str(malicious_payload), "anomalous_payload: " + str(anomalous_payload), "total: " + str(len(requests_bak)))
    print("program_wrong_num: " + str(program_wrong_num), "benign_payload: " + str(benign_payload), "malicious_payload: " + str(malicious_payload), "anomalous_payload: " + str(anomalous_payload), "total: " + str(len(requests_bak)))

    
if __name__ == '__main__':
    requestss = """POST http://localhost:8080/tienda1/publico/anadir.jsp?id=2&nombre=Jam%F3n+Ib%E9rico&precio=85&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25&B1=A%F1adir+al+carrito HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5
Accept-Language: en
Host: localhost:8080
Cookie: JSESSIONID=B92A8B48B9008CD29F622A994E0F650D
Connection: close

dafsfdsdf"""
    
    get_requests_from_datasets()
    parallel_supervisor_test(1)
    
    # print(parse_http_request_tool1(requestss))