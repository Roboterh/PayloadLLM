import argparse
import re
from loguru import logger
 
from utils.initial import env_initial, init_logger
from utils.model_utils import *
from utils.vectorstore_utils import *
from agents.extract_agent import ExtractAgent
from agents.multi_agent_supervisor import *

def args_initial():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--in_file', type=str, help='in_file')
    parser.add_argument('--out_file', type=str, help='out_file')
    parser.add_argument('--other_file', type=str, help='other_file')
    # preprocess datasets
    parser.add_argument('--expert_name', type=str, help='expert_name in ExtractAgent')
    parser.add_argument('--attack_name', type=str, help='attack_name in ExtractAgent')
    parser.add_argument('--keyword', nargs='+', help='keyword to filter the requests when preprocess the dataset')
    # index the datasets to vector store
    parser.add_argument('--index_datasets', action="store_true", help='Flag indicating whether to index the dataset using vector store')
    parser.add_argument('--index_name', type=str, choices=['payload_index_test', 'payload_summary_index_test', 'xss_payload_index_test', 'xss_payload_summary_index_test', 'xxe_payload_summary_index_test'], help='index_name in ElasticsearchStore')
    # process the results
    parser.add_argument('--evaluate', action="store_true", help='Flag indicating whether to evaluate the results')
    # test
    parser.add_argument('--test', action="store_true", help='Flag indicating whether to test')
    # flag
    parser.add_argument('--flag', type=str, help='flag to indicate the type of action to be performed')
    args = parser.parse_args()
    return args

def test(arg_content=1):
    # is_split_run = False
# lower_number = 600
# higher_number = 800
    # print(arg_content)
    # total_nums = 100
    # args = arg_content.split(",")
    # print(args)
    # if args[0] == "True":
    get_requests_from_datasets()
    parallel_supervisor_test(arg_content)
        
    
    http_request = """POST http://localhost:8080/tienda1/publico/autenticar.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5
Accept-Language: en
Host: localhost:8080
Cookie: JSESSIONID=5189B8429BAA429D403F728504402390
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 56

modo=entrar&login=auton&pwdA=gubi9&remember=on&B1=Entrar"""

    http_request1 = """
POST http://localhost:8080/tienda1/publico/anadir.jsp HTTP/1.1
User-Agent: Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)
Pragma: no-cache
Cache-control: no-cache
Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
Accept-Encoding: x-gzip, x-deflate, gzip, deflate
Accept-Charset: utf-8, utf-8;q=0.5, *;q=0.5
Accept-Language: en
Host: localhost:8080
Cookie: JSESSIONID=AE29AEEBDE479D5E1A18B4108C8E3CE0
Content-Type: application/x-www-form-urlencoded
Connection: close
Content-Length: 146

id=2&nombre=Jam%F3n+Ib%E9rico&precio=85&cantidad=%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25&B1=A%F1adir+al+carrito
"""

    # # 解析 HTTP 请求并以 JSON 格式输出
    # parsed_json = parse_http_request_tool1(http_request)
    # print(parsed_json)
    # supervisor_test()
    # string = {"canited": [";dddsdsdfds d"]}
    # print(find_deepest_value(string))
    # result = search_payload_tool(";select * from user-- ")
    # print(result)
    
def evaluate_results_threeRounds(save_consistent=True, save_majority=True, save_conflict=True, 
                                 report_dir_1="report_xxx",
                                 report_dir_2="report_xxx_(twice)",
                                 report_dir_3="report_xxx_(third)"):
    """
    基于三个不同report_dir路径，使用少数服从多数的方式决定最终结果
    
    Args:
        save_consistent: 是否保存完全一致的数据包
        save_majority: 是否保存多数一致的数据包
        save_conflict: 是否保存完全分歧的数据包
        report_dir_1, report_dir_2, report_dir_3: 三个报告目录路径
    """
    import json
    import os
    from collections import Counter
    
    # 创建保存目录
    output_dir = "three_rounds_analysis/" + report_dir_1
    os.makedirs(output_dir, exist_ok=True)
    
    # 获取三个文件夹中的JSON文件
    files1 = {f for f in os.listdir(report_dir_1) if f.endswith('.json')}
    files2 = {f for f in os.listdir(report_dir_2) if f.endswith('.json')}
    files3 = {f for f in os.listdir(report_dir_3) if f.endswith('.json')}
    
    # 找出三个文件夹中都存在的共同文件
    common_files = files1 & files2 & files3
    print(f"找到 {len(common_files)} 个共同文件")
    
    if not common_files:
        print("没有找到共同的JSON文件，请检查路径是否正确")
        return
    
    # 统计最终结果
    final_category_count = {"anomalous": 0, "benign": 0, "malicious": 0}
    vote_count = {"consistent": 0, "majority": 0, "split": 0}  # 投票情况统计
    
    # 保存数据包信息
    consistent_files = []  # 完全一致的文件列表
    majority_files = []  # 多数一致的文件列表
    conflict_files = []  # 完全分歧的文件列表
    discrepancy_details = []  # 详细出入记录
    
    # 处理每个文件
    for filename in common_files:
        categories = []
        file_data = []  # 保存三个文件的数据
        
        # 读取三个文件夹中的对应文件
        for report_dir in [report_dir_1, report_dir_2, report_dir_3]:
            file_path = os.path.join(report_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                category = data.get("category", "").lower()
                if category:  # 只添加非空分类
                    categories.append(category)
                    file_data.append({
                        "report_dir": os.path.basename(report_dir),
                        "category": category,
                        "data": data
                    })
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
        
        # 如果少于3个有效分类，跳过这个文件
        if len(categories) < 3:
            continue
        
        # 统计分类结果
        category_counter = Counter(categories)
        
        # 判断投票情况
        vote_type = ""
        if len(set(categories)) == 1:  # 三个结果完全一致
            final_category = categories[0]
            vote_count["consistent"] += 1
            vote_type = "consistent"
            
            # 保存完全一致的数据包
            if save_consistent:
                consistent_files.append({
                    "filename": filename,
                    "final_category": final_category,
                    "votes": categories,
                    "individual_results": file_data
                })
        elif len(category_counter) == 2 and max(category_counter.values()) >= 2:  # 两个相同，一个不同
            final_category = max(category_counter, key=category_counter.get)
            vote_count["majority"] += 1
            vote_type = "majority"
            
            # 保存多数一致的数据包
            if save_majority:
                majority_files.append({
                    "filename": filename,
                    "final_category": final_category,
                    "votes": categories,
                    "individual_results": file_data
                })
                
                # 记录出入详情
                minority_category = next(cat for cat in category_counter if cat != final_category)
                discrepancy_details.append({
                    "filename": filename,
                    "vote_type": "majority",
                    "final_result": final_category,
                    "discrepancy": minority_category,
                    "vote_distribution": dict(category_counter)
                })
        else:  # 三个都不同（理论上不可能，但代码上处理）
            # 如果出现三个不同的情况，按优先级选择
            if "anomalous" in categories:
                final_category = "anomalous"
            elif "malicious" in categories:
                final_category = "malicious"
            else:
                final_category = "benign"
            vote_count["split"] += 1
            vote_type = "split"
            
            # 保存完全分歧的数据包
            if save_conflict:
                conflict_files.append({
                    "filename": filename,
                    "final_category": final_category,
                    "votes": categories,
                    "individual_results": file_data
                })
                
                # 记录出入详情
                all_categories = list(category_counter.keys())
                discrepancy_details.append({
                    "filename": filename,
                    "vote_type": "split",
                    "final_result": final_category,
                    "discrepancy": all_categories,
                    "vote_distribution": dict(category_counter)
                })
        
        # 统计最终分类
        if final_category in final_category_count:
            final_category_count[final_category] += 1
    
    # 保存数据包到文件
    if save_consistent and consistent_files:
        consistent_file_path = os.path.join(output_dir, "consistent_vote_files.json")
        with open(consistent_file_path, 'w', encoding='utf-8') as f:
            json.dump(consistent_files, f, ensure_ascii=False, indent=2)
        print(f"\n完全一致的数据包已保存到: {consistent_file_path}")
    
    if save_majority and majority_files:
        majority_file_path = os.path.join(output_dir, "majority_vote_files.json")
        with open(majority_file_path, 'w', encoding='utf-8') as f:
            json.dump(majority_files, f, ensure_ascii=False, indent=2)
        print(f"多数一致的数据包已保存到: {majority_file_path}")
    
    if save_conflict and conflict_files:
        conflict_file_path = os.path.join(output_dir, "conflict_vote_files.json")
        with open(conflict_file_path, 'w', encoding='utf-8') as f:
            json.dump(conflict_files, f, ensure_ascii=False, indent=2)
        print(f"完全分歧的数据包已保存到: {conflict_file_path}")
    
    # 保存出入详情
    if discrepancy_details:
        discrepancy_file_path = os.path.join(output_dir, "discrepancy_details.json")
        with open(discrepancy_file_path, 'w', encoding='utf-8') as f:
            json.dump(discrepancy_details, f, ensure_ascii=False, indent=2)
        print(f"出入详情记录已保存到: {discrepancy_file_path}")
    
    # 计算比率
    total_count = len(common_files)
    if total_count > 0:
        anomalous_rate = final_category_count["anomalous"] / total_count * 100
        benign_rate = final_category_count["benign"] / total_count * 100
        malicious_rate = final_category_count["malicious"] / total_count * 100
        combined_rate = (final_category_count["anomalous"] + final_category_count["malicious"]) / total_count * 100
    else:
        anomalous_rate = benign_rate = malicious_rate = combined_rate = 0
    
    # 输出统计结果
    print("\n" + "="*60)
    print("三轮评估结果 - 少数服从多数策略")
    print("="*60)
    
    print(f"\n控制参数:")
    print(f"  保存完全一致: {'是' if save_consistent else '否'}")
    print(f"  保存多数一致: {'是' if save_majority else '否'}")
    print(f"  保存完全分歧: {'是' if save_conflict else '否'}")
    
    print(f"\n分析的文件总数量: {total_count}")
    
    print("\n最终分类统计:")
    print(f"  anomalous: {final_category_count['anomalous']}")
    print(f"  benign:    {final_category_count['benign']}")
    print(f"  malicious: {final_category_count['malicious']}")
    
    print("\n最终比率统计:")
    print(f"  anomalous率: {anomalous_rate:.2f}%")
    print(f"  benign率:    {benign_rate:.2f}%")
    print(f"  malicious率: {malicious_rate:.2f}%")
    print(f"  anomalous+malicious率: {combined_rate:.2f}%")
    
    print("\n投票情况统计:")
    print(f"  完全一致: {vote_count['consistent']} ({vote_count['consistent']/total_count*100:.2f}%)")
    print(f"  多数一致: {vote_count['majority']} ({vote_count['majority']/total_count*100:.2f}%)")
    print(f"  完全分歧: {vote_count['split']} ({vote_count['split']/total_count*100:.2f}%)")
    
    print("\n数据包保存情况:")
    print(f"  完全一致数据包: {len(consistent_files)} 个")
    print(f"  多数一致数据包: {len(majority_files)} 个")
    print(f"  完全分歧数据包: {len(conflict_files)} 个")
    print(f"  出入详情记录: {len(discrepancy_details)} 条")
    
    print("\n" + "="*60)
    
    return {
        "final_category_count": final_category_count,
        "vote_count": vote_count,
        "consistent_files": consistent_files if save_consistent else [],
        "majority_files": majority_files if save_majority else [],
        "conflict_files": conflict_files if save_conflict else [],
        "discrepancy_details": discrepancy_details
    }


def evaluate_results_threeRounds_lightweight(report_dir_1="report_xxxx",
                                            report_dir_2="report_xxxx_(twice)",
                                            report_dir_3="report_xxxx_(third)"):
    """
    轻量级版本的三轮评估函数，以report_dir_1为基准，
    仅对benign数据包使用少数服从多数策略，其他数据包直接采用report_dir_1的结果
    
    Args:
        report_dir_1: 基准报告目录（作为主要参考）
        report_dir_2: 第二个报告目录
        report_dir_3: 第三个报告目录
    """
    import json
    import os
    from collections import Counter
    
    # 获取三个文件夹中的JSON文件
    files1 = {f for f in os.listdir(report_dir_1) if f.endswith('.json')}
    files2 = {f for f in os.listdir(report_dir_2) if f.endswith('.json')}
    files3 = {f for f in os.listdir(report_dir_3) if f.endswith('.json')}
    
    # 找出三个文件夹中都存在的共同文件
    common_files = files1 & files2 & files3
    print(f"找到 {len(common_files)} 个共同文件")
    
    if not common_files:
        print("没有找到共同的JSON文件，请检查路径是否正确")
        return
    
    # 统计最终结果
    final_category_count = {"anomalous": 0, "benign": 0, "malicious": 0}
    vote_count = {"majority_vote": 0, "direct_adopt": 0}  # 投票情况统计
    
    # 详细记录
    majority_vote_files = []  # 使用少数服从多数的文件
    direct_adopt_files = []  # 直接采用report_dir_1结果的文件
    
    # 处理每个文件
    for filename in common_files:
        categories = []
        
        # 首先读取基准文件夹的结果
        file_path_1 = os.path.join(report_dir_1, filename)
        try:
            with open(file_path_1, "r", encoding="utf-8") as f:
                data1 = json.load(f)
            baseline_category = data1.get("category", "").lower()
        except Exception as e:
            print(f"Error processing file {file_path_1}: {e}")
            continue
        
        # 如果基准文件夹的结果是benign，则使用少数服从多数策略
        if baseline_category == "benign":
            # 读取另外两个文件夹的结果
            for report_dir in [report_dir_2, report_dir_3]:
                file_path = os.path.join(report_dir, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    category = data.get("category", "").lower()
                    if category:  # 只添加非空分类
                        categories.append(category)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
            
            # 如果没有获取到足够的分类结果，跳过这个文件
            if len(categories) < 2:
                final_category = baseline_category
                vote_count["direct_adopt"] += 1
                direct_adopt_files.append({
                    "filename": filename,
                    "final_category": final_category,
                    "vote_type": "direct_adopt",
                    "reason": "无法获取足够分类结果"
                })
            else:
                # 使用少数服从多数策略
                categories.append(baseline_category)  # 包括基准分类
                category_counter = Counter(categories)
                
                if len(category_counter) == 1:  # 三个结果完全一致
                    final_category = baseline_category
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter)
                    })
                elif len(category_counter) == 2 and max(category_counter.values()) >= 2:  # 多数一致
                    final_category = max(category_counter, key=category_counter.get)
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter)
                    })
                else:  # 分歧情况，优先保持原分类
                    final_category = baseline_category
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter),
                        "note": "分歧时保持基准分类"
                    })
        else:
            # 对于非benign数据包，直接采用基准结果
            final_category = baseline_category
            vote_count["direct_adopt"] += 1
            direct_adopt_files.append({
                "filename": filename,
                "final_category": final_category,
                "vote_type": "direct_adopt",
                "reason": "非benign数据包，直接采用基准结果"
            })
        
        # 统计最终分类
        if final_category in final_category_count:
            final_category_count[final_category] += 1
    
    # 输出详细统计结果
    print("\n" + "="*60)
    print("三轮评估结果 - 轻量级版本")
    print("="*60)
    
    print(f"\n处理策略统计:")
    print(f"  使用少数服从多数策略: {vote_count['majority_vote']} 个数据包")
    print(f"  直接采用基准结果: {vote_count['direct_adopt']} 个数据包")
    
    print(f"\n数据包详情:")
    print(f"  基准文件夹中benign数据包数量: {vote_count['majority_vote']}")
    print(f"  非benign数据包数量: {vote_count['direct_adopt']}")
    
    # 计算比率
    total_count = len(common_files)
    if total_count > 0:
        anomalous_rate = final_category_count["anomalous"] / total_count * 100
        benign_rate = final_category_count["benign"] / total_count * 100
        malicious_rate = final_category_count["malicious"] / total_count * 100
        combined_rate = (final_category_count["anomalous"] + final_category_count["malicious"]) / total_count * 100
    else:
        anomalous_rate = benign_rate = malicious_rate = combined_rate = 0
    
    print(f"\n最终分类统计:")
    print(f"  anomalous: {final_category_count['anomalous']}")
    print(f"  benign:    {final_category_count['benign']}")
    print(f"  malicious: {final_category_count['malicious']}")
    
    print("\n最终比率统计:")
    print(f"  anomalous率: {anomalous_rate:.2f}%")
    print(f"  benign率:    {benign_rate:.2f}%")
    print(f"  malicious率: {malicious_rate:.2f}%")
    print(f"  anomalous+malicious率: {combined_rate:.2f}%")
    
    print(f"\n少数服从多数数据包详情:")
    if majority_vote_files:
        # 分析投票结果变化
        category_changes = {"unchanged": 0, "changed": 0}
        for file_info in majority_vote_files:
            baseline_category = "benign"  # 由于只有benign数据包会进入这个处理流程
            final_category = file_info["final_category"]
            if baseline_category == final_category:
                category_changes["unchanged"] += 1
            else:
                category_changes["changed"] += 1
        
        print(f"  分类未变化: {category_changes['unchanged']} 个")
        print(f"  分类发生变化: {category_changes['changed']} 个")
        if vote_count['majority_vote'] > 0:
            change_rate = category_changes['changed'] / vote_count['majority_vote'] * 100
            print(f"  分类变化率: {change_rate:.2f}%")
    
    print("\n" + "="*60)
    
    return {
        "final_category_count": final_category_count,
        "vote_count": vote_count,
        "majority_vote_files": majority_vote_files,
        "direct_adopt_files": direct_adopt_files,
        "total_files": total_count
    }


def evaluate_results_threeRounds_lightweight_for_increment(report_dir_1="report_xxxx",
                                                          report_dir_2="report_xxxx_(twice)",
                                                          report_dir_3="report_xxxx_(third)"):
    """
    增量版本的三轮评估函数，专门处理部分请求重新检测的情况
    仅对进行了重新检测的请求使用少数服从多数策略，未检测的直接采用report_dir_1的结果
    
    Args:
        report_dir_1: 基准报告目录（包含所有请求的初始检测结果）
        report_dir_2: 第二个报告目录（仅包含部分重新检测的请求）
        report_dir_3: 第三个报告目录（仅包含部分重新检测的请求）
    """
    import json
    import os
    from collections import Counter
    
    # 获取三个文件夹中的JSON文件
    files1 = {f for f in os.listdir(report_dir_1) if f.endswith('.json')}
    files2 = {f for f in os.listdir(report_dir_2) if f.endswith('.json')}
    files3 = {f for f in os.listdir(report_dir_3) if f.endswith('.json')}
    
    print(f"基准文件夹文件数量: {len(files1)}")
    print(f"第二轮检测文件数量: {len(files2)}")
    print(f"第三轮检测文件数量: {len(files3)}")
    
    # 找出进行了重新检测的文件（存在于report_dir_2和report_dir_3中）
    rechecked_files = files2 & files3
    print(f"进行了重新检测的文件数量: {len(rechecked_files)}")
    
    # 所有需要处理的文件是基准文件夹中的所有文件
    all_files = files1
    print(f"总处理文件数量: {len(all_files)}")
    
    if not all_files:
        print("基准文件夹中没有找到JSON文件，请检查路径是否正确")
        return
    
    # 统计最终结果
    final_category_count = {"anomalous": 0, "benign": 0, "malicious": 0}
    vote_count = {"majority_vote": 0, "direct_adopt": 0}  # 投票情况统计
    
    # 详细记录
    majority_vote_files = []  # 使用少数服从多数的文件
    direct_adopt_files = []  # 直接采用report_dir_1结果的文件
    
    # 处理每个文件
    for filename in all_files:
        # 首先读取基准文件夹的结果
        file_path_1 = os.path.join(report_dir_1, filename)
        try:
            with open(file_path_1, "r", encoding="utf-8") as f:
                data1 = json.load(f)
            baseline_category = data1.get("category", "").lower()
        except Exception as e:
            print(f"Error processing file {file_path_1}: {e}")
            continue
        
        # 判断是否进行了重新检测
        if filename in rechecked_files:
            # 进行了重新检测，使用少数服从多数策略
            categories = []
            
            # 读取三个文件夹的结果
            for report_dir in [report_dir_1, report_dir_2, report_dir_3]:
                file_path = os.path.join(report_dir, filename)
                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    category = data.get("category", "").lower()
                    if category:  # 只添加非空分类
                        categories.append(category)
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
            
            # 如果没有获取到足够的分类结果，跳过这个文件
            if len(categories) < 3:
                final_category = baseline_category
                vote_count["direct_adopt"] += 1
                direct_adopt_files.append({
                    "filename": filename,
                    "final_category": final_category,
                    "vote_type": "direct_adopt",
                    "reason": "重新检测但无法获取足够分类结果"
                })
            else:
                # 使用少数服从多数策略
                category_counter = Counter(categories)
                
                if len(category_counter) == 1:  # 三个结果完全一致
                    final_category = categories[0]
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter),
                        "status": "完全一致"
                    })
                elif len(category_counter) == 2 and max(category_counter.values()) >= 2:  # 多数一致
                    final_category = max(category_counter, key=category_counter.get)
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter),
                        "status": "多数一致"
                    })
                else:  # 分歧情况，优先保持原分类
                    final_category = baseline_category
                    vote_count["majority_vote"] += 1
                    majority_vote_files.append({
                        "filename": filename,
                        "final_category": final_category,
                        "vote_type": "majority_vote",
                        "votes": categories,
                        "vote_distribution": dict(category_counter),
                        "status": "分歧时保持基准分类"
                    })
        else:
            # 未进行重新检测，直接采用基准结果
            final_category = baseline_category
            vote_count["direct_adopt"] += 1
            direct_adopt_files.append({
                "filename": filename,
                "final_category": final_category,
                "vote_type": "direct_adopt",
                "reason": "未进行重新检测"
            })
        
        # 统计最终分类
        if final_category in final_category_count:
            final_category_count[final_category] += 1
    
    # 输出详细统计结果
    print("\n" + "="*70)
    print("三轮评估结果 - 增量版本（部分请求重新检测）")
    print("="*70)
    
    print(f"\n检测情况统计:")
    print(f"  基准文件夹请求总数: {len(all_files)}")
    print(f"  进行了重新检测的请求: {len(rechecked_files)} ({len(rechecked_files)/len(all_files)*100:.2f}%)")
    print(f"  未进行重新检测的请求: {len(all_files) - len(rechecked_files)} ({(len(all_files) - len(rechecked_files))/len(all_files)*100:.2f}%)")
    
    print(f"\n处理策略统计:")
    print(f"  使用少数服从多数策略: {vote_count['majority_vote']} 个数据包")
    print(f"  直接采用基准结果: {vote_count['direct_adopt']} 个数据包")
    
    # 计算比率
    total_count = len(all_files)
    if total_count > 0:
        anomalous_rate = final_category_count["anomalous"] / total_count * 100
        benign_rate = final_category_count["benign"] / total_count * 100
        malicious_rate = final_category_count["malicious"] / total_count * 100
        combined_rate = (final_category_count["anomalous"] + final_category_count["malicious"]) / total_count * 100
    else:
        anomalous_rate = benign_rate = malicious_rate = combined_rate = 0
    
    print(f"\n最终分类统计:")
    print(f"  anomalous: {final_category_count['anomalous']}")
    print(f"  benign:    {final_category_count['benign']}")
    print(f"  malicious: {final_category_count['malicious']}")
    
    print("\n最终比率统计:")
    print(f"  anomalous率: {anomalous_rate:.2f}%")
    print(f"  benign率:    {benign_rate:.2f}%")
    print(f"  malicious率: {malicious_rate:.2f}%")
    print(f"  anomalous+malicious率: {combined_rate:.2f}%")
    
    # 重新检测请求的详细分析
    if majority_vote_files:
        print(f"\n重新检测请求详细分析:")
        
        # 分析投票结果变化
        category_changes = {"unchanged": 0, "changed": 0}
        vote_status_counts = {"完全一致": 0, "多数一致": 0, "分歧时保持基准分类": 0}
        
        for file_info in majority_vote_files:
            baseline_category = file_info["votes"][0]  # 基准结果是第一个
            final_category = file_info["final_category"]
            status = file_info.get("status", "")
            
            if baseline_category == final_category:
                category_changes["unchanged"] += 1
            else:
                category_changes["changed"] += 1
            
            if status in vote_status_counts:
                vote_status_counts[status] += 1
        
        print(f"  分类未变化: {category_changes['unchanged']} 个")
        print(f"  分类发生变化: {category_changes['changed']} 个")
        if vote_count['majority_vote'] > 0:
            change_rate = category_changes['changed'] / vote_count['majority_vote'] * 100
            print(f"  分类变化率: {change_rate:.2f}%")
        
        print(f"\n  投票状态分布:")
        for status, count in vote_status_counts.items():
            if vote_count['majority_vote'] > 0:
                percentage = count / vote_count['majority_vote'] * 100
                print(f"    {status}: {count} 个 ({percentage:.2f}%)")
    
    print("\n" + "="*70)
    
    return {
        "final_category_count": final_category_count,
        "vote_count": vote_count,
        "majority_vote_files": majority_vote_files,
        "direct_adopt_files": direct_adopt_files,
        "total_files": total_count,
        "rechecked_files_count": len(rechecked_files),
        "baseline_files_count": len(all_files)
    }
    

def evaluate_results():
    total_count = 0
    category_count = {"anomalous": 0, "benign": 0, "malicious": 0}

    report_dir = "report_exp/report_xxxx-with-GPT-5.2"

    is_twice_normal = False
    is_twice_anomalous = False
    is_dump = False
    for filename in os.listdir(report_dir):
        if filename.endswith(".json"):
            file_path = os.path.join(report_dir, filename)
            # print(file_path)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                category = data.get("category", "").lower()
                # if category == "benign":
                #     print("benign file:", filename)
                # if is_dump and category in ["anomalous", "malicious"]:
                #     filepath = os.path.join(report_dir, "noBenign", filename)
                if is_dump and category == "benign":
                    filepath = os.path.join(report_dir, category, filename)
                # detect_result = data["detection_result"].get("reporterResult", {})[0].get("vuln", "anomalous")
                # print(f"{filename}: category={category}, detect_result={detect_result}")

                # if is_dump and category == "malicious":
                #     if "SQL" in detect_result:
                #         filepath = os.path.join(report_dir, "SQL", filename)
                #     elif "XSS" in detect_result or "Cross" in detect_result:
                #         filepath = os.path.join(report_dir, "XSS", filename)
                #     elif "SSI" in detect_result:
                #         filepath = os.path.join(report_dir, "SSI", filename)
                #     else:
                #         filepath = os.path.join(report_dir, "Other", filename)
                
                    
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    with open(filepath, 'w', encoding='utf-8') as file_dump:
                        json.dump(data, file_dump, ensure_ascii=False, indent=4)
                if category in category_count:
                    category_count[category] += 1
                total_count += 1
                # if total_count > 10:
                #     exit(1)
            except Exception as e:
                print("Error processing file {}: {}".format(filename, e))
    # 计算比率
    anomalous_rate = category_count["anomalous"] / total_count * 100 if total_count > 0 else 0
    combined_rate = (category_count["anomalous"] + category_count["malicious"]) / total_count * 100 if total_count > 0 else 0

    # 输出统计结果
    print(f"JSON文件总数量: {total_count}")
    print("分类统计:")
    print(f"  anomalous: {category_count['anomalous']}")
    print(f"  benign:    {category_count['benign']}")
    print(f"  malicious: {category_count['malicious']}")
    print("\n比率统计:")
    print(f"  anomalous率: {anomalous_rate:.2f}%")
    print(f"  anomalous+malicious率: {combined_rate:.2f}%")
    
    if is_twice_normal or is_twice_anomalous:
        if is_twice_normal:
            total_real_count = 36000
        elif is_twice_anomalous:
            # total_real_count = 21021
            # total_real_count = 21538
            # total_real_count = 21073
            total_real_count = 20921
            # total_real_count = 25065
        print(f"\n基于实际请求总数量 ({total_real_count}) 的比率统计:")
        if is_twice_normal:
            print(f"  anomalous率: {category_count['anomalous'] / total_real_count * 100:.2f}%")
            print(f"  anomalous+malicious率: {(category_count['anomalous'] + category_count['malicious']) / total_real_count * 100:.2f}%")
        elif is_twice_anomalous:
            print(f"  benign率: {category_count['benign'] / total_real_count * 100:.2f}%")
    
def evaluate_reports_probability():
    report_dir_1 = "report_twice/report_anomalous-from-report-normalTrafficTest(round1)"
    report_dir_2 = "report_twice/report_anomalous-from-report-normalTrafficTest(round2)"
    report_dir_3 = "report_twice/report_anomalous-from-report-normalTrafficTest(round3)"
    
    # 获取所有文件夹中的JSON文件
    files1 = {f for f in os.listdir(report_dir_1) if f.endswith('.json')}
    files2 = {f for f in os.listdir(report_dir_2) if f.endswith('.json')}
    files3 = {f for f in os.listdir(report_dir_3) if f.endswith('.json')}
    
    # 找出三个文件夹中都存在的共同文件
    common_files = files1 & files2 & files3
    print(f"找到 {len(common_files)} 个共同文件")

def filter_requests(input_file, keyword_list, output_file="datasets/anomalousTrafficTest_filtered.txt"):
    if not keyword_list:
        logger.error("No keywords provided for filtering.")
        return
    print(keyword_list)
    # exit(1)
    # input_file = "datasets/anomalousTrafficTest.txt"
    # output_file = "datasets/anomalousTrafficTest_filtered.txt"
    
    if not os.path.exists(input_file):
        logger.error(f"The file {input_file} does not exist.")
        return
    
    with open(input_file, 'r', encoding='utf-8') as f:
        raw_requests = f.read()
    
    # 确保换行符格式一致（适用于 Windows / Linux / macOS）
    raw_requests = raw_requests.replace("\r\n", "\n").strip()

    # 通过 `GET|POST|PUT|DELETE` 作为分割点，但保留匹配的请求方法
    requests = re.split(r"(?=^(?:GET|POST|PUT|DELETE) )", raw_requests, flags=re.MULTILINE)

    # 过滤掉空白项
    requests = [req.strip() for req in requests if req.strip()]

    none_filtered_requests = []
    filtered_requests = []
    for request in requests:
        # print(request)
        ## 避免Cookie影响结果
        request_lines = request.split("\n")
        request_handle = request_lines[0] + "\n\n" + request_lines[1] + "\n\n" + request_lines[-1]
        # print(request_handle)
        if any(keyword in request_handle for keyword in keyword_list):
            filtered_requests.append(request)
        else:
            none_filtered_requests.append(request)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(filtered_requests))

    none_filtered_requests_filename = output_file.replace(".txt", "_none_filtered.txt")
    with open(none_filtered_requests_filename, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(none_filtered_requests))
    
    logger.info(f"Filtered requests saved to {output_file}. None   requests saved to {none_filtered_requests_filename}. Total filtered requests: {len(filtered_requests)}.Total none filtered requests: {len(none_filtered_requests)}. Total requests: {len(requests)}.")

def filter_requests_with_other_file(input_file, other_file, output_file):
    if not os.path.exists(input_file):
        logger.error(f"The file {input_file} does not exist.")
        return
    if not os.path.exists(other_file):
        logger.error(f"The file {other_file} does not exist.")
        return
    
    with open(other_file, 'r', encoding='utf-8') as f:
        other_requests = f.read()
    
    # 确保换行符格式一致（适用于 Windows / Linux / macOS）
    other_requests = other_requests.replace("\r\n", "\n").strip()

    # 通过 `GET|POST|PUT|DELETE` 作为分割点，但保留匹配的请求方法
    other_requests_list = re.split(r"(?=^(?:GET|POST|PUT|DELETE) )", other_requests, flags=re.MULTILINE)

    # 过滤掉空白项
    other_requests_list = [req.strip() for req in other_requests_list if req.strip()]
    print(f"Total requests in other file: {len(other_requests_list)}")
    
    with open(input_file, 'r', encoding='utf-8') as f:
        raw_requests = f.read()
    
    # 确保换行符格式一致（适用于 Windows / Linux / macOS）
    raw_requests = raw_requests.replace("\r\n", "\n").strip()

    # 通过 `GET|POST|PUT|DELETE` 作为分割点，但保留匹配的请求方法
    requests = re.split(r"(?=^(?:GET|POST|PUT|DELETE) )", raw_requests, flags=re.MULTILINE)

    # 过滤掉空白项
    requests = [req.strip() for req in requests if req.strip()]
    
    filtered_requests = []
    for request in requests:
        if request not in other_requests_list:
            filtered_requests.append(request)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(filtered_requests))
    
    logger.info(f"Filtered requests saved to {output_file}. Total filtered requests: {len(filtered_requests)}. Total requests: {len(requests)}.")


def extract_and_save_from_report(report_dir, output_file):
    if not os.path.exists(report_dir):
        logger.error(f"The directory {report_dir} does not exist.")
        return
    
    extracted_requests = []
    for filename in os.listdir(report_dir):
        if filename.endswith(".json"):
            file_path = os.path.join(report_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                category = data.get("category", "").lower()
                # if category == "benign" or category == "anomalous":
                if category == "benign":
                # if category == "anomalous":
                # if category == "malicious":
                # if category == "malicious" or category == "anomalous":
                # if category is not None:
                    http_request = data.get("original_request", "").strip()
                    if http_request:
                        extracted_requests.append(http_request)
            except Exception as e:
                print(f"Error processing file {filename}: {e}")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n\n'.join(extracted_requests))
    
    logger.info(f"Extracted {len(extracted_requests)} HTTP requests and saved to {output_file}.")

def main():
    args = args_initial()
    if args.index_datasets:
        logger.info("Indexing datasets to vector store...")
        if all([args.in_file, args.index_name]):
            save_to_vectorstore(args.in_file, connection(args.index_name), args.index_name)
    elif args.test and args.flag:
        test(args.flag)
        # supervisor_test()
    elif args.evaluate:
        logger.info("Evaluating the results...")
        evaluate_results()

    
    else:
        logger.error("missing arguments")
        exit(1)
        
            
    
    logger.info("Exit...")
    # ExtractAgent("select 1,2,3--+").create_prompt()
    # print(prompt_maker("Detailed analysis of the role of malicious SQL statements in the SQL injection process", "Now my input is a malicious SQL statement. Please analyze the role of this statement in the SQL injection process in detail"))
    
    # print(ExtractAgent("SQL injection", "SQL injection", "\" OR 1 = 1 -- -").extract())

if __name__ == "__main__":
        #     // "LANGSMITH_TRACING": "true",
    env_initial()
    init_logger()
    
    # print(ExtractAgent("SQL injection", "SQL injection", "\" OR 1 = 1 -- -").extract())
    main()