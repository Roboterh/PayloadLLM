import os
import json

def get_json_files(folder):
    """获取文件夹中所有JSON文件的列表[1,3](@ref)"""
    json_files = []
    try:
        for file in os.listdir(folder):
            if file.endswith('.json'):
                json_files.append(file)
    except FileNotFoundError:
        print(f"错误：文件夹 '{folder}' 不存在")
    return json_files

def read_original_requests(folder, json_files):
    """读取JSON文件中的original_request字段并序列化为字符串[6,7](@ref)"""
    requests_dict = {}
    for file in json_files:
        file_path = os.path.join(folder, file)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if 'original_request' in data:
                    # 序列化original_request为JSON字符串，确保键排序一致[7](@ref)
                    request_str = json.dumps(data['original_request'], sort_keys=True)
                    requests_dict[file] = request_str
                else:
                    print(f"警告: 文件 {file} 中缺少 'original_request' 字段")
                    requests_dict[file] = None
        except Exception as e:
            print(f"错误读取文件 {file}: {e}")
            requests_dict[file] = None
    return requests_dict

def main():
    # 定义文件夹路径[1](@ref)
    # folder1 = "report_twice/report_xxxx/benign"
    # folder2 = "report_third/report_xxxx/benign"
    folder1 = "report_third/report_xxxx-alterReportLogic/benign"
    folder2 = "report_anomalousTrafficTest_alterReportLogic_other/benign"
    
    # 获取两个文件夹中的JSON文件列表[1,3](@ref)
    json_files1 = get_json_files(folder1)
    json_files2 = get_json_files(folder2)
    
    if not json_files1:
        print("第一个文件夹中没有找到JSON文件")
        return
    if not json_files2:
        print("第二个文件夹中没有找到JSON文件")
        return
        
    print(f"第一个文件夹中找到 {len(json_files1)} 个JSON文件")
    print(f"第二个文件夹中找到 {len(json_files2)} 个JSON文件")
    
    # 读取两个文件夹中所有JSON文件的original_request字段[2,4](@ref)
    folder1_requests = read_original_requests(folder1, json_files1)
    folder2_requests = read_original_requests(folder2, json_files2)
    
    # 提取第二个文件夹中所有original_request的字符串集合[7](@ref)
    folder2_request_set = set()
    for req_str in folder2_requests.values():
        if req_str is not None:
            folder2_request_set.add(req_str)
    
    # 比较两个文件夹的original_request内容[5](@ref)
    existing_files = []  # 在第二个文件夹中存在对应original_request的文件
    missing_files = []   # 在第二个文件夹中不存在对应original_request的文件
    
    for file, req_str in folder1_requests.items():
        if req_str is not None and req_str in folder2_request_set:
            existing_files.append(file)
        else:
            missing_files.append(file)
    
    # 统计数量[12,13](@ref)
    num_existing = len(existing_files)
    num_missing = len(missing_files)
    
    # 输出结果到控制台
    print("\n" + "="*50)
    print("比较结果：")
    print("="*50)
    print(f"\n在第二个文件夹中存在对应original_request的文件（{num_existing}个）:")
    for file in existing_files:
        print(f"  {file}")
    
    print(f"\n在第二个文件夹中不存在对应original_request的文件（{num_missing}个）:")
    for file in missing_files:
        print(f"  {file}")
    
    # 保存结果到文件[4](@ref)
    output_file = "comparison_result.txt"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("JSON文件original_request字段比较结果\n")
            f.write("="*50 + "\n")
            f.write(f"比较时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"第一个文件夹: {folder1}\n")
            f.write(f"第二个文件夹: {folder2}\n")
            f.write("="*50 + "\n\n")
            
            f.write(f"在第二个文件夹中存在对应original_request的文件（{num_existing}个）:\n")
            for file in existing_files:
                f.write(f"  {file}\n")
            
            f.write(f"\n在第二个文件夹中不存在对应original_request的文件（{num_missing}个）:\n")
            for file in missing_files:
                f.write(f"  {file}\n")
            
            f.write("\n统计摘要:\n")
            f.write(f"  第一个文件夹中JSON文件总数: {len(json_files1)}\n")
            f.write(f"  第二个文件夹中JSON文件总数: {len(json_files2)}\n")
            f.write(f"  存在对应original_request的文件数: {num_existing}\n")
            f.write(f"  不存在对应original_request的文件数: {num_missing}\n")
        
        print(f"\n结果已保存到文件: {output_file}")
    except Exception as e:
        print(f"保存结果到文件时出错: {e}")

if __name__ == "__main__":
    main()