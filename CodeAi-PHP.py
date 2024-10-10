# coding=utf-8
'''
by：Segador
'''
import subprocess
import sys
import json
import requests
import re
import os
import logging
from html import escape

# 在文件顶部创建全局 logger 对象
logger = logging.getLogger(__name__)

def run_phpid(directory):
    """运行 phpid.py，并返回输出"""
    command = ['python3', 'phpid.py', '-d', directory]
    # logger.debug(f"执行命令: {' '.join(command)}")
    try:
        process = subprocess.run(command, capture_output=True, text=True, check=True)
        logger.debug(f"phpid.py 执行成功，输出长度: {len(process.stdout)}")
        return process.stdout
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running phpid.py: {e.stderr}")
        sys.exit(1)

def get_file_content(file_path):
    """读取文件内容"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            return file.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None
# GPT配置处
def ask_gpt(content):
    logger.debug("开始询问 GPT")
    api_url = ""
    headers = {
        "Authorization": "",
        "Content-Type": "application/json",
    }
    data = {
        "bot_id": "",
        "user_id": "",
        "stream": True,
        "auto_save_history": True,
        "additional_messages": [
            {
                "role": "user",
                "content": content,
                "content_type": "text"
            }
        ]
    }
    response = requests.post(api_url, headers=headers, data=json.dumps(data))
    if response.status_code == 200:
        logger.debug("GPT 响应成功")
        decoded_content = response.content.decode('utf-8')
        contents = re.findall(r'"content":"(.*?)","content_type', decoded_content)
        content = contents[-5] if len(contents) >= 5 else "Error: Unable to retrieve the content"
        content = content.replace(r'\n', '\n').replace(r'\n\n', '\n').replace("\\\"","").replace("**","")
        return content
    else:
        logger.error(f"GPT 响应错误: {response.status_code} {response.text}")
        return f"Error: {response.status_code} {response.text}"

def extract_route(file_content):
    """从文件内容中提取路由信息"""
    route_patterns = [
        r'@Route\(["\'](.+?)["\']\)',  # Symfony 风格
        r'\$router->add\(["\'](.+?)["\']',  # 一些 PHP 框架
        r'->route\(["\'](.+?)["\']',  # Laravel 风格
        r'app->get\(["\'](.+?)["\']',  # Express.js 风格 (如果有 PHP 等效)
    ]
    
    for pattern in route_patterns:
        match = re.search(pattern, file_content)
        if match:
            return match.group(1)
    
    # 如果没有找到路由，返回文件名作为默认路由
    return None

def analyze_file(file_path, file_content):
    route = extract_route(file_content) or os.path.basename(file_path)
    
    prompt = f"""
作为一个安全专家，请分析以下PHP代码是否存在安全隐患：

文件路径：{file_path}
路由信息：{route}

文件内容：
{file_content}

如果存在安全隐患，请提供以下信息：
1. 漏洞类型
2. 漏洞描述
3. 一个可以直接使用的完整验证数据包POC，包括：
   - 完整的HTTP请求头
   - 请求方法（GET/POST等）
   - 完整的URL路径（使用提供的路由信息 {route}）
   - 所有必要的参数和它们的值
   - 如果是POST请求，请包含请求体，并确保Content-Type正确设置

POC应该能够触发漏洞，但不应该对系统造成实际损害。请确保POC可以直接复制并使用。
请根据漏洞类型选择合适的请求方法（GET或POST），并按照以下格式提供POC：

对于GET请求：
GET /{route}?param1=value1&param2=value2 HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive

对于POST请求：
POST /{route} HTTP/1.1
Host: localhost
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.112 Safari/537.36
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: [计算实际长度]

param1=value1&param2=value2

4. 修复建议

如果不存在安全隐患，请回复"该文件不存在安全隐患"。
"""
    return ask_gpt(prompt)

def extract_poc(analysis_result):
    poc_pattern = r'```\s*((?:GET|POST).*?)```'
    poc_match = re.search(poc_pattern, analysis_result, re.DOTALL | re.IGNORECASE)
    if poc_match:
        poc = poc_match.group(1).strip()
        return poc
    return "未找到有效的 POC"

def extract_vuln_info(analysis_result):
    vuln_type_match = re.search(r'漏洞类型[:：]\s*(.+)', analysis_result)
    vuln_type = vuln_type_match.group(1) if vuln_type_match else "未知"
    
    description_match = re.search(r'漏洞描述[:：](.*?)(?=3\.|\Z)', analysis_result, re.DOTALL)
    description = description_match.group(1).strip() if description_match else "无描述"
    
    request_type_match = re.search(r'(GET|POST)', analysis_result)
    request_type = request_type_match.group(1) if request_type_match else "未知"
    
    return vuln_type, request_type, description

def extract_fix_suggestion(analysis_result):
    fix_match = re.search(r'4\.\s*修复建议[:：](.*?)(?=\n\n|\Z)', analysis_result, re.DOTALL)
    return fix_match.group(1).strip() if fix_match else "无具体修复建议。"

def generate_html_report(results, vulnerability_count, vulnerability_types):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>漏洞分析报告</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; padding: 20px; background-color: #f0f0f0; }}
            .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
            h1, h2, h3 {{ color: #333; }}
            pre {{ background-color: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }}
            .vulnerability {{ margin-bottom: 30px; border-bottom: 1px solid #ccc; padding-bottom: 20px; }}
            .poc-form {{ margin-top: 10px; }}
            .poc-form textarea {{ width: 100%; height: 200px; padding: 5px; margin-bottom: 10px; }}
            .poc-form input[type="text"] {{ width: 300px; padding: 5px; margin-right: 10px; }}
            .poc-form input[type="submit"] {{ padding: 5px 10px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }}
            #response {{ margin-top: 20px; border: 1px solid #ddd; padding: 10px; }}
            .stats {{ background-color: #e9e9e9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
            .vuln-description {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; margin-bottom: 10px; }}
            .fix-suggestion {{ background-color: #e6f7ff; padding: 10px; border-radius: 5px; margin-top: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>漏洞分析报告</h1>
            <div class="stats">
                <h2>漏洞统计</h2>
                <p>总共发现 {vulnerability_count} 个漏洞</p>
                <h3>漏洞类型统计：</h3>
                <ul>
    """
    
    for vuln_type, count in vulnerability_types.items():
        html_content += f"<li>{vuln_type}: {count} 个</li>"
    
    html_content += """
                </ul>
            </div>
    """
    
    for index, result in enumerate(results):
        vuln_type, request_type, description = extract_vuln_info(result['analysis'])
        fix_suggestion = extract_fix_suggestion(result['analysis'])
        
        html_content += f"""
        <div class="vulnerability">
            <h2>文件: {escape(result['file_path'])}</h2>
            <div class="vuln-info">
                <p><strong>漏洞名称：</strong>{escape(vuln_type)}</p>
                <p><strong>漏洞请求类型：</strong>{escape(request_type)}</p>
            </div>
            <div class="vuln-description">
                <h3>漏洞描述：</h3>
                <p>{escape(description)}</p>
            </div>
            <div class="poc-form">
                <form onsubmit="return executePOC(this, {index});">
                    <textarea name="poc">{escape(result['poc'])}</textarea><br>
                    <input type="text" name="host" placeholder="输入目标主机" required>
                    <input type="text" name="path" placeholder="输入路径（选填）">
                    <input type="submit" value="执行 POC">
                </form>
            </div>
            <div id="response{index}"></div>
            <div class="fix-suggestion">
                <h3>修复建议：</h3>
                <p>{escape(fix_suggestion)}</p>
            </div>
        </div>
        """
    
    html_content += """
        </div>
        <script>
        function executePOC(form, index) {
            var poc = form.poc.value;
            var host = form.host.value;
            var path = form.path.value || '';
            
            // 解析 POC
            var lines = poc.split('\\n');
            var firstLine = lines[0].split(' ');
            var method = firstLine[0];
            var originalPath = firstLine[1];
            
            if (method === 'GET') {
                // 构建新的 URL
                var url = 'http://' + host;
                if (path) {
                    url += '/' + path;
                }
                url += originalPath;
                
                // 打开新窗口或标签页
                window.open(url, '_blank');
            } else if (method === 'POST') {
                var form = document.createElement('form');
                form.method = 'POST';
                form.action = 'http://' + host + (path ? '/' + path : '') + originalPath;
                form.target = '_blank';

                // 提取POST数据
                var postData = poc.split('\\n\\n').pop();
                var params = new URLSearchParams(postData);
                
                for (var pair of params.entries()) {
                    var input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = pair[0];
                    input.value = pair[1];
                    form.appendChild(input);
                }

                document.body.appendChild(form);
                form.submit();
                document.body.removeChild(form);
            }
            
            return false;
        }
        </script>
    </body>
    </html>
    """
    
    return html_content

def main(directory):
    logging.basicConfig(level=logging.DEBUG)

    logger.debug(f"开始分析目录: {directory}")
    
    # 运行 phpid.py，并获取输出
    # logger.debug("运行 phpid.py")
    phpid_output = run_phpid(directory)
    # logger.debug(f"phpid.py 输出: {phpid_output}")

    # 提取所有文件路径
    file_paths = re.findall(r'in file \[(.*?)\]', phpid_output)
    
    # 去重
    file_paths = list(set(file_paths))

    vulnerability_count = 0
    vulnerability_types = {}
    results = []

    for file_path in file_paths:
        file_content = get_file_content(file_path)
        if file_content:
            route = extract_route(file_content) or os.path.basename(file_path)
            analysis_result = analyze_file(file_path, file_content)
            print(f"文件: {file_path}")
            print(f"路由: {route}")
            print("分析结果:")
            print(analysis_result)
            
            if "该文件不存在安全隐患" not in analysis_result:
                vulnerability_count += 1
                vuln_type, _, _ = extract_vuln_info(analysis_result)
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
                
                # 提取POC
                poc = extract_poc(analysis_result)
                # print(poc)
                if poc == "未找到有效的 POC":
                    print("警告：无法提取 POC。")
                    print("原始分析结果:")
                    print(analysis_result)
                
                results.append({
                    'file_path': file_path,
                    'analysis': analysis_result,
                    'poc': poc
                })
            
            print("-" * 50)
        else:
            logger.error(f"无法读取文件内容: {file_path}")

    print("\n漏洞分析统计:")
    print(f"总共发现 {vulnerability_count} 个漏洞")
    print("漏洞类型统计:")
    for vuln_type, count in vulnerability_types.items():
        print(f"- {vuln_type}: {count} 个")

    # 生成 HTML 报告
    html_report = generate_html_report(results, vulnerability_count, vulnerability_types)
    
    # 保存 HTML 报告
    with open('vulnerability_report.html', 'w', encoding='utf-8') as f:
        f.write(html_report)
    
    print("\n漏洞分析完成，报告已保存到 vulnerability_report.html")

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python CodeAi-PHP.py <directory>")
        sys.exit(1)

    directory = sys.argv[1]
    main(directory)
