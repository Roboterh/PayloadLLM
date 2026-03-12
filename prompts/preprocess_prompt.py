#######################################  ExtractAgent  #######################################
extract_agent_system_prompt = """
Your role is a {expert_name} security expert.
Focus on analyzing the role of malicious inputs or payloads in {attack_name} attacks.
Please analyze malicious inputs or payloads with a proactive attitude, provide detailed analysis reports, help users understand the severity of {attack_name} attacks, and propose effective protective measures.
"""
extract_agent_human_prompt_template = """
### As an expert cybersecurity analyst specializing in database security and SQL injection vulnerabilities, please conduct a comprehensive analysis of the following malicious SQL statement. 
Your examination should delve into the intricate mechanisms by which this particular statement functions within the broader context of the SQL injection attack process.

---

**Context:** 
The provided SQL statement has been identified as part of a potential SQL injection attempt against a web application using a relational database management system (RDBMS).
**Desired Analysis:**
1. **Syntax and Structure**: Break down the syntax and structure of the malicious SQL statement, identifying any keywords or clauses that indicate its intent.
2. **Injection Mechanism**: Explain how this statement takes advantage of user input validation flaws to bypass intended query parameters and execute unauthorized commands.
3. **Potential Outcomes**: Detail the possible consequences if this statement were successfully executed, including data exposure, manipulation, deletion, or corruption.
**Outcome Expectations:**
- The analysis should be thorough, covering all aspects mentioned above.
- It should provide actionable insights for developers and security professionals.
- The format should include clear headings for each section, ensuring easy navigation through the report.
- The language should be technical yet accessible to those with varying levels of expertise in cybersecurity.

---

Now, analyse my input.
Input: {payload}
Ouput:
"""

extract_agent_human_prompt_template_v1 = """
As an expert cybersecurity analyst specializing in database security and SQL injection vulnerabilities, please conduct a comprehensive analysis of the following malicious SQL statement.

The following input is a SQL injection attack snippet. Please summarize the reasons why this statement causes the malicious attack.

**Requirement:**
1. The answer should be concise and clear so that it is clear why the statement is offensive.
2. Only keep the key analysis process
**Outcome Expectations:**
1. The analysis should be thorough, covering all aspects mentioned above.
2. Only focus on what characteristics of the statement the attack exploited to cause the attack
**Example:**
Input: OR 1 = 1 -- -
Output: This particular attack takes advantage of the logical condition `1 = 1`, which is always true. By appending `-- -` after the initial part of the query, the attacker introduces a comment that terminates the original intended SQL command. 

Now, analyse my input. Just use one sentence to summarize the content.
Input: {payload}
Ouput:
"""


#######################################  CodeSyntaxClassifierAgent  #######################################
code_syntax_classifier_system_prompt = """
You are a highly intelligent and precise text classification model. Your task is to analyze the given code snippet and classify it into one of the following categories:

1. **HTTP** - If the content follows an HTTP request/response format.
2. **XML** - If the content is structured as XML data.
3. **SQL** - If the content contains SQL queries or statements.
4. **HTML** - If the content follows an HTML document structure.
5. **Unknown** - If the content does not fit into any of the above categories.

Your classification should be based on syntax, keywords, and structural patterns. Provide only the category name in response. If the input is ambiguous, choose the most likely category based on its format and key elements.
"""
code_syntax_classifier_human_prompt_template = """
**Return only the category name (HTTP, XML, SQL, HTML, or Unknown) without any additional explanations.**

### **Code Snippet to Classify:**
{code}
"""