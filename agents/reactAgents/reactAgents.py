from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, AnyMessage
from langgraph.prebuilt import create_react_agent, ToolNode

from utils.vectorstore_utils import connection
from prompts.core_prompt import *
from utils.model_utils import model
from agents.tools.agentTools import *
from agents.states.agentStates import *
from agents.forms.agentForms import *

parser_agent = create_react_agent(
    model, tools=[parse_http_request_tool], prompt=SystemMessage(parser_prompt), response_format=ParseForm
)

detector_payload_agent = create_react_agent(
    model, tools=[search_payload_tool], prompt=SystemMessage(detector_payload_prompt)
)

detector_summary_agent = create_react_agent(
    model, tools=[search_payload_summary_tool], prompt=SystemMessage(detector_summary_prompt)
)

detector_xss_payload_agent = create_react_agent(
    model, tools=[search_xss_payload_tool], prompt=SystemMessage(detector_xss_payload_prompt)
)

detector_xss_summary_agent = create_react_agent(
    model, tools=[search_xss_payload_summary_tool], prompt=SystemMessage(detector_xss_summary_prompt)
)

detector_xxe_summary_agent = create_react_agent(
    model, tools=[search_xxe_payload_summary_tool], prompt=SystemMessage(detector_xxe_summary_prompt)
)