from typing import Annotated, Literal, Dict, Any, Optional
from typing_extensions import TypedDict
from langgraph.graph import add_messages, END, START, StateGraph, MessagesState
from pydantic import BaseModel, Field

class ParseForm(BaseModel):
    """Form for the parse worker."""
    # http_json: Dict[str, Any] = Field(..., description="The parsed HTTP request in JSON format")
    url: str = Field(..., description="The URL of the HTTP request")
    headers: Dict[str, str] = Field(..., description="The headers of the HTTP request")
    body: str = Field(..., description="The body of the HTTP request")
    # value_type: Dict[str, Literal["HTTP", "XML", "SQL", "HTML", "Unknown"]] = Field(..., description="The type of each value in JSON, which key is the value name in http_json")
    
class ClassifyForm(BaseModel):
    """Form for the classify agent to classify the content."""
    SQL: Dict[str, Any] = Field(default_factory=dict, description="Content that belongs to SQL")
    Unknown: Dict[str, Any] = Field(default_factory=dict, description="Content that belongs to Unknown")
    XML: Dict[str, Any] = Field(default_factory=dict, description="Content that belongs to XML")
    XSS: Dict[str, Any] = Field(default_factory=dict, description="Content that belongs to XSS")

class AnomalousForm(BaseModel):
    """Form for the detector_anomalous_node to detect the anomalous traffic"""
    cause: list = Field(description="The brief reason of anomalous traffic")
    position: list = Field(description="The location of the http request that generated the anomalous")
    statement: list = Field(description="The specifical statement caused anomalous")
    result: list = Field(description="Whether the provided http request is anomalous")

class ExtractForm(BaseModel):
    """Form for the Extract agent to summary the content."""
    summary: str = Field(description="The brief summary of the actions of the provided statement")

class ReportForm(BaseModel):
    """Form for the Report agent to generate report of the process of the detection"""
    vuln: str = Field(description="The types of vulnerabilities detected")
    position: str = Field(description="The location of the http request that generated the vulnerability")
    statement: str = Field(description="Specific statements that lead to vulnerabilities")
    cause: str = Field(description="The specific cause of the vulnerability")