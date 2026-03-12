from typing import Annotated, Literal, Dict, Any, Optional
from typing_extensions import TypedDict
from langgraph.graph import add_messages, END, START, StateGraph, MessagesState
import urllib.parse
import operator

class OverallState(MessagesState):
    """Overall state for the worker."""
    contents: Annotated[list, operator.add]
    summarys: Annotated[list, operator.add]
    categorys: Annotated[list, operator.add]
    contentsSanitized: list
    summarysSanitized: list
    categorysSanitized: list
    contentsResult: Annotated[list, operator.add]
    summarysResult: Annotated[list, operator.add]
    verifyResult: Annotated[list, operator.add]
    verify_anomalous_result: str
    anomalousResult: str
    anomalousNativeResult: str
    httpJson: Dict
    classifierResult: Dict
    # reporterResult: str
    reporterResult: Annotated[list, operator.add]
    flag: str
    # detector_content_advice: str
    # detector_summary_advice: str
    detector_content_advice: Annotated[list, operator.add]
    detector_summary_advice: Annotated[list, operator.add]
    repeat_str: str
    httpJson_repeat: Annotated[list, operator.add]

class ExtractState(TypedDict):
    input: str
    expertName: str
    category: str
    
class DetectState(TypedDict):
    contentDetect: str
    categoryDetect: str
    detector_content_advice: str
    detector_summary_advice: str
    
class VerifyState(TypedDict):
    originalStatement: str
    contentVerify: str
    summaryVerify: str
    categoryVerify: str

class ReportState(TypedDict):
    verifierResult: str
    originalJson: Dict
    vulStatement: str
    flag_category: str