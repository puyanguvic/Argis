"""LangGraph pipeline for phishing email analysis."""

from __future__ import annotations

from typing import Any, Dict, TypedDict

from langgraph.graph import END, StateGraph

from agent.config import LLMConfig
from agent.policy import PolicyEngine
from agent.state import AgentState
from schemas.email_schema import EmailSchema
from tools.attachment_analyzer import analyze_attachments
from tools.content_analyzer import analyze_content
from tools.header_analyzer import analyze_headers
from tools.parser import parse_raw_email
from tools.url_analyzer import analyze_urls


class GraphState(TypedDict, total=False):
    raw_email: str
    email: EmailSchema
    evidence: Dict[str, Any]
    scores: Dict[str, float]
    result: AgentState
    llm_config: LLMConfig


def build_agent_graph(policy: PolicyEngine):
    def parse_node(state: GraphState) -> Dict[str, Any]:
        email = state.get("email")
        if email is None:
            email = parse_raw_email(state.get("raw_email", ""))
        return {"email": email, "evidence": state.get("evidence", {})}

    def headers_node(state: GraphState) -> Dict[str, Any]:
        evidence = dict(state.get("evidence", {}))
        evidence["headers"] = analyze_headers(state["email"])
        return {"evidence": evidence}

    def urls_node(state: GraphState) -> Dict[str, Any]:
        evidence = dict(state.get("evidence", {}))
        evidence["urls"] = analyze_urls(state["email"])
        return {"evidence": evidence}

    def content_node(state: GraphState) -> Dict[str, Any]:
        evidence = dict(state.get("evidence", {}))
        evidence["content"] = analyze_content(state["email"], llm_config=state.get("llm_config"))
        return {"evidence": evidence}

    def attachments_node(state: GraphState) -> Dict[str, Any]:
        evidence = dict(state.get("evidence", {}))
        evidence["attachments"] = analyze_attachments(state["email"])
        return {"evidence": evidence}

    def policy_node(state: GraphState) -> Dict[str, Any]:
        result = policy.evaluate(
            state["email"],
            state.get("evidence", {}),
            llm_config=state.get("llm_config"),
        )
        return {"result": result, "scores": result.scores}

    workflow = StateGraph(GraphState)
    workflow.add_node("parse_email", parse_node)
    workflow.add_node("analyze_headers", headers_node)
    workflow.add_node("analyze_urls", urls_node)
    workflow.add_node("analyze_content", content_node)
    workflow.add_node("analyze_attachments", attachments_node)
    workflow.add_node("apply_policy", policy_node)

    workflow.set_entry_point("parse_email")
    workflow.add_edge("parse_email", "analyze_headers")
    workflow.add_edge("analyze_headers", "analyze_urls")
    workflow.add_edge("analyze_urls", "analyze_content")
    workflow.add_edge("analyze_content", "analyze_attachments")
    workflow.add_edge("analyze_attachments", "apply_policy")
    workflow.add_edge("apply_policy", END)

    return workflow.compile()
