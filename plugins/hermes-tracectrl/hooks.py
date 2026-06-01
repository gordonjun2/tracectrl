"""TraceCtrl Hermes Agent hook handlers.

Mirrors openclaw-tracectrl src/hooks.ts.  All 11 Hermes hook handlers that
produce spans, metrics, and security detection events.

Every handler is fail-open: wrapped in try/except so telemetry errors never
crash the agent or the gateway.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from opentelemetry.trace import SpanKind, StatusCode
from opentelemetry.trace.propagation import set_span_in_context

from . import (
    TurnState,
    _TRACE_STATES,
    _STATE_LOCK,
    get_state,
    set_state,
    del_state,
    safe_end_span,
    close_state,
    get_config,
)
from .telemetry import get_runtime
from .security import analyse_tool_call, analyse_message_content

logger = logging.getLogger("tracectrl.hermes")


def _extract_args_str(args: dict) -> str:
    if not args:
        return ""
    try:
        return json.dumps(args, default=str)[:2000]
    except Exception:
        return str(args)[:2000]


def _has_error(result: str) -> bool:
    if not result:
        return False
    try:
        data = json.loads(result)
        if isinstance(data, dict):
            return bool(data.get("error")) or bool(data.get("errors"))
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Hook handlers — mirrors openclaw-tracectrl hooks.ts
# ---------------------------------------------------------------------------

def on_session_start(**kwargs: Any) -> None:
    """Create tracectrl.request root span. Mirrors message_received hook."""
    try:
        session_id = kwargs.get("session_id", "unknown")
        platform = kwargs.get("platform", "cli")
        model = kwargs.get("model", "unknown")
        tel = get_runtime()
        if tel is None:
            return

        span = tel.tracer.start_span(
            "tracectrl.request",
            kind=SpanKind.SERVER,
            attributes={
                "tracectrl.channel": platform,
                "tracectrl.session.key": session_id,
                "tracectrl.message.direction": "inbound",
                "tracectrl.message.id": session_id,
                "tracectrl.agent.framework": "hermes",
            },
        )
        ctx = set_span_in_context(span)
        state = TurnState(root_span=span, root_ctx=ctx, model=model)
        set_state(session_id, state)

        try:
            from tracectrl.session import set_session_id
            set_session_id(session_id)
        except Exception:
            pass

        tel.counters.messages_received.add(1, {"tracectrl.channel": platform})
        logger.debug("tracectrl: session started sid=%s platform=%s", session_id, platform)
    except Exception as exc:
        logger.debug("tracectrl: on_session_start error: %s", exc)


def pre_llm_call(**kwargs: Any) -> None:
    """Create tracectrl.agent.turn span. Mirrors before_agent_start hook."""
    try:
        session_id = kwargs.get("session_id", "unknown")
        model = kwargs.get("model", "unknown")
        platform = kwargs.get("platform", "cli")
        sender_id = kwargs.get("sender_id", "unknown")
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        parent_ctx = state.root_ctx if state else None

        api_call_count = len(state.agent_spans) if state else 0
        attrs = {
            "tracectrl.model": model,
            "tracectrl.provider": kwargs.get("provider", "unknown"),
            "tracectrl.channel": platform,
            "tracectrl.session.key": session_id,
            "tracectrl.agent.framework": "hermes",
            "tracectrl.message.from": sender_id,
            "gen_ai.system": kwargs.get("provider", "unknown"),
            "gen_ai.response.model": model,
        }

        span = tel.tracer.start_span(
            "tracectrl.agent.turn",
            kind=SpanKind.INTERNAL,
            attributes=attrs,
            context=parent_ctx,
        )

        if state:
            state.agent_spans[api_call_count] = span
            state.model = model
            state.provider = kwargs.get("provider", "unknown")

        user_message = kwargs.get("user_message", "")
        if user_message:
            cfg = get_config()
            if cfg and cfg.capture_content:
                analyse_message_content(user_message, span, tel)

        logger.debug("tracectrl: agent turn started model=%s call=%d", model, api_call_count)
    except Exception as exc:
        logger.debug("tracectrl: pre_llm_call error: %s", exc)


def pre_api_request(**kwargs: Any) -> None:
    """Enrich the current agent turn span with request metadata."""
    try:
        session_id = kwargs.get("session_id", "unknown")
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        if state is None:
            return

        api_call_count = kwargs.get("api_call_count", 0)
        span = state.agent_spans.get(api_call_count)
        if span is None:
            return

        span.set_attribute("tracectrl.api_call_count", api_call_count)
        span.set_attribute("tracectrl.message_count", kwargs.get("message_count", 0))
        span.set_attribute("tracectrl.tool_count", kwargs.get("tool_count", 0))
        span.set_attribute("tracectrl.approx_input_tokens", kwargs.get("approx_input_tokens", 0))
        span.set_attribute("tracectrl.request_char_count", kwargs.get("request_char_count", 0))
    except Exception as exc:
        logger.debug("tracectrl: pre_api_request error: %s", exc)


def post_api_request(**kwargs: Any) -> None:
    """Close agent turn span + create tracectrl.model.usage span.

    Mirrors openclaw diagnostic model.usage event — emits a separate
    tracectrl.model.usage child span for each LLM API call with token usage,
    cost, and context window attributes.
    """
    try:
        session_id = kwargs.get("session_id", "unknown")
        model = kwargs.get("model", "unknown")
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        if state is None:
            return

        api_call_count = kwargs.get("api_call_count", 0)
        agent_span = state.agent_spans.get(api_call_count)

        usage = kwargs.get("usage") or {}
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0))
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0))
        cache_read = usage.get("cache_read_tokens", 0)
        cache_write = usage.get("cache_write_tokens", 0)
        total_tokens = usage.get("total_tokens", input_tokens + output_tokens)

        api_duration = kwargs.get("api_duration", 0.0)
        duration_ms = int(api_duration * 1000) if api_duration else 0

        # --- tracectrl.model.usage span (parity with openclaw diagnostic) ---
        model_usage_attrs = {
            "tracectrl.model": model,
            "tracectrl.provider": kwargs.get("provider", "unknown"),
            "tracectrl.channel": kwargs.get("platform", "unknown"),
            "tracectrl.session.key": session_id,
            "gen_ai.response.model": model,
            "gen_ai.system": kwargs.get("provider", "unknown"),
            "gen_ai.usage.input_tokens": input_tokens,
            "gen_ai.usage.output_tokens": output_tokens,
            "gen_ai.usage.total_tokens": total_tokens,
            "tracectrl.cost_usd": kwargs.get("cost_usd", 0.0),
            "tracectrl.context.limit": kwargs.get("context_window_limit", 0),
            "tracectrl.context.used": kwargs.get("context_window_used", 0),
        }
        if cache_read > 0:
            model_usage_attrs["gen_ai.usage.cache_read_tokens"] = cache_read
        if cache_write > 0:
            model_usage_attrs["gen_ai.usage.cache_write_tokens"] = cache_write
        if duration_ms > 0:
            model_usage_attrs["tracectrl.duration_ms"] = duration_ms

        model_span = tel.tracer.start_span(
            "tracectrl.model.usage",
            kind=SpanKind.INTERNAL,
            attributes=model_usage_attrs,
            context=state.root_ctx,
        )
        model_span.set_status(StatusCode.OK)
        model_span.end()
        state.model_usage_spans[api_call_count] = model_span

        # --- Enrich agent.turn span with usage ---
        if agent_span is not None:
            agent_span.set_attribute("gen_ai.usage.input_tokens", input_tokens)
            agent_span.set_attribute("gen_ai.usage.output_tokens", output_tokens)
            agent_span.set_attribute("gen_ai.usage.total_tokens", total_tokens)
            if cache_read > 0:
                agent_span.set_attribute("gen_ai.usage.cache_read_tokens", cache_read)
            if cache_write > 0:
                agent_span.set_attribute("gen_ai.usage.cache_write_tokens", cache_write)
            if duration_ms > 0:
                agent_span.set_attribute("tracectrl.duration_ms", duration_ms)
            finish_reason = kwargs.get("finish_reason", "")
            if finish_reason:
                agent_span.set_attribute("tracectrl.finish_reason", finish_reason)
            agent_span.set_status(StatusCode.OK)
            agent_span.end()
            state.agent_spans.pop(api_call_count, None)

        # --- Metrics ---
        if duration_ms > 0:
            tel.histograms.agent_turn_duration.record(duration_ms, {"tracectrl.model": model})

        token_attrs = {"tracectrl.model": model}
        tel.counters.tokens_prompt.add(input_tokens + cache_read + cache_write, token_attrs)
        tel.counters.tokens_completion.add(output_tokens, token_attrs)
        tel.counters.tokens_total.add(total_tokens, token_attrs)

        logger.debug(
            "tracectrl: api request done model=%s tokens=%d/%d",
            model, input_tokens, output_tokens,
        )
    except Exception as exc:
        logger.debug("tracectrl: post_api_request error: %s", exc)


def pre_tool_call(**kwargs: Any) -> None:
    """Create tracectrl.tool.{name} span + security analysis."""
    try:
        tool_name = kwargs.get("tool_name", "unknown")
        args = kwargs.get("args", {})
        session_id = kwargs.get("session_id", "unknown")
        tool_call_id = kwargs.get("tool_call_id", "")
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        parent_ctx = state.root_ctx if state else None

        span = tel.tracer.start_span(
            f"tracectrl.tool.{tool_name}",
            kind=SpanKind.INTERNAL,
            attributes={
                "tool.name": tool_name,
                "tracectrl.session.key": session_id,
                "tracectrl.tool.call_id": tool_call_id,
            },
            context=parent_ctx,
        )

        if state:
            state.tool_spans[tool_call_id or tool_name] = span

        args_str = _extract_args_str(args)
        if args_str:
            cfg = get_config()
            if cfg and cfg.capture_content:
                span.set_attribute("input.value", args_str)

        analyse_tool_call(tool_name, args_str, span, tel)

        tel.counters.tool_calls.add(1, {"tracectrl.tool.name": tool_name})
        logger.debug("tracectrl: tool call started tool=%s id=%s", tool_name, tool_call_id)
    except Exception as exc:
        logger.debug("tracectrl: pre_tool_call error: %s", exc)


def post_tool_call(**kwargs: Any) -> None:
    """Close tool span with result and duration."""
    try:
        tool_name = kwargs.get("tool_name", "unknown")
        session_id = kwargs.get("session_id", "unknown")
        tool_call_id = kwargs.get("tool_call_id", "")
        result = kwargs.get("result", "")
        duration_ms = kwargs.get("duration_ms", 0)
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        span_key = tool_call_id or tool_name
        span = state.tool_spans.pop(span_key, None) if state else None
        if span is None:
            return

        cfg = get_config()
        if cfg and cfg.capture_content:
            try:
                truncated = result[:2000] if result else ""
                span.set_attribute("output.value", truncated)
            except Exception:
                pass

        if duration_ms > 0:
            span.set_attribute("tracectrl.tool.duration_ms", duration_ms)
            tel.histograms.tool_duration.record(duration_ms, {"tracectrl.tool.name": tool_name})

        is_error = _has_error(result)
        if is_error:
            span.set_status(StatusCode.ERROR, "Tool returned error")
            span.set_attribute("tracectrl.error", "true")
            tel.counters.tool_errors.add(1, {"tracectrl.tool.name": tool_name})
        else:
            span.set_status(StatusCode.OK)

        span.end()
        logger.debug("tracectrl: tool call done tool=%s duration=%dms", tool_name, duration_ms)
    except Exception as exc:
        logger.debug("tracectrl: post_tool_call error: %s", exc)


def post_llm_call(**kwargs: Any) -> None:
    """Close root span. Mirrors agent_end hook + message.processed outcome."""
    try:
        session_id = kwargs.get("session_id", "unknown")
        tel = get_runtime()
        if tel is None:
            return

        state = get_state(session_id)
        if state is None:
            return

        for span in state.agent_spans.values():
            safe_end_span(span)
        state.agent_spans.clear()

        state.root_span.set_attribute(
            "tracectrl.message.outcome",
            kwargs.get("assistant_response", "") and "completed" or "no_response",
        )

        assistant_response = kwargs.get("assistant_response", "")
        if assistant_response:
            cfg = get_config()
            if cfg and cfg.capture_content:
                state.root_span.set_attribute(
                    "tracectrl.message.response_preview",
                    assistant_response[:500],
                )

        state.root_span.set_status(StatusCode.OK)
        state.root_span.end()
        del_state(session_id)

        tel.counters.messages_sent.add(1)
        logger.debug("tracectrl: turn completed sid=%s", session_id)
    except Exception as exc:
        logger.debug("tracectrl: post_llm_call error: %s", exc)


def on_session_end(**kwargs: Any) -> None:
    """Emit tracectrl.session.{action} span + cleanup.

    Mirrors openclaw command:new/reset/stop hook.
    """
    try:
        session_id = kwargs.get("session_id", "unknown")
        completed = kwargs.get("completed", True)
        interrupted = kwargs.get("interrupted", False)
        tel = get_runtime()

        if interrupted:
            action = "interrupted"
        elif not completed:
            action = "stopped"
        else:
            action = "end"

        if tel is not None:
            span = tel.tracer.start_span(
                f"tracectrl.session.{action}",
                kind=SpanKind.INTERNAL,
                attributes={
                    "tracectrl.session.action": action,
                    "tracectrl.session.key": session_id,
                },
            )
            span.set_status(
                StatusCode.ERROR if interrupted else StatusCode.OK,
            )
            span.end()

            tel.counters.session_resets.add(1)

        if interrupted or not completed:
            close_state(session_id, StatusCode.ERROR, "Session interrupted")
        else:
            close_state(session_id, StatusCode.OK)

        logger.debug(
            "tracectrl: session end sid=%s action=%s completed=%s interrupted=%s",
            session_id, action, completed, interrupted,
        )
    except Exception as exc:
        logger.debug("tracectrl: on_session_end error: %s", exc)


def on_session_finalize(**kwargs: Any) -> None:
    """Flush all pending spans."""
    try:
        tel = get_runtime()
        if tel is None:
            return

        with _STATE_LOCK:
            for key, state in list(_TRACE_STATES.items()):
                for span in state.tool_spans.values():
                    safe_end_span(span)
                for span in state.model_usage_spans.values():
                    safe_end_span(span)
                for span in state.agent_spans.values():
                    safe_end_span(span)
                safe_end_span(state.root_span)
            _TRACE_STATES.clear()

        try:
            if tel.tracer_provider and hasattr(tel.tracer_provider, "force_flush"):
                tel.tracer_provider.force_flush()
        except Exception:
            pass

        logger.debug("tracectrl: session finalized, flushed")
    except Exception as exc:
        logger.debug("tracectrl: on_session_finalize error: %s", exc)


def pre_approval_request(**kwargs: Any) -> None:
    """Create tracectrl.security.approval span."""
    try:
        tel = get_runtime()
        if tel is None:
            return

        command = kwargs.get("command", "")
        description = kwargs.get("description", "")
        session_key = kwargs.get("session_key", "unknown")

        span = tel.tracer.start_span(
            "tracectrl.security.approval",
            kind=SpanKind.INTERNAL,
            attributes={
                "tracectrl.security.category": "approval_required",
                "tracectrl.session.key": session_key,
                "tracectrl.security.command": command[:500],
                "tracectrl.security.description": description[:500],
            },
        )

        state_key = f"_approval:{session_key}:{threading.get_ident()}"
        with _STATE_LOCK:
            _TRACE_STATES[state_key] = TurnState(
                root_span=span,
                root_ctx=None,
            )

        tel.counters.security_events.add(1, {
            "tracectrl.security.max_severity": "medium",
        })
        logger.debug("tracectrl: approval requested command=%s", command[:100])
    except Exception as exc:
        logger.debug("tracectrl: pre_approval_request error: %s", exc)


def post_approval_response(**kwargs: Any) -> None:
    """Close approval span with choice."""
    try:
        tel = get_runtime()
        if tel is None:
            return

        session_key = kwargs.get("session_key", "unknown")
        choice = kwargs.get("choice", "unknown")

        state_key = f"_approval:{session_key}:{threading.get_ident()}"
        with _STATE_LOCK:
            state = _TRACE_STATES.pop(state_key, None)

        if state and state.root_span:
            state.root_span.set_attribute("tracectrl.approval.choice", choice)
            state.root_span.set_status(StatusCode.OK)
            state.root_span.end()

        logger.debug("tracectrl: approval response choice=%s", choice)
    except Exception as exc:
        logger.debug("tracectrl: post_approval_response error: %s", exc)


def on_gateway_error(**kwargs: Any) -> None:
    """Create tracectrl.webhook.error or tracectrl.session.stuck span.

    Mirrors openclaw-tracectrl diagnostic events:
      - error_source="platform"          -> tracectrl.webhook.error
      - error_source="inactivity_timeout" -> tracectrl.session.stuck
      - error_source="stuck_loop"         -> tracectrl.session.stuck
    """
    try:
        tel = get_runtime()
        if tel is None:
            return

        error_source = kwargs.get("error_source", "platform")
        error_type = kwargs.get("error_type", "UnknownError")
        error_message = kwargs.get("error_message", "")
        platform = kwargs.get("platform", "gateway")
        session_key = kwargs.get("session_key", "unknown")

        if error_source in ("inactivity_timeout", "stuck_loop"):
            span_name = "tracectrl.session.stuck"
        else:
            span_name = "tracectrl.webhook.error"

        attrs = {
            "tracectrl.session.key": session_key,
            "tracectrl.channel": platform,
            "tracectrl.error.type": error_type,
            "tracectrl.error.source": error_source,
            "tracectrl.error.message": error_message[:1000],
        }

        diagnostic = kwargs.get("diagnostic")
        if diagnostic and isinstance(diagnostic, dict):
            for dk, dv in diagnostic.items():
                attrs[f"tracectrl.diagnostic.{dk}"] = str(dv)

        if error_source in ("inactivity_timeout", "stuck_loop"):
            attrs["tracectrl.session.state"] = "stuck"
            if diagnostic and isinstance(diagnostic, dict):
                seconds = diagnostic.get("seconds_since_activity", 0)
                if seconds:
                    attrs["tracectrl.session.age_ms"] = int(float(seconds) * 1000)

        span = tel.tracer.start_span(
            span_name,
            kind=SpanKind.INTERNAL,
            attributes=attrs,
        )
        span.set_status(StatusCode.ERROR, error_message[:200])
        span.end()

        tel.counters.security_events.add(1, {
            "tracectrl.error.source": error_source,
            "tracectrl.error.type": error_type,
        })

        logger.debug(
            "tracectrl: gateway error source=%s type=%s session=%s",
            error_source, error_type, session_key,
        )
    except Exception as exc:
        logger.debug("tracectrl: on_gateway_error error: %s", exc)
