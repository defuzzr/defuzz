"""Orchestrate the new-project flow (prompt parse, questionnaire, options, scaffolding) under one shared deadline.

A project is created only from an explicit template id or kit id. Without one the flow
returns status ``needs_choice`` with the template and kit matches attached (suggestions
only) and creates nothing.
"""

from __future__ import annotations

import copy
import inspect
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import componentize_bridge
from .kit_scaffold import (
    KitProposal,
    KitUnavailable,
    accept_kit,
    discard_kit,
    propose_kit,
)
from .matcher import (
    KitInfo,
    KitMatch,
    Match,
    best_matches,
    match_kits,
    parse_kit_list,
)
from .prompt_parse import (
    ParsedPrompt,
    PromptChip,
    explicit_code_from,
    merge_parsed_answers,
    parse_prompt,
)
from .questionnaire import (
    Question,
    QuestionnaireTimeout,
    _call_with_budget,
    run_questionnaire,
)
from .scaffolder import (
    AcceptResult,
    Proposal,
    ScaffoldError,
    ScaffoldTimeout,
    accept,
    default_project_create,
    discard,
    propose,
)
from .templates import (
    TemplateError,
    TemplateSpec,
    load_templates,
    templates_root as default_templates_root,
)

VALID_FLOW_STATUSES: frozenset[str] = frozenset(
    {"created", "needs_choice", "no_match", "timeout", "declined", "error"}
)


@dataclass
class FlowResult:
    """Outcome of a single run_new_project_flow invocation."""

    status: str
    matches: List[Match] = field(default_factory=list)
    proposal: Optional[Proposal] = None
    accept: Optional[AcceptResult] = None
    message: str = ""
    output: str = ""
    parsed_prompt: Optional[ParsedPrompt] = None
    chips: List[PromptChip] = field(default_factory=list)
    options: Dict[str, str] = field(default_factory=dict)
    catalog: str = ""
    kit_matches: List[KitMatch] = field(default_factory=list)
    kit_proposal: Optional[KitProposal] = None
    kits_notice: str = ""


def _default_ask(_q: Question, prefill_vals: List[str]) -> Optional[Any]:
    return prefill_vals[0] if prefill_vals else None


def _invoke_decision_callback(
    fn: Callable[..., Any],
    *args: Any,
    remaining_fn: Callable[[], float],
    wait_msg: str,
    before_msg: Optional[str] = None,
) -> Tuple[Any, Optional[str]]:
    """Run a side-effect-free decision callback within the remaining deadline."""
    rem = remaining_fn()
    if rem <= 0:
        return None, before_msg or wait_msg
    try:
        val = _call_with_budget(
            fn,
            *args,
            budget_s=rem,
            timeout_exc_factory=lambda: QuestionnaireTimeout(wait_msg),
        )
    except QuestionnaireTimeout as exc:
        return None, str(exc)
    if val is None or remaining_fn() <= 0:
        return None, wait_msg
    return val, None


def _accepts_timeout(fn: Any) -> bool:
    try:
        params = inspect.signature(fn).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(
        p.kind == inspect.Parameter.VAR_KEYWORD or p.name == "timeout"
        for p in params
    )


def _load_kit_catalog(
    kits: Optional[Sequence[Any]],
    eff_bridge: Any,
    *,
    timeout: Optional[float] = None,
) -> Tuple[List[KitInfo], str, bool]:
    """Load KitInfo entries from an explicit sequence or via eff_bridge.kit_list()."""
    if kits is not None:
        infos, _, _ = parse_kit_list({"status": "ok", "data": {"kits": kits}})
        return infos, "", False

    if timeout is not None and _accepts_timeout(eff_bridge.kit_list):
        res = eff_bridge.kit_list(timeout=timeout)
    else:
        res = eff_bridge.kit_list()
    infos, notice, status = parse_kit_list(res)
    return infos, notice, status != "ok"


def _clean_kits_notice(notice: str) -> str:
    return (notice.strip() or componentize_bridge.UNAVAILABLE_NOTICE).rstrip(".")


def _format_kits_unavailable_message(notice: str) -> str:
    return (
        f"Project kits are unavailable: {_clean_kits_notice(notice)}. "
        "Install and enable the componentize plugin to create this kind of project."
    )


def _confirm_proposal(
    confirm_cb: Optional[Callable[[Any], Optional[bool]]],
    prop: Any,
    discard_fn: Callable[[Any], None],
    remaining_fn: Callable[[], float],
) -> Tuple[Optional[float], Optional[Tuple[str, str]]]:
    """Confirm a detached proposal and discard staging on any pre-accept failure."""
    if confirm_cb is None:
        discard_fn(prop)
        return None, ("timeout", "New-project flow timed out waiting for confirmation")

    try:
        decision, err_msg = _invoke_decision_callback(
            confirm_cb,
            copy.deepcopy(prop),
            remaining_fn=remaining_fn,
            before_msg="New-project flow timed out after staging proposal",
            wait_msg="New-project flow timed out waiting for confirmation",
        )
    except BaseException:
        discard_fn(prop)
        raise

    if err_msg is not None:
        discard_fn(prop)
        return None, ("timeout", err_msg)
    if not decision:
        discard_fn(prop)
        return None, ("declined", "Scaffold proposal declined; staging removed.")

    rem = remaining_fn()
    if rem <= 0:
        discard_fn(prop)
        return None, ("timeout", "New-project flow timed out before accepting proposal")
    return rem, None


def run_new_project_flow(
    *,
    ask: Optional[Callable[[Question, List[str]], Optional[Any]]] = None,
    confirm: Optional[Callable[[Any], Optional[bool]]] = None,
    name_provider: Optional[Callable[[], Optional[str]]] = None,
    templates: Optional[Sequence[TemplateSpec]] = None,
    templates_root: Optional[os.PathLike[str] | str] = None,
    register: Optional[Callable[[str, str], str]] = None,
    timeout_s: float = 300.0,
    db_path: Optional[Path | str] = None,
    dest_root: Optional[os.PathLike[str] | str] = None,
    staging_parent: Optional[os.PathLike[str] | str] = None,
    initial_answers: Optional[Mapping[str, Any]] = None,
    clock: Optional[Callable[[], float]] = None,
    prompt: Optional[str] = None,
    options: Optional[Mapping[str, str]] = None,
    choose_options: Optional[
        Callable[[TemplateSpec, Dict[str, str]], Optional[Mapping[str, str]]]
    ] = None,
    cancel: Any = None,
    kits: Optional[Sequence[KitInfo]] = None,
    kit_bridge: Optional[Any] = None,
    kit_id: Optional[str] = None,
    confirm_kit: Optional[Callable[[KitProposal], Optional[bool]]] = None,
    template_id: Optional[str] = None,
) -> FlowResult:
    """Create the project named by ``template_id`` or ``kit_id`` under one shared deadline.

    With an id: (optional prompt parse for name and answers) -> questionnaire -> options ->
    propose -> confirm -> accept. Without one: nothing is asked, staged or written; the
    result has status ``needs_choice``, an empty message, and the template and kit matches
    for the prompt/answers so a caller can mark suggestions.

    Decision callbacks (`ask`, `name_provider`, `choose_options`, `confirm`, `confirm_kit`) must
    follow the 'return data only, no side effects' contract.
    """
    from .catalog_list import coming_soon_message

    for kind, ident in (("kit", kit_id), ("template", template_id)):
        refusal = coming_soon_message(kind, ident)
        if refusal:
            return FlowResult(status="error", message=refusal)
    now_fn = clock if clock is not None else time.monotonic
    if timeout_s <= 0:
        return FlowResult(status="timeout", message="Flow timeout_s must be positive")
    if template_id and kit_id:
        return FlowResult(status="error", message="Specify only one of template_id or kit_id")

    deadline = now_fn() + float(timeout_s)
    remaining_fn = lambda: deadline - now_fn()
    eff_bridge = kit_bridge if kit_bridge is not None else componentize_bridge

    t_root = Path(templates_root) if templates_root is not None else default_templates_root()
    if kit_id is None:
        try:
            loaded_templates = list(templates) if templates is not None else load_templates(t_root)
        except TemplateError as exc:
            return FlowResult(status="error", message=str(exc))
    else:
        loaded_templates = list(templates) if templates is not None else []

    chosen_template: Optional[TemplateSpec] = None
    if template_id:
        chosen_template = next((t for t in loaded_templates if t.id == template_id), None)
        if chosen_template is None:
            return FlowResult(status="error", message=f"Template not found: {template_id}")

    parsed_prompt_obj: Optional[ParsedPrompt] = None
    chips_list: List[PromptChip] = []
    merged_initial: Dict[str, Any] = dict(initial_answers) if initial_answers else {}
    kit_matches_list: List[KitMatch] = []
    kits_notice_str: str = ""
    matches: List[Match] = []

    def _flow_result(
        status: str,
        message: str = "",
        *,
        matches_val: Optional[List[Match]] = None,
        proposal_val: Optional[Proposal] = None,
        accept_val: Optional[AcceptResult] = None,
        options_val: Optional[Mapping[str, str]] = None,
        output_val: str = "",
        catalog_val: str = "",
        kit_proposal_val: Optional[KitProposal] = None,
        kits_notice_val: Optional[str] = None,
    ) -> FlowResult:
        return FlowResult(
            status=status,
            matches=list(matches_val) if matches_val is not None else [],
            proposal=proposal_val,
            accept=accept_val,
            parsed_prompt=parsed_prompt_obj,
            chips=chips_list,
            options=dict(options_val) if options_val is not None else {},
            message=message,
            output=output_val,
            catalog=catalog_val,
            kit_matches=list(kit_matches_list),
            kit_proposal=kit_proposal_val,
            kits_notice=kits_notice_str if kits_notice_val is None else kits_notice_val,
        )

    def _kit_unavailable_result(
        exc: BaseException,
        *,
        kit_proposal_val: Optional[KitProposal] = None,
    ) -> FlowResult:
        notice_str = str(exc).strip() or kits_notice_str or componentize_bridge.UNAVAILABLE_NOTICE
        return _flow_result(
            "no_match",
            _format_kits_unavailable_message(notice_str),
            matches_val=matches,
            catalog_val="kit",
            kit_proposal_val=kit_proposal_val,
            kits_notice_val=kits_notice_str or notice_str,
        )

    def _confirm_and_check_pre_accept(
        confirm_cb: Optional[Callable[[Any], Optional[bool]]],
        prop: Any,
        discard_fn: Callable[[Any], None],
        *,
        catalog_val: str,
        proposal_val: Optional[Proposal] = None,
        kit_proposal_val: Optional[KitProposal] = None,
        options_val: Optional[Mapping[str, str]] = None,
    ) -> Tuple[Optional[float], Optional[FlowResult]]:
        rem, failure = _confirm_proposal(confirm_cb, prop, discard_fn, remaining_fn)
        if failure is None:
            return rem, None
        status, message = failure
        return None, _flow_result(
            status,
            message,
            matches_val=matches,
            proposal_val=proposal_val,
            options_val=options_val,
            catalog_val=catalog_val,
            kit_proposal_val=kit_proposal_val,
        )

    if prompt is not None and str(prompt).strip():
        rem = remaining_fn()
        if rem <= 0:
            return _flow_result("timeout", "New-project flow timed out before parsing prompt")
        try:
            parsed_prompt_obj = parse_prompt(str(prompt))
        except Exception as exc:
            return _flow_result("error", str(exc))
        chips_list = list(parsed_prompt_obj.chips)
        merged_initial = merge_parsed_answers(parsed_prompt_obj, merged_initial)

    if chosen_template is None and kit_id is None:
        # No id: compute suggestions only. The caller shows the list and asks for a choice.
        if parsed_prompt_obj is not None and parsed_prompt_obj.not_a_project_request:
            return _flow_result("needs_choice")
        prompt_text = str(prompt) if prompt is not None else ""
        matches = best_matches(
            [s for s in loaded_templates if not coming_soon_message("template", s.id)],
            merged_initial,
            prompt=prompt_text or None,
            explicit_code=explicit_code_from(parsed_prompt_obj, initial_answers),
        )
        rem = remaining_fn()
        if rem <= 0:
            return _flow_result("timeout", "New-project flow timed out before kit matching")
        loaded_kits, kits_notice_str, _unavailable = _load_kit_catalog(kits, eff_bridge, timeout=rem)
        if remaining_fn() <= 0:
            return _flow_result("timeout", "New-project flow timed out during kit matching")
        kit_matches_list = match_kits([k for k in loaded_kits if not coming_soon_message("kit", k.id)], prompt_text, merged_initial)
        return _flow_result("needs_choice", matches_val=matches)

    rem = remaining_fn()
    if rem <= 0:
        return _flow_result("timeout", "New-project flow timed out before questionnaire")

    if kit_id is not None and ask is None and "building" not in merged_initial:
        answers: Dict[str, Any] = dict(merged_initial)
    else:
        try:
            answers = run_questionnaire(
                ask if ask is not None else _default_ask,
                timeout_s=rem,
                initial_answers=merged_initial,
                clock=now_fn,
            )
        except QuestionnaireTimeout as exc:
            return _flow_result("timeout", str(exc))
        except ValueError as exc:
            return _flow_result("error", str(exc))

    if remaining_fn() <= 0:
        return _flow_result("timeout", "New-project flow timed out after questionnaire")

    eff_name_provider = name_provider
    if eff_name_provider is None and parsed_prompt_obj is not None:
        parsed_name = parsed_prompt_obj.name
        eff_name_provider = lambda: parsed_name

    if kit_id is not None:
        chosen_kit_id = str(kit_id)
        if eff_name_provider is None:
            return _flow_result(
                "timeout",
                "New-project flow timed out waiting for project name",
                matches_val=matches,
                catalog_val="kit",
            )

        project_name, err_msg = _invoke_decision_callback(
            eff_name_provider,
            remaining_fn=remaining_fn,
            wait_msg="New-project flow timed out waiting for project name",
        )
        if err_msg is not None or not str(project_name).strip():
            return _flow_result(
                "timeout",
                err_msg or "New-project flow timed out waiting for project name",
                matches_val=matches,
                catalog_val="kit",
            )

        rem = remaining_fn()
        if rem <= 0:
            return _flow_result(
                "timeout",
                "New-project flow timed out before staging proposal",
                matches_val=matches,
                catalog_val="kit",
            )
        kit_vars = dict(options) if options else None
        try:
            kit_prop = propose_kit(
                chosen_kit_id,
                str(project_name),
                answers,
                dest_root=dest_root,
                staging_parent=staging_parent,
                variables=kit_vars,
                bridge=eff_bridge,
                timeout_s=rem,
                clock=now_fn,
            )
        except ScaffoldTimeout as exc:
            return _flow_result(
                "timeout",
                str(exc),
                matches_val=matches,
                catalog_val="kit",
            )
        except KitUnavailable as exc:
            return _kit_unavailable_result(exc)
        except ScaffoldError as exc:
            return _flow_result(
                "error",
                str(exc),
                matches_val=matches,
                catalog_val="kit",
            )

        eff_confirm_kit = confirm_kit if confirm_kit is not None else confirm
        rem_accept, early_res = _confirm_and_check_pre_accept(
            eff_confirm_kit,
            kit_prop,
            discard_kit,
            catalog_val="kit",
            kit_proposal_val=kit_prop,
        )
        if early_res is not None:
            return early_res
        assert rem_accept is not None

        reg_fn = register if register is not None else default_project_create
        accept_ok = False
        keep_staging = False
        try:
            try:
                accept_res = accept_kit(
                    kit_prop,
                    register=reg_fn,
                    db_path=db_path,
                    timeout_s=rem_accept,
                    clock=now_fn,
                    cancel=cancel,
                    bridge=eff_bridge,
                )
                accept_ok = True
            except ScaffoldTimeout as exc:
                keep_staging = bool(getattr(exc, "keep_staging", False))
                return _flow_result(
                    "timeout",
                    str(exc),
                    matches_val=matches,
                    catalog_val="kit",
                    kit_proposal_val=kit_prop,
                    output_val=getattr(exc, "output", ""),
                )
            except KitUnavailable as exc:
                keep_staging = bool(getattr(exc, "keep_staging", False))
                return _kit_unavailable_result(exc, kit_proposal_val=kit_prop)
            except Exception as exc:
                keep_staging = bool(getattr(exc, "keep_staging", False))
                return _flow_result(
                    "error",
                    str(exc),
                    matches_val=matches,
                    catalog_val="kit",
                    kit_proposal_val=kit_prop,
                    output_val=getattr(exc, "output", ""),
                )
        finally:
            if not accept_ok and not keep_staging:
                discard_kit(kit_prop)

        from .desktop_registration import failure_notice

        created_paths = ", ".join(r["path"] for r in accept_res.repos)
        notices = [
            failure_notice(repo)
            for repo in accept_res.repos
            if repo.get("registration") == "failed"
        ]
        return _flow_result(
            "created",
            "\n".join([f"Created: {created_paths}", *notices]),
            matches_val=matches,
            catalog_val="kit",
            kit_proposal_val=kit_prop,
            accept_val=accept_res,
        )

    assert chosen_template is not None
    if eff_name_provider is None:
        return _flow_result(
            "timeout",
            "New-project flow timed out waiting for project name",
            matches_val=matches,
            catalog_val="template",
        )

    project_name, err_msg = _invoke_decision_callback(
        eff_name_provider,
        remaining_fn=remaining_fn,
        wait_msg="New-project flow timed out waiting for project name",
    )
    if err_msg is not None or not str(project_name).strip():
        return _flow_result(
            "timeout",
            err_msg or "New-project flow timed out waiting for project name",
            matches_val=matches,
            catalog_val="template",
        )

    selected_options: Optional[Mapping[str, str]] = options
    if choose_options is not None and chosen_template.options:
        default_opts = {
            opt_id: opt_spec.default for opt_id, opt_spec in chosen_template.options.items()
        }
        if selected_options:
            default_opts.update(selected_options)
        chosen_opts, err_msg = _invoke_decision_callback(
            choose_options,
            chosen_template,
            default_opts,
            remaining_fn=remaining_fn,
            before_msg="New-project flow timed out before template options choice",
            wait_msg="New-project flow timed out waiting for template options",
        )
        if err_msg is not None:
            return _flow_result("timeout", err_msg, matches_val=matches, catalog_val="template")
        selected_options = dict(chosen_opts)

    try:
        proposal = propose(
            chosen_template,
            str(project_name),
            answers,
            dest_root=dest_root,
            staging_parent=staging_parent,
            options=selected_options,
            db_path=db_path,
        )
    except ScaffoldError as exc:
        return _flow_result("error", str(exc), matches_val=matches, catalog_val="template")

    rem_accept, early_res = _confirm_and_check_pre_accept(
        confirm,
        proposal,
        discard,
        catalog_val="template",
        proposal_val=proposal,
        options_val=proposal.options,
    )
    if early_res is not None:
        return early_res
    assert rem_accept is not None

    reg_fn = register if register is not None else default_project_create
    accept_ok = False
    keep_staging = False
    try:
        try:
            accept_res = accept(
                proposal,
                register=reg_fn,
                db_path=db_path,
                timeout_s=rem_accept,
                clock=now_fn,
                options=selected_options,
                cancel=cancel,
            )
            accept_ok = True
        except ScaffoldTimeout as exc:
            keep_staging = bool(getattr(exc, "keep_staging", False))
            return _flow_result(
                "timeout",
                str(exc),
                matches_val=matches,
                proposal_val=proposal,
                options_val=proposal.options,
                output_val=getattr(exc, "output", ""),
                catalog_val="template",
            )
        except Exception as exc:
            keep_staging = bool(getattr(exc, "keep_staging", False))
            return _flow_result(
                "error",
                str(exc),
                matches_val=matches,
                proposal_val=proposal,
                options_val=proposal.options,
                output_val=getattr(exc, "output", ""),
                catalog_val="template",
            )
    finally:
        if not accept_ok and not keep_staging:
            discard(proposal)

    from .desktop_registration import failure_notice

    created_paths = ", ".join(r["path"] for r in accept_res.repos)
    notices = [failure_notice(repo) for repo in accept_res.repos if repo.get("registration") == "failed"]
    return _flow_result(
        "created",
        "\n".join([f"Created: {created_paths}", *notices]),
        matches_val=matches,
        proposal_val=proposal,
        accept_val=accept_res,
        options_val=accept_res.options,
        catalog_val="template",
    )
