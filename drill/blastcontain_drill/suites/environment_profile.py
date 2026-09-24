"""Generic API 3 simulation contract; no framework imports or names in the host."""

from ..contracts import ContractError
from ..plugins.catalog import check_profile


def validate_scenario(scenario, capabilities, strategy=None):
    if (
        strategy is not None
        or scenario.turns
        or len(scenario.fixture_refs) != 1
        or scenario.task_checks != ("utility",)
        or scenario.security.goal != "state_violation"
        or not scenario.legitimate_task
        or len(scenario.injections) > 1
        or any(i.surface != "document" or not i.payload for i in scenario.injections)
    ):
        raise ContractError(
            "Stateful environment requires one fixture, utility check and document-only static input"
        )
    if "fixture." + scenario.fixture_refs[0] not in capabilities:
        raise ContractError("Environment does not support the selected fixture")
    if not {
        "environment.stateful.v1",
        "task.utility",
        "observe.model_output",
        "observe.tool_actions",
        "observe.payload_delivery",
    } <= set(capabilities):
        raise ContractError("Environment lacks required state, task or observation capabilities")


def validate_environment(spec, case, plugins):
    manifest = next((p for p in plugins if p.id == spec.environment), None)
    if (
        manifest is None
        or manifest.adapter_api != 3
        or spec.target.kind != "agent"
        or spec.target.binding != "builtin.target.llm"
        or spec.evaluators != (spec.environment,)
        or case.scenario is None
    ):
        raise ContractError("Unsupported stateful environment binding")
    check_profile(manifest)
    validate_scenario(case.scenario, manifest.capabilities, case.strategy)
    return manifest
