"""ManifestDeviationOracle testleri -- ajan akisinin beyan edilen mimariden sapmasini denetler."""
from pentestai.agent.manifest_deviation import ManifestDeviationOracle
from pentestai.models.agent import AgentTrace, DeclaredManifest, ToolCall


def _call(name: str, step: int = 1) -> ToolCall:
    return ToolCall(name=name, arguments={}, ok=True, step=step)


def test_no_manifest_inconclusive():
    oracle = ManifestDeviationOracle()
    trace = AgentTrace(tool_calls=[_call("http.get")])
    finding = oracle.run(trace, finding_id="f1", manifest=None)
    assert finding.verdict == "INCONCLUSIVE"


def test_empty_manifest_inconclusive():
    oracle = ManifestDeviationOracle()
    trace = AgentTrace(tool_calls=[_call("http.get")])
    manifest = DeclaredManifest(allowed_tools=())
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "INCONCLUSIVE"


def test_empty_trace_inconclusive():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(allowed_tools=("http.get",))
    trace = AgentTrace(tool_calls=[])
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "INCONCLUSIVE"


def test_all_compliant_rejected():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(allowed_tools=("http.get", "fs.read"))
    trace = AgentTrace(tool_calls=[_call("http.get"), _call("fs.read", step=2)])
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "REJECTED"


def test_deviation_with_compliant_confirmed():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(allowed_tools=("http.get",))
    trace = AgentTrace(
        tool_calls=[_call("http.get"), _call("email.send", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "CONFIRMED"


def test_all_deviant_no_negative_control_inconclusive():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(allowed_tools=("http.get",))
    trace = AgentTrace(
        tool_calls=[_call("email.send"), _call("fs.delete", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "INCONCLUSIVE"


def test_transition_deviation_confirmed():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(
        allowed_tools=("http.get", "fs.read"),
        allowed_transitions=(("http.get", "fs.read"),),
    )
    trace = AgentTrace(
        tool_calls=[_call("fs.read"), _call("http.get", step=2)]
    )
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "CONFIRMED"


def test_failed_calls_ignored():
    oracle = ManifestDeviationOracle()
    manifest = DeclaredManifest(allowed_tools=("http.get",))
    failed = ToolCall(name="email.send", arguments={}, ok=False, step=1)
    trace = AgentTrace(tool_calls=[failed])
    finding = oracle.run(trace, finding_id="f1", manifest=manifest)
    assert finding.verdict == "INCONCLUSIVE"


def test_vuln_type():
    oracle = ManifestDeviationOracle()
    assert oracle.vuln_type == "manifest_deviation"
