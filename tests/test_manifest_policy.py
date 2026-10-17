"""ManifestPolicy -- tool-call'un beyan edilen mimariye uygunlugunu denetler."""
from pentestai.models.agent import DeclaredManifest, ToolCall
from pentestai.policy.authorize import Allow, Deny
from pentestai.policy.manifest import ManifestPolicy


def _call(name: str, step: int = 1) -> ToolCall:
    return ToolCall(name=name, arguments={}, ok=True, step=step)


def _manifest(
    tools: tuple[str, ...] = (),
    transitions: tuple[tuple[str, str], ...] = (),
) -> DeclaredManifest:
    return DeclaredManifest(allowed_tools=tools, allowed_transitions=transitions)


def test_declared_tool_allowed():
    policy = ManifestPolicy()
    call = _call("http.get")
    manifest = _manifest(tools=("http.get", "fs.read"))
    decision = policy.authorize(call, manifest)
    assert isinstance(decision, Allow)


def test_undeclared_tool_denied():
    policy = ManifestPolicy()
    call = _call("email.send")
    manifest = _manifest(tools=("http.get", "fs.read"))
    decision = policy.authorize(call, manifest)
    assert isinstance(decision, Deny)
    assert "undeclared tool" in decision.reason


def test_prefix_match_allowed():
    policy = ManifestPolicy()
    call = _call("http.get")
    manifest = _manifest(tools=("http",))
    decision = policy.authorize(call, manifest)
    assert isinstance(decision, Allow)


def test_case_insensitive_match():
    policy = ManifestPolicy()
    call = _call("HTTP.GET")
    manifest = _manifest(tools=("http.get",))
    decision = policy.authorize(call, manifest)
    assert isinstance(decision, Allow)


def test_no_prior_skips_transition_check():
    policy = ManifestPolicy()
    call = _call("http.get")
    manifest = _manifest(
        tools=("http.get", "fs.read"),
        transitions=(("fs.read", "http.get"),),
    )
    decision = policy.authorize(call, manifest, prior=None)
    assert isinstance(decision, Allow)


def test_no_transitions_in_manifest_skips_check():
    policy = ManifestPolicy()
    prior = _call("fs.read", step=1)
    call = _call("http.get", step=2)
    manifest = _manifest(tools=("http.get", "fs.read"), transitions=())
    decision = policy.authorize(call, manifest, prior=prior)
    assert isinstance(decision, Allow)


def test_declared_transition_allowed():
    policy = ManifestPolicy()
    prior = _call("fs.read", step=1)
    call = _call("http.get", step=2)
    manifest = _manifest(
        tools=("http.get", "fs.read"),
        transitions=(("fs.read", "http.get"),),
    )
    decision = policy.authorize(call, manifest, prior=prior)
    assert isinstance(decision, Allow)


def test_undeclared_transition_denied():
    policy = ManifestPolicy()
    prior = _call("http.get", step=1)
    call = _call("email.send", step=2)
    manifest = _manifest(
        tools=("http.get", "email.send"),
        transitions=(("http.get", "fs.read"),),
    )
    decision = policy.authorize(call, manifest, prior=prior)
    assert isinstance(decision, Deny)
    assert "undeclared transition" in decision.reason


def test_undeclared_tool_takes_priority_over_transition():
    policy = ManifestPolicy()
    prior = _call("http.get", step=1)
    call = _call("malicious.tool", step=2)
    manifest = _manifest(
        tools=("http.get", "fs.read"),
        transitions=(("http.get", "fs.read"),),
    )
    decision = policy.authorize(call, manifest, prior=prior)
    assert isinstance(decision, Deny)
    assert "undeclared tool" in decision.reason


def test_transition_prefix_match():
    policy = ManifestPolicy()
    prior = _call("fs.read", step=1)
    call = _call("http.get", step=2)
    manifest = _manifest(
        tools=("http", "fs"),
        transitions=(("fs", "http"),),
    )
    decision = policy.authorize(call, manifest, prior=prior)
    assert isinstance(decision, Allow)
