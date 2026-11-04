
from src.llm import agent


def test_investigate_email_returns_fallback_when_all_models_fail(monkeypatch):

    calls = []

    class FakeModels:
        def generate_content(self, model, contents):
            calls.append(model)
            raise Exception("503 UNAVAILABLE")

    class FakeClient:
        models = FakeModels()

    monkeypatch.setattr(agent, "client", FakeClient())

    result = agent.investigate_email(
        sender_result={},
        url_results=[],
        content_result={},
        attachment_result={},
        header_result={},
        risk={},
        email={}
    )

    assert "AI Investigation Temporarily Unavailable" in result
    assert "deterministic email analysis completed successfully" in result
    assert len(calls) == len(agent.MODELS)
    assert calls == agent.MODELS
