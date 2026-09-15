"""Tests for scan_toolkit.models — round-trip, enums, JSON cols, to_dict, cascade."""

from datetime import date

from scan_toolkit.models import (
    AttackChain,
    Confidence,
    Engagement,
    EngagementStatus,
    Finding,
    FindingStatus,
    Platform,
    Severity,
    SourceAgent,
)


# --- Engagement round-trip ---

def test_engagement_round_trip(db_session):
    eng = Engagement(
        client_name="Acme Corp",
        scope_notes="Android APK only",
        app_platform=Platform.android,
        app_version="2.1.0",
        build_type="release",
        start_date=date(2025, 6, 15),
        status=EngagementStatus.intake,
    )
    db_session.add(eng)
    db_session.flush()

    loaded = db_session.get(Engagement, eng.id)
    assert loaded is not None
    assert loaded.client_name == "Acme Corp"
    assert loaded.app_platform == Platform.android
    assert loaded.start_date == date(2025, 6, 15)
    assert loaded.status == EngagementStatus.intake


# --- Finding round-trip + enum persistence ---

def test_finding_round_trip(db_session):
    eng = Engagement(client_name="Test")
    db_session.add(eng)
    db_session.flush()

    finding = Finding(
        engagement_id=eng.id,
        source_agent=SourceAgent.static,
        category="insecure_storage",
        cwe_id="CWE-312",
        title="Plaintext credentials in SharedPreferences",
        description="Credentials stored in plaintext.",
        severity=Severity.high,
        confidence=Confidence.high,
        affected_component="com.example.app/SharedPrefs",
        remediation_suggestion="Use EncryptedSharedPreferences.",
        status=FindingStatus.new,
        related_finding_ids=["f4k3id0001", "f4k3id0002"],
    )
    db_session.add(finding)
    db_session.flush()

    loaded = db_session.get(Finding, finding.id)
    assert loaded.source_agent == SourceAgent.static
    assert loaded.severity == Severity.high
    assert loaded.confidence == Confidence.high
    assert loaded.status == FindingStatus.new
    assert loaded.related_finding_ids == ["f4k3id0001", "f4k3id0002"]


# --- AttackChain round-trip ---

def test_attack_chain_round_trip(db_session):
    eng = Engagement(client_name="ChainTest")
    db_session.add(eng)
    db_session.flush()

    f1 = Finding(engagement_id=eng.id, source_agent=SourceAgent.static,
                 title="F1", severity=Severity.medium, confidence=Confidence.high)
    f2 = Finding(engagement_id=eng.id, source_agent=SourceAgent.sca,
                 title="F2", severity=Severity.low, confidence=Confidence.medium)
    db_session.add_all([f1, f2])
    db_session.flush()

    chain = AttackChain(
        engagement_id=eng.id,
        finding_ids=[f1.id, f2.id],
        narrative="User uploads file → stored unencrypted → downloaded by attacker.",
        combined_severity=Severity.high,
    )
    db_session.add(chain)
    db_session.flush()

    loaded = db_session.get(AttackChain, chain.id)
    assert loaded.finding_ids == [f1.id, f2.id]
    assert loaded.combined_severity == Severity.high


# --- to_dict key sets match schemas exactly ---

ENGAGEMENT_KEYS = {"id", "client_name", "scope_notes", "app_platform", "app_version",
                   "build_type", "start_date", "status"}

FINDING_KEYS = {"id", "engagement_id", "source_agent", "category", "cwe_id", "title",
                "description", "evidence", "severity", "confidence", "affected_component",
                "remediation_suggestion", "status", "related_finding_ids"}

ATTACK_CHAIN_KEYS = {"id", "engagement_id", "finding_ids", "narrative", "combined_severity"}


def test_to_dict_engagement(db_session):
    eng = Engagement(client_name="DictTest")
    db_session.add(eng)
    db_session.flush()
    d = eng.to_dict()
    assert set(d.keys()) == ENGAGEMENT_KEYS
    assert d["status"] == "intake"
    assert d["start_date"] is None  # unset


def test_to_dict_finding(db_session):
    eng = Engagement(client_name="x")
    db_session.add(eng)
    db_session.flush()
    f = Finding(engagement_id=eng.id, source_agent=SourceAgent.api, title="T",
                severity=Severity.critical, confidence=Confidence.medium)
    db_session.add(f)
    db_session.flush()
    d = f.to_dict()
    assert set(d.keys()) == FINDING_KEYS
    assert d["severity"] == "critical"
    assert d["related_finding_ids"] == []


def test_to_dict_attack_chain(db_session):
    eng = Engagement(client_name="x")
    db_session.add(eng)
    db_session.flush()
    chain = AttackChain(engagement_id=eng.id, finding_ids=["a1", "a2"],
                        narrative="N", combined_severity=Severity.low)
    db_session.add(chain)
    db_session.flush()
    d = chain.to_dict()
    assert set(d.keys()) == ATTACK_CHAIN_KEYS
    assert d["finding_ids"] == ["a1", "a2"]


# --- Cascade delete ---

def test_cascade_delete_engagement(db_session):
    eng = Engagement(client_name="CascadeTest")
    db_session.add(eng)
    db_session.flush()

    f = Finding(engagement_id=eng.id, source_agent=SourceAgent.sca,
                title="F", severity=Severity.info, confidence=Confidence.low)
    chain = AttackChain(engagement_id=eng.id, finding_ids=[], narrative="N",
                        combined_severity=Severity.info)
    db_session.add_all([f, chain])
    db_session.flush()

    eng_id = eng.id
    db_session.delete(eng)
    db_session.flush()

    assert db_session.get(Engagement, eng_id) is None
    assert db_session.get(Finding, f.id) is None
    assert db_session.get(AttackChain, chain.id) is None