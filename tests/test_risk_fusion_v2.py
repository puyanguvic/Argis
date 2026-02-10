from phish_email_detection_agent.agents.risk_fusion import fuse_risk_scores


def test_fusion_phishing_when_multisignal_strong():
    result = fuse_risk_scores(
        text_score=50,
        url_score=70,
        domain_score=40,
        attachment_score=80,
        ocr_score=20,
    )
    assert result["verdict"] == "phishing"
    assert result["risk_score"] >= 35


def test_fusion_benign_when_all_low():
    result = fuse_risk_scores(
        text_score=10,
        url_score=0,
        domain_score=5,
        attachment_score=8,
        ocr_score=0,
    )
    assert result["verdict"] == "benign"
    assert result["risk_score"] < 35
