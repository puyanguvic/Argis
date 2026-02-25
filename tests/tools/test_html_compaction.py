from phish_email_detection_agent.tools.url_fetch.html_compaction import compact_html


def test_compact_html_extracts_visible_text_and_skips_script_style():
    html = """
    <html>
      <head>
        <title>Account Login</title>
        <style>.hidden{display:none}</style>
        <script>var secret = "should_not_appear";</script>
      </head>
      <body>
        <h1>Verify your account</h1>
        <p>Urgent: password reset required.</p>
      </body>
    </html>
    """
    result = compact_html(html)
    assert result["title"] == "Account Login"
    assert "Verify your account" in result["visible_text_sample"]
    assert "should_not_appear" not in result["visible_text_sample"]


def test_compact_html_extracts_form_and_meta_refresh_and_data_uri():
    html = """
    <html>
      <head>
        <meta http-equiv="refresh" content="0; url=https://evil.example/redirect">
      </head>
      <body>
        <form action="https://evil.example/login">
          <input type="password" name="pwd">
          <input name="otp_code">
        </form>
        <a href="https://evil.example/reset">reset</a>
        <img src="data:text/plain;base64,SGVsbG8=">
      </body>
    </html>
    """
    result = compact_html(html)
    features = result["features"]
    assert int(features["form_count"]) == 1
    assert int(features["password_fields"]) == 1
    assert int(features["otp_fields"]) >= 1
    assert result["meta_refresh"] is True
    assert any("evil.example" in item for item in result["outbound_links"])
    assert result["data_uri_reports"]
    assert result["data_uri_reports"][0]["status"] == "ok"

