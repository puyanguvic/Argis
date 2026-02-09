from my_agent_app.tools.debug import runtime_info
from my_agent_app.tools.text import contains_phishing_keywords, normalize_text

text = "  urgent   password reset required now  "
print(normalize_text(text))
print(contains_phishing_keywords(text))
print(runtime_info())
