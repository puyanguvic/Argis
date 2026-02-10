"""Attachment domain typing and extraction."""

from phish_email_detection_agent.domain.attachment.detect import classify_attachment
from phish_email_detection_agent.domain.attachment.extract import extract_attachment_urls
from phish_email_detection_agent.domain.attachment.models import AttachmentArtifact

__all__ = ["AttachmentArtifact", "classify_attachment", "extract_attachment_urls"]
