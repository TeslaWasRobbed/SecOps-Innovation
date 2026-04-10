"""Auto-update system for homepage when new content is generated."""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def update_homepage_after_generation(content_type: str, filename: str) -> None:
    """Update homepage after new content is generated."""
    try:
        from homepage.generator import generate_homepage
        
        # Check if homepage exists
        homepage_path = Path("index.html")
        if homepage_path.exists():
            logger.info(f"Updating homepage after {content_type} generation: {filename}")
            generate_homepage(homepage_path)
            logger.info("Homepage updated successfully")
        else:
            logger.debug("Homepage not found, skipping auto-update")
            
    except Exception as exc:
        logger.warning(f"Failed to auto-update homepage: {exc}")


def register_content_hooks() -> None:
    """Register hooks to auto-update homepage when content is generated."""
    # This would be called by other modules when they generate content
    pass