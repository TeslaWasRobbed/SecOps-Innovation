"""Real-time actor mention tracking from threat digest history.

Scans generated digests against the full known threat-actor roster (MITRE
ATT&CK + Microsoft Threat Intelligence, via ``shared.actor_correlation``) so
mention counts reflect the entire actor database rather than a small
hardcoded list of financial/nation-state groups.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from shared.actor_correlation import actor_key, get_actor_alias_index


def scan_digest_for_mentions(digest_path: Path) -> Dict[str, List[dict]]:
    """Scan a digest file for actor mentions (full roster) and return matches."""
    if not digest_path.exists():
        return {}

    try:
        content = digest_path.read_text(encoding='utf-8')
        mentions: Dict[str, List[dict]] = {}

        for actor in get_actor_alias_index():
            actor_mentions = []

            # Check all aliases for this actor
            for alias in actor['aliases']:
                # Use word boundaries to avoid partial matches
                pattern = r'\b' + re.escape(alias) + r'\b'
                matches = re.finditer(pattern, content, re.IGNORECASE)

                for match in matches:
                    # Get context around the mention (50 chars before and after)
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    context = content[start:end].strip()

                    actor_mentions.append({
                        'alias_used': match.group(),
                        'context': context,
                        'position': match.start()
                    })

            if actor_mentions:
                mentions[actor_key(actor['name'])] = actor_mentions

        return mentions

    except Exception as e:
        print(f"Error scanning {digest_path}: {e}")
        return {}


def get_digest_files() -> List[Path]:
    """Get one digest file per report date from the output directory.

    Both Markdown and HTML are generated for the same digest. Prefer Markdown:
    it contains the report text without embedded actor UI data, so mentions are
    not double-counted or inflated by the webpage's support scripts.
    """
    output_dir = Path("output/threat_digest")
    if not output_dir.exists():
        return []
    
    by_date: dict[str, Path] = {}
    for digest_file in output_dir.glob("digest_*.*"):
        if digest_file.suffix.lower() not in {".html", ".md"}:
            continue
        date_match = re.search(r'digest_(\d{4}-\d{2}-\d{2})', digest_file.name)
        if not date_match:
            continue
        digest_date = date_match.group(1)
        existing = by_date.get(digest_date)
        if existing is None or digest_file.suffix.lower() == ".md":
            by_date[digest_date] = digest_file

    digest_files = list(by_date.values())
    digest_files.sort(key=lambda x: x.name, reverse=True)
    return digest_files


def build_actor_tracking_data() -> Dict[str, Any]:
    """Build comprehensive tracking data from all digest files."""
    digest_files = get_digest_files()
    
    # Initialize tracking data
    tracking_data = {
        'last_updated': datetime.now().isoformat(),
        'total_digests_scanned': len(digest_files),
        'actors': {}
    }
    
    # Initialize every actor in the full roster (MITRE ATT&CK + Microsoft Threat Intel)
    for actor in get_actor_alias_index():
        slug = actor_key(actor['name'])
        tracking_data['actors'][slug] = {
            'name': actor['name'],
            'id': actor['id'],
            'type': actor['type'],
            'aliases': actor['aliases'],
            'total_mentions': 0,
            'digest_appearances': 0,
            'mentions_by_digest': {},
            'recent_contexts': [],
            'first_seen': None,
            'last_seen': None
        }
    
    # Scan each digest file
    for digest_file in digest_files:
        # Extract date from filename (e.g., digest_2026-04-10.html -> 2026-04-10)
        date_match = re.search(r'digest_(\d{4}-\d{2}-\d{2})', digest_file.name)
        if not date_match:
            continue
        
        digest_date = date_match.group(1)
        mentions = scan_digest_for_mentions(digest_file)
        
        # Update tracking data
        for slug, actor_mentions in mentions.items():
            actor_data = tracking_data['actors'].get(slug)
            if actor_data is None:
                continue

            # Update counts
            mention_count = len(actor_mentions)
            actor_data['total_mentions'] += mention_count
            actor_data['digest_appearances'] += 1
            
            # Store mentions for this digest
            actor_data['mentions_by_digest'][digest_date] = {
                'count': mention_count,
                'file': digest_file.name,
                'mentions': actor_mentions[:3]  # Keep first 3 mentions for context
            }
            
            # Update recent contexts (keep last 5)
            for mention in actor_mentions[:2]:  # Max 2 per digest
                actor_data['recent_contexts'].append({
                    'date': digest_date,
                    'context': mention['context'],
                    'alias_used': mention['alias_used']
                })
            
            # Keep only the 5 most recent contexts
            actor_data['recent_contexts'] = actor_data['recent_contexts'][-5:]
            
            # Update first/last seen dates
            if not actor_data['first_seen'] or digest_date < actor_data['first_seen']:
                actor_data['first_seen'] = digest_date
            if not actor_data['last_seen'] or digest_date > actor_data['last_seen']:
                actor_data['last_seen'] = digest_date
    
    return tracking_data


def save_tracking_data(tracking_data: Dict[str, Any]) -> None:
    """Save tracking data to JSON file."""
    output_file = Path("shared/actor_tracking_data.json")
    output_file.parent.mkdir(exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(tracking_data, f, indent=2, ensure_ascii=False)


def load_tracking_data() -> Dict[str, Any]:
    """Load existing tracking data or return empty structure."""
    tracking_file = Path("shared/actor_tracking_data.json")
    
    if tracking_file.exists():
        try:
            with open(tracking_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading tracking data: {e}")
    
    # Return empty structure if file doesn't exist or can't be loaded
    return {
        'last_updated': None,
        'total_digests_scanned': 0,
        'actors': {}
    }


def update_actor_tracking() -> Dict[str, Any]:
    """Update actor tracking data and return the results."""
    print("Scanning digest files for actor mentions...")
    
    tracking_data = build_actor_tracking_data()
    save_tracking_data(tracking_data)
    
    print(f"Scanned {tracking_data['total_digests_scanned']} digest files")
    
    # Print summary
    total_mentions = sum(actor['total_mentions'] for actor in tracking_data['actors'].values())
    active_actors = sum(1 for actor in tracking_data['actors'].values() if actor['total_mentions'] > 0)
    
    print(f"Found {total_mentions} total mentions across {active_actors} actors")
    
    return tracking_data


def get_actor_stats() -> Dict[str, int]:
    """Get summary statistics for the Actor Watch page."""
    tracking_data = load_tracking_data()
    
    total_actors = len([a for a in tracking_data.get('actors', {}).values() if a.get('total_mentions', 0) > 0])
    total_mentions = sum(a.get('total_mentions', 0) for a in tracking_data.get('actors', {}).values())
    total_digests = tracking_data.get('total_digests_scanned', 0)
    
    return {
        'total_actors': total_actors,
        'total_mentions': total_mentions,
        'total_digests': total_digests,
        'last_updated': tracking_data.get('last_updated')
    }


if __name__ == "__main__":
    # Run the tracking update
    update_actor_tracking()
