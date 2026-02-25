#!/usr/bin/env python3
"""Validate Spektion marketplace plugin structure and content."""

import json
import os
import re
import sys
from pathlib import Path

NAMING_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
MAX_NAME_LENGTH = 64
MAX_DESCRIPTION_LENGTH = 1024
SECRET_PATTERNS = [
    ".env", ".env.*", "*.key", "*.pem", "*.p12", "*.pfx",
    "credentials.json", "secrets.json", ".api_key",
]

def validate_name(name: str, context: str) -> list[str]:
    errors = []
    if not name:
        errors.append(f"{context}: name is required")
    elif len(name) > MAX_NAME_LENGTH:
        errors.append(f"{context}: name exceeds {MAX_NAME_LENGTH} characters")
    elif not NAMING_PATTERN.match(name):
        errors.append(f"{context}: name '{name}' must match pattern {NAMING_PATTERN.pattern}")
    return errors

def validate_description(description: str, context: str) -> list[str]:
    errors = []
    if not description:
        errors.append(f"{context}: description is required")
    elif len(description) > MAX_DESCRIPTION_LENGTH:
        errors.append(f"{context}: description exceeds {MAX_DESCRIPTION_LENGTH} characters")
    return errors

def validate_marketplace_json(root: Path) -> list[str]:
    errors = []
    manifest_path = root / ".claude-plugin" / "marketplace.json"
    if not manifest_path.exists():
        return [f"Missing marketplace manifest: {manifest_path}"]
    try:
        with open(manifest_path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON in {manifest_path}: {e}"]

    for field in ["name", "description", "owner", "plugins"]:
        if field not in data:
            errors.append(f"marketplace.json: missing required field '{field}'")

    if "name" in data:
        errors.extend(validate_name(data["name"], "marketplace.json"))
    if "description" in data:
        errors.extend(validate_description(data["description"], "marketplace.json"))
    if "owner" in data:
        owner = data["owner"]
        if "name" not in owner:
            errors.append("marketplace.json: owner.name is required")
        if "email" not in owner:
            errors.append("marketplace.json: owner.email is required")
    if "plugins" in data:
        if not isinstance(data["plugins"], list) or len(data["plugins"]) == 0:
            errors.append("marketplace.json: plugins must be a non-empty array")
        for plugin in data.get("plugins", []):
            if "name" not in plugin:
                errors.append("marketplace.json: each plugin must have a name")
            if "source" not in plugin:
                errors.append("marketplace.json: each plugin must have a source")
    return errors

def validate_plugin_json(plugin_dir: Path) -> list[str]:
    errors = []
    plugin_json = plugin_dir / ".claude-plugin" / "plugin.json"
    if not plugin_json.exists():
        return [f"Missing plugin manifest: {plugin_json}"]
    try:
        with open(plugin_json) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return [f"Invalid JSON in {plugin_json}: {e}"]

    for field in ["name", "description", "version"]:
        if field not in data:
            errors.append(f"plugin.json: missing required field '{field}'")

    if "name" in data:
        errors.extend(validate_name(data["name"], "plugin.json"))
    if "description" in data:
        errors.extend(validate_description(data["description"], "plugin.json"))
    return errors

def parse_skill_frontmatter(skill_md: Path) -> tuple[dict, list[str]]:
    errors = []
    try:
        content = skill_md.read_text()
    except Exception as e:
        return {}, [f"Cannot read {skill_md}: {e}"]

    if not content.startswith("---"):
        return {}, [f"{skill_md}: SKILL.md must start with YAML frontmatter (---)"]

    parts = content.split("---", 2)
    if len(parts) < 3:
        return {}, [f"{skill_md}: SKILL.md frontmatter not properly closed (needs opening and closing ---)"]

    frontmatter = {}
    for line in parts[1].strip().split("\n"):
        if ":" in line:
            key, _, value = line.partition(":")
            frontmatter[key.strip()] = value.strip()

    return frontmatter, errors

def validate_skills(plugin_dir: Path) -> list[str]:
    errors = []
    skills_dir = plugin_dir / "skills"
    if not skills_dir.exists():
        return [f"Missing skills directory: {skills_dir}"]

    for skill_dir in sorted(skills_dir.iterdir()):
        if not skill_dir.is_dir():
            continue

        dir_name = skill_dir.name
        errors.extend(validate_name(dir_name, f"skill directory '{dir_name}'"))

        skill_md = skill_dir / "SKILL.md"
        if not skill_md.exists():
            errors.append(f"Missing SKILL.md in {skill_dir}")
            continue

        frontmatter, parse_errors = parse_skill_frontmatter(skill_md)
        errors.extend(parse_errors)

        if "name" not in frontmatter:
            errors.append(f"{skill_md}: frontmatter missing 'name'")
        elif frontmatter["name"] != dir_name:
            errors.append(f"{skill_md}: frontmatter name '{frontmatter['name']}' does not match directory name '{dir_name}'")

        if "description" not in frontmatter:
            errors.append(f"{skill_md}: frontmatter missing 'description'")
        else:
            errors.extend(validate_description(frontmatter["description"], f"skill '{dir_name}'"))

    return errors

def check_secrets(root: Path) -> list[str]:
    errors = []
    for pattern in SECRET_PATTERNS:
        for match in root.rglob(pattern):
            if match.is_file() and ".git" not in match.parts:
                errors.append(f"Potential secret file found: {match}")
    return errors

def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    verbose = "--verbose" in sys.argv

    all_errors = []
    all_errors.extend(validate_marketplace_json(root))
    all_errors.extend(check_secrets(root))

    plugins_dir = root / "plugins"
    if not plugins_dir.exists():
        all_errors.append(f"Missing plugins directory: {plugins_dir}")
    else:
        for plugin_dir in sorted(plugins_dir.iterdir()):
            if not plugin_dir.is_dir():
                continue
            if verbose:
                print(f"Validating plugin: {plugin_dir.name}")
            all_errors.extend(validate_plugin_json(plugin_dir))
            all_errors.extend(validate_skills(plugin_dir))

    if all_errors:
        print(f"\nValidation FAILED with {len(all_errors)} error(s):\n")
        for error in all_errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print("Validation PASSED")
        sys.exit(0)

if __name__ == "__main__":
    main()
