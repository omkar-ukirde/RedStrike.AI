"""
RedStrike.AI - Skill Loader Service
Loads knowledge base files (SKILL.md) for agents to use.
Supports agentskills.io format with YAML frontmatter.
"""
import os
import re
import yaml
from typing import Dict, List, Optional, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"


class Skill:
    """Represents a loaded skill with metadata and content."""
    
    def __init__(self, name: str, description: str, content: str, 
                 tags: List[str] = None, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.content = content
        self.tags = tags or []
        self.version = version
    
    def __repr__(self):
        return f"Skill(name='{self.name}', tags={self.tags})"


class SkillLoader:
    """
    Load and manage agent skills from various formats.
    Supports: SKILL.md, SKILL.yaml, SKILL.json, SKILL.txt
    """
    
    SUPPORTED_FORMATS = [".md", ".yaml", ".yml", ".json", ".txt"]
    
    def __init__(self, skills_directory: Optional[Path] = None):
        self.skills_dir = skills_directory or SKILLS_DIR
        self._cache: Dict[str, Skill] = {}
    
    def list_skills(self) -> Dict[str, List[str]]:
        """
        List all available skills organized by category.
        
        Returns:
            Dict mapping category -> list of skill names
        """
        skills = {}
        
        if not self.skills_dir.exists():
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            return skills
        
        for category_dir in self.skills_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("."):
                category = category_dir.name
                skills[category] = []
                
                # Check for new format: skills/category/skill_name/SKILL.md
                for skill_dir in category_dir.iterdir():
                    if skill_dir.is_dir():
                        for ext in self.SUPPORTED_FORMATS:
                            skill_file = skill_dir / f"SKILL{ext}"
                            if skill_file.exists():
                                skills[category].append(skill_dir.name)
                                break
                
                # Also check for old format: skills/category/skill_name.md
                for skill_file in category_dir.glob("*.md"):
                    if skill_file.name != "README.md":
                        skills[category].append(skill_file.stem)
        
        return skills
    
    def _parse_frontmatter(self, content: str) -> tuple[Dict[str, Any], str]:
        """Parse YAML frontmatter from markdown content."""
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    metadata = yaml.safe_load(parts[1])
                    body = parts[2].strip()
                    return metadata or {}, body
                except yaml.YAMLError:
                    pass
        return {}, content
    
    def _find_skill_file(self, category: str, skill_name: str) -> Optional[Path]:
        """Find the skill file in various formats."""
        # Try new format: skills/category/skill_name/SKILL.*
        skill_dir = self.skills_dir / category / skill_name
        if skill_dir.is_dir():
            for ext in self.SUPPORTED_FORMATS:
                skill_file = skill_dir / f"SKILL{ext}"
                if skill_file.exists():
                    return skill_file
        
        # Try old format: skills/category/skill_name.md
        skill_file = self.skills_dir / category / f"{skill_name}.md"
        if skill_file.exists():
            return skill_file
        
        return None
    
    def load_skill(self, category: str, skill_name: str) -> Optional[Skill]:
        """Load a specific skill."""
        cache_key = f"{category}/{skill_name}"
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        skill_path = self._find_skill_file(category, skill_name)
        
        if not skill_path:
            logger.debug(f"Skill not found: {category}/{skill_name}")
            return None
        
        try:
            content = skill_path.read_text(encoding="utf-8")
            
            # Parse based on format
            if skill_path.suffix in [".md"]:
                metadata, body = self._parse_frontmatter(content)
            elif skill_path.suffix in [".yaml", ".yml"]:
                data = yaml.safe_load(content)
                metadata = {k: v for k, v in data.items() if k != "content"}
                body = data.get("content", "")
            elif skill_path.suffix == ".json":
                import json
                data = json.loads(content)
                metadata = {k: v for k, v in data.items() if k != "content"}
                body = data.get("content", "")
            else:  # .txt
                metadata = {"name": skill_name}
                body = content
            
            skill = Skill(
                name=metadata.get("name", skill_name),
                description=metadata.get("description", ""),
                content=body,
                tags=metadata.get("tags", []),
                version=metadata.get("version", "1.0.0"),
            )
            
            self._cache[cache_key] = skill
            return skill
            
        except Exception as e:
            logger.error(f"Error loading skill {skill_path}: {e}")
            return None
    
    def load_category(self, category: str) -> Dict[str, Skill]:
        """Load all skills from a category."""
        skills = {}
        category_skills = self.list_skills().get(category, [])
        
        for skill_name in category_skills:
            skill = self.load_skill(category, skill_name)
            if skill:
                skills[skill_name] = skill
        
        return skills
    
    def load_all(self) -> Dict[str, Dict[str, Skill]]:
        """Load all skills from all categories."""
        all_skills = {}
        
        for category, skill_names in self.list_skills().items():
            all_skills[category] = self.load_category(category)
        
        return all_skills
    
    def search_by_tag(self, tag: str) -> List[Skill]:
        """Find skills by tag (e.g., 'A03:2021')."""
        matching = []
        
        for category, skills in self.load_all().items():
            for skill in skills.values():
                if tag in skill.tags:
                    matching.append(skill)
        
        return matching
    
    def get_skill_context(self, categories: Optional[List[str]] = None) -> str:
        """
        Get concatenated skill content for agent context.
        
        Args:
            categories: List of categories to include, or None for all
            
        Returns:
            Combined skill content as a single string
        """
        context_parts = []
        
        if categories:
            for category in categories:
                skills = self.load_category(category)
                for skill_name, skill in skills.items():
                    header = f"## {skill.name}"
                    if skill.description:
                        header += f"\n*{skill.description}*"
                    context_parts.append(f"{header}\n\n{skill.content}")
        else:
            all_skills = self.load_all()
            for category, skills in all_skills.items():
                for skill_name, skill in skills.items():
                    header = f"## {skill.name}"
                    if skill.description:
                        header += f"\n*{skill.description}*"
                    context_parts.append(f"{header}\n\n{skill.content}")
        
        return "\n\n---\n\n".join(context_parts)
    
    def reload(self):
        """Clear cache and reload all skills."""
        self._cache.clear()


# Global skill loader instance
skill_loader = SkillLoader()
