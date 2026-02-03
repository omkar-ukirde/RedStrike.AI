"""
RedStrike.AI - Skill Loader Service
Loads knowledge base files (SKILL.md) for agents to use.
Supports agentskills.io format with YAML frontmatter.
Implements progressive disclosure per Agent Skills specification.
"""
import os
import re
import yaml
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"


class Skill:
    """Represents a loaded skill with metadata and content."""
    
    def __init__(self, name: str, description: str, content: str, 
                 tags: List[str] = None, version: str = "1.0.0",
                 allowed_tools: List[str] = None, compatibility: str = "",
                 metadata: Dict[str, Any] = None):
        self.name = name
        self.description = description
        self.content = content
        self.tags = tags or []
        self.version = version
        self.allowed_tools = allowed_tools or []
        self.compatibility = compatibility
        self.metadata = metadata or {}
    
    def __repr__(self):
        return f"Skill(name='{self.name}', tags={self.tags})"
    
    def get_summary(self) -> Dict[str, Any]:
        """Return minimal summary for progressive disclosure (~100 tokens)."""
        return {
            "name": self.name,
            "description": self.description,
            "tags": self.tags,
            "allowed_tools": self.allowed_tools,
        }


class SkillLoader:
    """
    Load and manage agent skills from various formats.
    Supports: SKILL.md, SKILL.yaml, SKILL.json, SKILL.txt
    
    Implements progressive disclosure per Agent Skills specification:
    1. Metadata (~100 tokens): name + description at startup
    2. Instructions (<5000 tokens): Full SKILL.md body when activated
    3. Resources (as needed): Reference files loaded on demand
    """
    
    SUPPORTED_FORMATS = [".md", ".yaml", ".yml", ".json", ".txt"]
    
    def __init__(self, skills_directory: Optional[Path] = None):
        self.skills_dir = skills_directory or SKILLS_DIR
        self._cache: Dict[str, Skill] = {}
        self._reference_cache: Dict[str, str] = {}
    
    def _parse_category_path(self, category: str) -> Tuple[Path, str]:
        """
        Parse category path supporting hierarchical structure.
        
        Examples:
            "injection" -> skills/injection, "injection"
            "web/a03-injection" -> skills/web/a03-injection, "a03-injection"
        """
        parts = category.split("/")
        category_path = self.skills_dir / "/".join(parts)
        skill_name = parts[-1]
        return category_path, skill_name
    
    def list_skills(self) -> Dict[str, List[str]]:
        """
        List all available skills organized by category.
        Supports hierarchical categories like web/a03-injection.
        
        Returns:
            Dict mapping category -> list of skill names
        """
        skills = {}
        
        if not self.skills_dir.exists():
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            return skills
        
        def process_directory(dir_path: Path, prefix: str = ""):
            """Recursively process directories."""
            for item in dir_path.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    category = f"{prefix}/{item.name}" if prefix else item.name
                    
                    # Check if this directory has a SKILL.md (making it a skill)
                    has_skill_file = any(
                        (item / f"SKILL{ext}").exists() 
                        for ext in self.SUPPORTED_FORMATS
                    )
                    
                    if has_skill_file:
                        # This is a skill directory
                        parent_category = prefix if prefix else "root"
                        if parent_category not in skills:
                            skills[parent_category] = []
                        skills[parent_category].append(item.name)
                        
                        # Also add to full path category
                        skills[category] = ["SKILL"]
                    
                    # Check for subdirectories with skills
                    process_directory(item, category)
                    
                    # Check for old-style .md files
                    for md_file in item.glob("*.md"):
                        if md_file.name not in ["README.md", "SKILL.md"]:
                            if category not in skills:
                                skills[category] = []
                            skills[category].append(md_file.stem)
        
        process_directory(self.skills_dir)
        return skills
    
    def list_categories(self) -> List[str]:
        """List all top-level and nested skill categories."""
        categories = set()
        
        def find_categories(dir_path: Path, prefix: str = ""):
            for item in dir_path.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    category = f"{prefix}/{item.name}" if prefix else item.name
                    
                    # Check if has SKILL.md
                    has_skill = any(
                        (item / f"SKILL{ext}").exists() 
                        for ext in self.SUPPORTED_FORMATS
                    )
                    
                    if has_skill:
                        categories.add(category)
                    
                    # Check subdirectories
                    find_categories(item, category)
        
        find_categories(self.skills_dir)
        return sorted(categories)
    
    def _parse_frontmatter(self, content: str) -> Tuple[Dict[str, Any], str]:
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
    
    def _find_skill_file(self, category: str, skill_name: str = None) -> Optional[Path]:
        """
        Find the skill file supporting hierarchical paths.
        
        Args:
            category: Category path (e.g., "web/a03-injection" or "injection")
            skill_name: Optional specific skill name
        """
        # Handle hierarchical category paths
        if "/" in category:
            skill_dir = self.skills_dir / category
            if skill_dir.is_dir():
                for ext in self.SUPPORTED_FORMATS:
                    skill_file = skill_dir / f"SKILL{ext}"
                    if skill_file.exists():
                        return skill_file
        
        # Try category/skill_name/SKILL.md format
        if skill_name:
            skill_dir = self.skills_dir / category / skill_name
            if skill_dir.is_dir():
                for ext in self.SUPPORTED_FORMATS:
                    skill_file = skill_dir / f"SKILL{ext}"
                    if skill_file.exists():
                        return skill_file
            
            # Try category/skill_name.md format (legacy)
            skill_file = self.skills_dir / category / f"{skill_name}.md"
            if skill_file.exists():
                return skill_file
        
        # Try category itself as skill directory
        skill_dir = self.skills_dir / category
        if skill_dir.is_dir():
            for ext in self.SUPPORTED_FORMATS:
                skill_file = skill_dir / f"SKILL{ext}"
                if skill_file.exists():
                    return skill_file
        
        return None
    
    def load_skill(self, category: str, skill_name: str = None) -> Optional[Skill]:
        """
        Load a specific skill with full content.
        
        Args:
            category: Category path (e.g., "web/a03-injection")
            skill_name: Optional skill name within category
        """
        cache_key = f"{category}/{skill_name}" if skill_name else category
        
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
                metadata = {"name": skill_name or category.split("/")[-1]}
                body = content
            
            # Parse allowed-tools (can be space or comma separated)
            allowed_tools_str = metadata.get("allowed-tools", "")
            if isinstance(allowed_tools_str, str):
                allowed_tools = [t.strip() for t in allowed_tools_str.replace(",", " ").split() if t.strip()]
            else:
                allowed_tools = allowed_tools_str if isinstance(allowed_tools_str, list) else []
            
            skill = Skill(
                name=metadata.get("name", skill_name or category.split("/")[-1]),
                description=metadata.get("description", ""),
                content=body,
                tags=metadata.get("tags", []),
                version=metadata.get("version", "1.0.0"),
                allowed_tools=allowed_tools,
                compatibility=metadata.get("compatibility", ""),
                metadata=metadata.get("metadata", {}),
            )
            
            self._cache[cache_key] = skill
            return skill
            
        except Exception as e:
            logger.error(f"Error loading skill {skill_path}: {e}")
            return None
    
    # ============================================================
    # PROGRESSIVE DISCLOSURE METHODS (Agent Skills Specification)
    # ============================================================
    
    def get_skill_summary(self, category: str, skill_name: str = None) -> Optional[Dict[str, Any]]:
        """
        Get minimal skill summary for initial context (~100 tokens).
        Level 1 of progressive disclosure.
        
        Returns:
            Dict with name, description, tags, allowed_tools
        """
        skill = self.load_skill(category, skill_name)
        if skill:
            return skill.get_summary()
        return None
    
    def get_skill_summaries(self, categories: List[str]) -> List[Dict[str, Any]]:
        """
        Get summaries for multiple skill categories.
        Useful for initial agent context.
        """
        summaries = []
        for category in categories:
            summary = self.get_skill_summary(category)
            if summary:
                summary["category"] = category
                summaries.append(summary)
        return summaries
    
    def get_skill_instructions(self, category: str, skill_name: str = None) -> str:
        """
        Get full skill instructions (<5000 tokens recommended).
        Level 2 of progressive disclosure.
        
        Returns:
            Full SKILL.md body content
        """
        skill = self.load_skill(category, skill_name)
        if skill:
            return skill.content
        return ""
    
    def list_references(self, category: str, skill_name: str = None) -> List[str]:
        """
        List available reference files for a skill.
        
        Returns:
            List of reference file names (without path)
        """
        # Find skill directory
        if "/" in category:
            skill_dir = self.skills_dir / category
        elif skill_name:
            skill_dir = self.skills_dir / category / skill_name
        else:
            skill_dir = self.skills_dir / category
        
        references_dir = skill_dir / "references"
        
        if references_dir.is_dir():
            return [f.name for f in references_dir.iterdir() if f.is_file() and f.suffix == ".md"]
        
        return []
    
    def get_reference(self, category: str, reference_name: str, skill_name: str = None) -> str:
        """
        Get specific reference file content on demand.
        Level 3 of progressive disclosure.
        
        Args:
            category: Skill category (e.g., "web/a03-injection")
            reference_name: Reference file name (e.g., "sql-injection.md")
            skill_name: Optional skill name
            
        Returns:
            Reference file content
        """
        cache_key = f"{category}/{skill_name}/{reference_name}" if skill_name else f"{category}/{reference_name}"
        
        if cache_key in self._reference_cache:
            return self._reference_cache[cache_key]
        
        # Find references directory
        if "/" in category:
            skill_dir = self.skills_dir / category
        elif skill_name:
            skill_dir = self.skills_dir / category / skill_name
        else:
            skill_dir = self.skills_dir / category
        
        ref_path = skill_dir / "references" / reference_name
        
        if ref_path.exists():
            try:
                content = ref_path.read_text(encoding="utf-8")
                self._reference_cache[cache_key] = content
                return content
            except Exception as e:
                logger.error(f"Error loading reference {ref_path}: {e}")
        
        return ""
    
    def get_allowed_tools(self, category: str, skill_name: str = None) -> List[str]:
        """Get allowed-tools from skill metadata."""
        skill = self.load_skill(category, skill_name)
        if skill:
            return skill.allowed_tools
        return []
    
    # ============================================================
    # LEGACY COMPATIBILITY METHODS
    # ============================================================
    
    def load_category(self, category: str) -> Dict[str, Skill]:
        """Load all skills from a category."""
        skills = {}
        category_skills = self.list_skills().get(category, [])
        
        for skill_name in category_skills:
            if skill_name == "SKILL":
                # This is the category itself as a skill
                skill = self.load_skill(category)
            else:
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
        
        for category in self.list_categories():
            skill = self.load_skill(category)
            if skill and tag in skill.tags:
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
                skill = self.load_skill(category)
                if skill:
                    header = f"## {skill.name}"
                    if skill.description:
                        header += f"\n*{skill.description}*"
                    context_parts.append(f"{header}\n\n{skill.content}")
                else:
                    # Try loading as old-style category
                    skills = self.load_category(category)
                    for skill_name, skill in skills.items():
                        header = f"## {skill.name}"
                        if skill.description:
                            header += f"\n*{skill.description}*"
                        context_parts.append(f"{header}\n\n{skill.content}")
        else:
            for category in self.list_categories():
                skill = self.load_skill(category)
                if skill:
                    header = f"## {skill.name}"
                    if skill.description:
                        header += f"\n*{skill.description}*"
                    context_parts.append(f"{header}\n\n{skill.content}")
        
        return "\n\n---\n\n".join(context_parts)
    
    def get_progressive_context(
        self, 
        categories: List[str],
        include_references: bool = False,
        max_references_per_skill: int = 2
    ) -> str:
        """
        Get skill context using progressive disclosure.
        
        Args:
            categories: List of category paths
            include_references: Whether to include reference files
            max_references_per_skill: Maximum number of references to include
            
        Returns:
            Formatted skill context with progressive detail
        """
        context_parts = []
        
        for category in categories:
            skill = self.load_skill(category)
            if not skill:
                continue
            
            # Add skill header and description
            header = f"## {skill.name}"
            if skill.description:
                header += f"\n*{skill.description}*"
            
            # Add main content
            content = f"{header}\n\n{skill.content}"
            
            # Optionally add references
            if include_references:
                references = self.list_references(category)[:max_references_per_skill]
                if references:
                    ref_content = "\n\n### Detailed References\n"
                    for ref_name in references:
                        ref_text = self.get_reference(category, ref_name)
                        if ref_text:
                            ref_content += f"\n#### {ref_name.replace('.md', '').replace('-', ' ').title()}\n{ref_text[:2000]}"  # Limit size
                    content += ref_content
            
            context_parts.append(content)
        
        return "\n\n---\n\n".join(context_parts)
    
    def reload(self):
        """Clear cache and reload all skills."""
        self._cache.clear()
        self._reference_cache.clear()


# Global skill loader instance
skill_loader = SkillLoader()
