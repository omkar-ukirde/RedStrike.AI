"""
RedStrike.AI - Skill Loader Service
Loads knowledge base files (MD) for agents to use.
"""
import os
from typing import Dict, List, Optional
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).parent.parent.parent / "skills"


class SkillLoader:
    """Load and manage agent skills from markdown files."""
    
    def __init__(self, skills_directory: Optional[Path] = None):
        self.skills_dir = skills_directory or SKILLS_DIR
        self._cache: Dict[str, str] = {}
    
    def list_skills(self) -> Dict[str, List[str]]:
        """List all available skills organized by category."""
        skills = {}
        
        if not self.skills_dir.exists():
            logger.warning(f"Skills directory not found: {self.skills_dir}")
            return skills
        
        for category_dir in self.skills_dir.iterdir():
            if category_dir.is_dir() and not category_dir.name.startswith("."):
                category = category_dir.name
                skills[category] = []
                
                for skill_file in category_dir.glob("*.md"):
                    skills[category].append(skill_file.stem)
        
        return skills
    
    def load_skill(self, category: str, skill_name: str) -> Optional[str]:
        """Load a specific skill file content."""
        cache_key = f"{category}/{skill_name}"
        
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        skill_path = self.skills_dir / category / f"{skill_name}.md"
        
        if not skill_path.exists():
            logger.warning(f"Skill not found: {skill_path}")
            return None
        
        try:
            content = skill_path.read_text(encoding="utf-8")
            self._cache[cache_key] = content
            return content
        except Exception as e:
            logger.error(f"Error loading skill {skill_path}: {e}")
            return None
    
    def load_category(self, category: str) -> Dict[str, str]:
        """Load all skills from a category."""
        skills = {}
        category_dir = self.skills_dir / category
        
        if not category_dir.exists():
            return skills
        
        for skill_file in category_dir.glob("*.md"):
            skill_name = skill_file.stem
            content = self.load_skill(category, skill_name)
            if content:
                skills[skill_name] = content
        
        return skills
    
    def load_all(self) -> Dict[str, Dict[str, str]]:
        """Load all skills from all categories."""
        all_skills = {}
        
        for category, skill_names in self.list_skills().items():
            all_skills[category] = self.load_category(category)
        
        return all_skills
    
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
                for skill_name, content in skills.items():
                    context_parts.append(f"## {category.title()} - {skill_name.replace('_', ' ').title()}\n\n{content}")
        else:
            all_skills = self.load_all()
            for category, skills in all_skills.items():
                for skill_name, content in skills.items():
                    context_parts.append(f"## {category.title()} - {skill_name.replace('_', ' ').title()}\n\n{content}")
        
        return "\n\n---\n\n".join(context_parts)
    
    def reload(self):
        """Clear cache and reload all skills."""
        self._cache.clear()


# Global skill loader instance
skill_loader = SkillLoader()
