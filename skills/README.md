# RedStrike.AI Skills (Knowledge Base)

This directory contains skill files that extend agent capabilities. Each skill is a Markdown file containing methodologies, payloads, and techniques that agents use during testing.

## Structure

```
skills/
├── reconnaissance/       # Information gathering techniques
├── vulnerabilities/      # Vulnerability testing methodologies
├── exploitation/         # PoC templates and exploitation
└── reporting/            # Report templates
```

## Adding New Skills

1. Create a new `.md` file in the appropriate category
2. Use clear headings and bullet points
3. Include:
   - **Methodology**: Step-by-step testing approach
   - **Payloads**: Common test payloads
   - **Indicators**: How to identify the vulnerability
   - **PoC Templates**: Code snippets

## Example Skill Format

```markdown
# Skill Name

## Overview
Brief description of the vulnerability/technique.

## Methodology
1. Step one
2. Step two
3. Step three

## Payloads
- Payload 1
- Payload 2

## Detection Indicators
- Indicator 1
- Indicator 2

## PoC Template
\`\`\`python
# Python code here
\`\`\`
```

## Contributing

Skills can be community-contributed. Follow the format above and submit a PR.
