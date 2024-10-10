import xml.etree.ElementTree as ET
import re

# Load and parse the XML file
tree = ET.parse('stigs.txt')
root = tree.getroot()

# Define the namespace
ns = {'xccdf': 'http://checklists.nist.gov/xccdf/1.1'}

# Find all 'Group' elements
groups = root.findall('.//xccdf:Group', ns)

results = []

# Process each Group
for group in groups:
    group_id = group.get('id')
    rule = group.find('.//xccdf:Rule', ns)
    if rule is not None:
        rule_id = rule.get('id')
        title = rule.find('xccdf:title', ns).text
        description_elem = rule.find('xccdf:description', ns)
        if description_elem is not None:
            # Extract the content within VulnDiscussion tags
            vuln_discussion = re.search(r'<VulnDiscussion>(.*?)</VulnDiscussion>', description_elem.text, re.DOTALL)
            description = vuln_discussion.group(1).strip() if vuln_discussion else "No vulnerability discussion available"
        else:
            description = "No description available"
        fixtext_elem = rule.find('.//xccdf:fixtext', ns)
        fixtext = fixtext_elem.text if fixtext_elem is not None else "No fixtext available"
        check_elem = rule.find('.//xccdf:check-content', ns)
        check = check_elem.text if check_elem is not None else "No check content available"
        
        results.append({
            '_id': group_id,
            'title': title,
            'description': description,
            'fixtext': fixtext,
            'check': check
        })

# Create and write to markdown file
with open('stig_rules.md', 'w') as md_file:
    md_file.write("# STIG Rules\n\n")
    
    for i, result in enumerate(results, 1):
        md_file.write(f"## {result['_id']}\n\n")
        md_file.write(f"### Title\n{result['title']}\n\n")
        md_file.write(f"### Description\n{result['description']}\n\n")
        md_file.write(f"### Rule Check\n{result['check']}\n\n")
        md_file.write(f"### Fix\n{result['fixtext']}\n\n")
        md_file.write("---\n\n")  # Separator between rules

print(f"Processed {len(results)} rules.")
print("Results have been exported to 'stig_rules.md'")