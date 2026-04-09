import os

path = r'c:\Users\akshi\OneDrive\Desktop\Hack_2\CIS-Benchmark-Hardening-Toolkit---L1\docs\index.html'

with open(path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
favicon_inserted = False
logo_inserted = False

for line in lines:
    # Handle favicon
    if '<meta name="viewport" content="width=device-width, initial-scale=1.0" />' in line and not favicon_inserted:
        new_lines.append(line)
        # Only insert if not already there
        if not any('link rel="icon"' in l for l in lines[0:100]):
            new_lines.append('  <link rel="icon" type="image/svg+xml" href="favicon.svg" />\n')
            favicon_inserted = True
        continue

    # Handle logo in hero header
    if '<header class="hero" id="top">' in line and not logo_inserted:
        new_lines.append(line)
        new_lines.append('      <div style="display:flex;align-items:center;gap:18px;margin-bottom:12px;">\n')
        new_lines.append('        <img src="favicon.svg" alt="Logo" style="width:60px;height:60px;filter:drop-shadow(0 4px 12px rgba(0,0,0,0.4));" />\n')
        new_lines.append('        <h1 style="margin:0;">CIS Benchmark Hardening Toolkit Documentation</h1>\n')
        new_lines.append('      </div>\n')
        logo_inserted = True
        continue

    # Skip the old H1 if we just added a new one in a div
    if logo_inserted and '<h1>CIS Benchmark Hardening Toolkit Documentation</h1>' in line:
        continue

    new_lines.append(line)

with open(path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Favicon and Logo integration complete.")
