#!/bin/bash

echo "🔐 Advanced obfuscation for static files..."

# Create build directory
mkdir -p rest-api/static-secure

# Advanced JavaScript obfuscation
echo "Applying advanced JavaScript obfuscation..."

# Extract JavaScript
sed -n '/<script>/,/<\/script>/p' rest-api/static/index.html | sed '1d;$d' > /tmp/app.js

# Heavy obfuscation with terser
npx terser /tmp/app.js \
  --compress drop_console=true,drop_debugger=true,pure_funcs=['console.log','console.warn','console.error'],unsafe=true,unsafe_comps=true,unsafe_math=true \
  --mangle \
  --toplevel \
  --rename \
  --output /tmp/app.obf.js

# Additional variable name scrambling
sed -i 's/testHealth/_0x1a2b/g; s/testDetailed/_0x3c4d/g; s/clearResults/_0x5e6f/g; s/showResponse/_0x7890/g; s/apiUrl/_0xabcd/g; s/response/_0xef01/g' /tmp/app.obf.js

# CSS obfuscation - minify and scramble class names
sed -n '/<style>/,/<\/style>/p' rest-api/static/index.html | sed '1d;$d' > /tmp/app.css

# Minify CSS aggressively
npx cleancss --level 2 -o /tmp/app.min.css /tmp/app.css

# Scramble CSS class names
sed -i 's/terminal-container/_tc/g; s/ascii-art/_aa/g; s/typewriter-text/_tt/g; s/api-form/_af/g; s/response-area/_ra/g; s/response-content/_rc/g' /tmp/app.min.css

# Create ultra-minified HTML
cat > rest-api/static-secure/index.html << 'EOF'
<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'self';script-src 'unsafe-inline';style-src 'unsafe-inline'"><title>Cypheron Labs</title><style>
EOF

# Insert minified CSS
cat /tmp/app.min.css >> rest-api/static-secure/index.html

# Insert HTML structure with scrambled class names
cat >> rest-api/static-secure/index.html << 'EOF'
</style></head><body><div class="_tc">
EOF

# Process ASCII art with scrambled classes
sed -n '/class="ascii-art"/,/<\/div>/p' rest-api/static/index.html | sed 's/ascii-art/_aa/g' >> rest-api/static-secure/index.html

# Ultra-compact HTML structure
cat >> rest-api/static-secure/index.html << 'EOF'
<div id="t" class="_tt"></div><div class="_af"><div><label>API Endpoint:</label><input type="text" id="u" value="https://api.cypheronlabs.com"></div><div style="text-align:center"><button onclick="_0x1a2b()">Test Health</button><button onclick="_0x3c4d()">Detailed Status</button><button onclick="_0x5e6f()">Clear</button></div></div><div class="_ra"><div style="color:#C084FC;margin-bottom:10px">═══ API RESPONSE ═══</div><div class="_rc" id="r">$ Ready to test your Cypheron Labs API...
$ </div></div></div><script>
EOF

# Insert obfuscated JavaScript with element ID changes
sed 's/"typewriter"/"t"/g; s/"api-url"/"u"/g; s/"response-content"/"r"/g' /tmp/app.obf.js >> rest-api/static-secure/index.html

echo "</script></body></html>" >> rest-api/static-secure/index.html

# Clean up
rm /tmp/app.js /tmp/app.css /tmp/app.min.css /tmp/app.obf.js

echo "🔒 Advanced obfuscated files created:"
echo "   Original size: $(wc -c < rest-api/static/index.html) bytes"
echo "   Obfuscated size: $(wc -c < rest-api/static-secure/index.html) bytes"
echo "   Reduction: $(echo "scale=1; (1 - $(wc -c < rest-api/static-secure/index.html) / $(wc -c < rest-api/static/index.html)) * 100" | bc)%"
echo ""
echo "🛡️  Obfuscation applied:"
echo "   ✅ Function names scrambled"
echo "   ✅ CSS classes shortened"
echo "   ✅ HTML minified"
echo "   ✅ JavaScript heavily compressed"
echo "   ✅ Element IDs shortened"