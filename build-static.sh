#!/bin/bash

echo "🔧 Building obfuscated static files for production..."

# Create build directory
mkdir -p rest-api/static-build

# Extract and minify JavaScript from HTML
echo "Extracting and obfuscating JavaScript..."

# Extract JS content between <script> tags
sed -n '/<script>/,/<\/script>/p' rest-api/static/index.html | sed '1d;$d' > /tmp/app.js

# Obfuscate JavaScript with terser
npx terser /tmp/app.js \
  --compress drop_console=true,drop_debugger=true \
  --mangle \
  --toplevel \
  --output /tmp/app.min.js

# Extract CSS content
sed -n '/<style>/,/<\/style>/p' rest-api/static/index.html | sed '1d;$d' > /tmp/app.css

# Minify CSS
npx clean-css-cli -o /tmp/app.min.css /tmp/app.css

# Create obfuscated HTML with minified JS/CSS
cat > rest-api/static-build/index.html << 'EOF'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline';"><title>Cypheron Labs - API Status</title><style>
EOF

# Append minified CSS
cat /tmp/app.min.css >> rest-api/static-build/index.html

cat >> rest-api/static-build/index.html << 'EOF'
</style></head><body><div class="terminal-container">
EOF

# Add ASCII art (keep this unminified for display)
sed -n '/class="ascii-art"/,/<\/div>/p' rest-api/static/index.html >> rest-api/static-build/index.html

# Extract the actual body content between ascii-art and script tags
sed -n '/<div id="typewriter"/,/<script>/p' rest-api/static/index.html | sed '$d' >> rest-api/static-build/index.html

cat >> rest-api/static-build/index.html << 'EOF'
<script>
EOF

# Append obfuscated JavaScript
cat /tmp/app.min.js >> rest-api/static-build/index.html

echo "</script></body></html>" >> rest-api/static-build/index.html

# Clean up temp files
rm /tmp/app.js /tmp/app.css /tmp/app.min.js /tmp/app.min.css

echo "✅ Obfuscated static files created in rest-api/static-build/"
echo "📁 File size reduction:"
echo "   Original: $(wc -c < rest-api/static/index.html) bytes"
echo "   Minified: $(wc -c < rest-api/static-build/index.html) bytes"