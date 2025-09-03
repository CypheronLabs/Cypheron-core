// Custom JavaScript for Cypheron Core Documentation

document.addEventListener('DOMContentLoaded', function() {
    // Add copy buttons to code blocks
    const codeBlocks = document.querySelectorAll('pre code');
    codeBlocks.forEach(function(codeBlock) {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.textContent = 'Copy';
        button.style.position = 'absolute';
        button.style.top = '5px';
        button.style.right = '5px';
        button.style.padding = '5px 10px';
        button.style.fontSize = '12px';
        button.style.backgroundColor = '#007acc';
        button.style.color = 'white';
        button.style.border = 'none';
        button.style.borderRadius = '3px';
        button.style.cursor = 'pointer';
        
        codeBlock.parentElement.style.position = 'relative';
        codeBlock.parentElement.appendChild(button);
        
        button.addEventListener('click', function() {
            const text = codeBlock.textContent;
            navigator.clipboard.writeText(text).then(function() {
                button.textContent = 'Copied!';
                setTimeout(function() {
                    button.textContent = 'Copy';
                }, 2000);
            });
        });
    });
    
    // Add error code search functionality
    const errorCodePattern = /ERROR-(\w+)-(\d+)/g;
    const content = document.querySelector('.content');
    if (content) {
        content.innerHTML = content.innerHTML.replace(errorCodePattern, function(match) {
            const errorCode = match;
            return `<span class="error-code" data-error="${errorCode}">${errorCode}</span>`;
        });
        
        // Add click handlers for error codes
        const errorCodes = document.querySelectorAll('.error-code');
        errorCodes.forEach(function(errorCodeEl) {
            errorCodeEl.style.cursor = 'pointer';
            errorCodeEl.style.color = '#f44336';
            errorCodeEl.style.textDecoration = 'underline';
            
            errorCodeEl.addEventListener('click', function() {
                const errorCode = this.getAttribute('data-error');
                // Navigate to troubleshooting section
                window.location.href = `/troubleshooting/errors.html#${errorCode.toLowerCase()}`;
            });
        });
    }
    
    // Performance metrics tooltips
    const perfMetrics = document.querySelectorAll('[data-perf]');
    perfMetrics.forEach(function(metric) {
        metric.style.cursor = 'help';
        metric.style.borderBottom = '1px dotted #ccc';
        
        metric.addEventListener('mouseenter', function() {
            const tooltip = document.createElement('div');
            tooltip.className = 'perf-tooltip';
            tooltip.textContent = this.getAttribute('data-perf');
            tooltip.style.position = 'absolute';
            tooltip.style.backgroundColor = '#333';
            tooltip.style.color = 'white';
            tooltip.style.padding = '5px 10px';
            tooltip.style.borderRadius = '3px';
            tooltip.style.fontSize = '12px';
            tooltip.style.zIndex = '1000';
            tooltip.style.pointerEvents = 'none';
            
            document.body.appendChild(tooltip);
            
            const rect = this.getBoundingClientRect();
            tooltip.style.left = rect.left + 'px';
            tooltip.style.top = (rect.top - tooltip.offsetHeight - 5) + 'px';
        });
        
        metric.addEventListener('mouseleave', function() {
            const tooltip = document.querySelector('.perf-tooltip');
            if (tooltip) {
                tooltip.remove();
            }
        });
    });
});