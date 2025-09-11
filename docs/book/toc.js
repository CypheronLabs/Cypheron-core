// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="index.html">Introduction</a></li><li class="chapter-item expanded affix "><li class="part-title">Getting Started</li><li class="chapter-item expanded "><a href="getting-started/installation.html"><strong aria-hidden="true">1.</strong> Installation</a></li><li class="chapter-item expanded "><a href="getting-started/quick-start.html"><strong aria-hidden="true">2.</strong> Quick Start</a></li><li class="chapter-item expanded "><a href="getting-started/examples.html"><strong aria-hidden="true">3.</strong> Basic Examples</a></li><li class="chapter-item expanded "><a href="getting-started/roadmap.html"><strong aria-hidden="true">4.</strong> Development Roadmap</a></li><li class="chapter-item expanded affix "><li class="part-title">Algorithms</li><li class="chapter-item expanded "><a href="algorithms/ml-kem.html"><strong aria-hidden="true">5.</strong> ML-KEM (Key Encapsulation)</a></li><li class="chapter-item expanded "><a href="algorithms/ml-dsa.html"><strong aria-hidden="true">6.</strong> ML-DSA (Digital Signatures)</a></li><li class="chapter-item expanded "><a href="algorithms/falcon.html"><strong aria-hidden="true">7.</strong> Falcon (Digital Signatures)</a></li><li class="chapter-item expanded "><a href="algorithms/sphincsplus.html"><strong aria-hidden="true">8.</strong> SPHINCS+ (Digital Signatures)</a></li><li class="chapter-item expanded affix "><li class="part-title">Hybrid Cryptography</li><li class="chapter-item expanded "><a href="hybrid/overview.html"><strong aria-hidden="true">9.</strong> Overview</a></li><li class="chapter-item expanded affix "><li class="part-title">API Reference</li><li class="chapter-item expanded "><a href="api/types.html"><strong aria-hidden="true">10.</strong> Core Types</a></li><li class="chapter-item expanded affix "><li class="part-title">Architecture</li><li class="chapter-item expanded "><a href="architecture/overview.html"><strong aria-hidden="true">11.</strong> System Architecture</a></li><li class="chapter-item expanded "><a href="architecture/security.html"><strong aria-hidden="true">12.</strong> Security Architecture</a></li><li class="chapter-item expanded "><a href="architecture/ffi.html"><strong aria-hidden="true">13.</strong> FFI Boundary</a></li><li class="chapter-item expanded "><a href="architecture/memory.html"><strong aria-hidden="true">14.</strong> Memory Safety</a></li><li class="chapter-item expanded affix "><li class="part-title">Security</li><li class="chapter-item expanded "><a href="security/model.html"><strong aria-hidden="true">15.</strong> Security Model</a></li><li class="chapter-item expanded "><a href="security/reporting.html"><strong aria-hidden="true">16.</strong> Vulnerability Reporting</a></li><li class="chapter-item expanded "><a href="security/unsafe-guide.html"><strong aria-hidden="true">17.</strong> Unsafe Code Guide</a></li><li class="chapter-item expanded "><a href="security/audit.html"><strong aria-hidden="true">18.</strong> Audit Readiness</a></li><li class="chapter-item expanded affix "><li class="part-title">Development</li><li class="chapter-item expanded "><a href="development/contributing.html"><strong aria-hidden="true">19.</strong> Contributing Guidelines</a></li><li class="chapter-item expanded "><a href="development/build.html"><strong aria-hidden="true">20.</strong> Build System</a></li><li class="chapter-item expanded "><a href="development/testing.html"><strong aria-hidden="true">21.</strong> Testing</a></li><li class="chapter-item expanded affix "><li class="part-title">Troubleshooting</li><li class="chapter-item expanded "><a href="troubleshooting/errors.html"><strong aria-hidden="true">22.</strong> Error Codes</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString().split("#")[0].split("?")[0];
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
