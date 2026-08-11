let currentReportData = null;

// Utility function to get DOM elements by ID
const getElement = id => document.getElementById(id);

// Updates the result display section with given content
const updateResult = (content, display = true) => {
    const result = getElement('result');
    result.style.display = display ? 'block' : 'none';
    result.innerHTML = content;
};

// Shows a loading spinner and message
const showLoading = message => updateResult(`
        <div class="loading">
            <p>${message}</p>
            <div class="spinner"></div>
        </div>
`);

// Displays an error message
const showError = message => updateResult(`<p class="error">${message}</p>`);


// Handles the process of scanning a URL using VirusTotal
async function scanURL() {
    const url = getElement('urlInput').value.trim();
    if (!url) return showError("Please enter a URL!");

    try {
        new URL(url); // Validate URL format
    } catch {
        return showError("Please enter a valid URL (e.g., https://example.com)");
    }

    try {
        showLoading("Submitting URL for scanning...");

        const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to scan the URL.');
        }

        showFormattedResult(result.report);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}

// Handles the process of scanning a file using VirusTotal
async function scanFile() {
    const file = getElement('fileInput').files[0];
    if (!file) return showError("Please select a file!");
    if (file.size > 32 * 1024 * 1024) return showError("File size exceeds 32MB limit.");

    try {
        showLoading("Uploading file...");

        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });

        const result = await response.json();
        if (!response.ok) {
            throw new Error(result.error || 'Failed to scan the file.');
        }

        showFormattedResult(result.report);
    } catch (error) {
        showError(`Error: ${error.message}`);
    }
}


// Formats and displays analysis results in the UI
function showFormattedResult(data) {
    if (!data?.data?.attributes?.stats) return showError("Invalid response format!");

    const stats = data.data.attributes.stats;
    const total = Object.values(stats).reduce((sum, val) => sum + val, 0);
    if (!total) return showError("No analysis results available!");

    const getPercent = val => ((val / total) * 100).toFixed(1);

    const categories = {
        malicious: { color: 'malicious', label: 'Malicious' },
        suspicious: { color: 'suspicious', label: 'Suspicious' },
        harmless: { color: 'safe', label: 'Clean' },
        undetected: { color: 'undetected', label: 'Undetected' }
    };

    const percents = Object.keys(categories).reduce((acc, key) => {
        acc[key] = getPercent(stats[key]);
        return acc;
    }, {});

    // Determine overall vardict
    const verdict = stats.malicious > 0 ? "Malicious" : stats.suspicious > 0 ? "Suspicious" : "Safe";
    const verdictClass = stats.malicious > 0 ? "malicious" : stats.suspicious > 0 ? "suspicious" : "safe";

    // Render result summary UI
    currentReportData = data;
    updateResult(`
        <h3>Scan Report</h3>
        <div class="scan-stats">
            <p><strong>Verdict:</strong> <span class="${verdictClass}">${verdict}</span></p>
            <div class="progress-section">
                <div class="progress-label">
                    <span>Detection Results</span>
                    <span class="progress-percent">${percents.malicious}% Detection Rate</span>
                </div>
                <div class="progress-stacked">
                    ${Object.entries(categories).map(([key, { color }]) => `
                        <div class="progress-bar ${color}" style="width: ${percents[key]}%" title="${categories[key].label}: ${stats[key]} (${percents[key]}%)">
                            <span class="progress-label-overlay">${stats[key]}</span>
                        </div>
                    `).join('')}
                </div>
                <div class="progress-legend">
                    ${Object.entries(categories).map(([key, { color, label }]) => `
                        <div class="legend-item">
                            <span class="legend-color ${color}"></span>
                            <span>${label} (${percents[key]}%)</span>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="detection-details">
                ${Object.entries(categories).map(([key, { color, label }]) => `
                    <div class="detail-item ${color}">
                        <span class="detail-label">${label}</span>
                        <span class="detail-value">${stats[key]}</span>
                        <span class="detail-percent">${percents[key]}%<span>
                    </div>
                `).join('')}
            </div>
        </div>
        <button onclick="showFullReport()">View Full Report</button>
    `);

    // Trigger animation
    setTimeout(() => getElement('result').querySelector('.progress-stacked').classList.add('animate'), 1000);
}

// Displays a detailed report modal with engine-by-engine detection results
function showFullReport() {
    if (!currentReportData) return showError('No report data available. Please run a scan first.');

    const data = currentReportData;
    const modal = getElement("fullReportModal");
    const results = data.data?.attributes?.results;

    getElement("fullReportContent").innerHTML = `
        <h3>Full Report Details</h3>
        ${results ? `
            <table>
                <tr><th>Engine</th><th>Result</th></tr>
                ${Object.entries(results).map(([engine, { category }]) => `
                    <tr>
                        <td>${engine}</td>
                        <td class="${category === "malicious" ? "malicious" : category === "suspicious" ? "suspicious" : "safe"}">${category}</td>
                    </tr>
                `).join('')}
            </table>
        ` : '<p>No detailed results available!</p>'}
    `;

    modal.style.display = "block";
    modal.offsetHeight;
    modal.classList.add("show");
}

// Closes the full report modal
const closeModal = () => {
    const modal = getElement("fullReportModal");
    modal.classList.remove("show");
    setTimeout(() => modal.style.display = "none", 300);
}

// Close modal on outside click
window.addEventListener('load', () => {
    const modal = getElement("fullReportModal");
    window.addEventListener('click', e => e.target === modal && closeModal());
});