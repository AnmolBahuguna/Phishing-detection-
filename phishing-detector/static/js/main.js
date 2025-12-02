document.addEventListener('DOMContentLoaded', function() {
    const urlInput = document.getElementById('urlInput');
    const scanButton = document.getElementById('scanButton');
    const loadingElement = document.getElementById('loading');
    const resultsElement = document.getElementById('results');
    const errorElement = document.getElementById('error');
    const errorMessage = document.getElementById('errorMessage');
    const riskScoreElement = document.getElementById('riskScore');
    const riskBar = document.getElementById('riskBar');
    const riskBadge = document.getElementById('riskBadge');
    const scannedUrlElement = document.getElementById('scannedUrl');
    const checkResultsElement = document.getElementById('checkResults');

    // Handle scan button click
    scanButton.addEventListener('click', startScan);
    
    // Allow Enter key to trigger scan
    urlInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            startScan();
        }
    });

    function startScan() {
        const url = urlInput.value.trim();
        
        // Basic URL validation
        if (!url) {
            showError('Please enter a URL to scan');
            return;
        }

        // Show loading, hide previous results/errors
        loadingElement.classList.remove('hidden');
        resultsElement.classList.add('hidden');
        errorElement.classList.add('hidden');
        
        // Disable button during scan
        scanButton.disabled = true;
        scanButton.classList.add('opacity-75', 'cursor-not-allowed');

        // Send request to backend
        fetch('/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                throw new Error(data.error);
            }
            displayResults(data);
        })
        .catch(error => {
            console.error('Error:', error);
            showError(error.message || 'An error occurred while scanning the URL');
        })
        .finally(() => {
            loadingElement.classList.add('hidden');
            scanButton.disabled = false;
            scanButton.classList.remove('opacity-75', 'cursor-not-allowed');
        });
    }

    function displayResults(data) {
        // Update basic info
        scannedUrlElement.textContent = data.url;
        riskScoreElement.textContent = `${data.risk_score}/10`;
        
        // Update risk bar and badge
        const riskPercentage = (data.risk_score / 10) * 100;
        riskBar.style.width = `${riskPercentage}%`;
        
        if (data.risk_score < 4) {
            riskBar.className = 'h-4 rounded-full bg-green-500';
            riskBadge.className = 'px-4 py-1 rounded-full text-sm font-medium bg-green-100 text-green-800';
            riskBadge.textContent = 'Low Risk';
        } else if (data.risk_score < 7) {
            riskBar.className = 'h-4 rounded-full bg-yellow-500';
            riskBadge.className = 'px-4 py-1 rounded-full text-sm font-medium bg-yellow-100 text-yellow-800';
            riskBadge.textContent = 'Medium Risk';
        } else {
            riskBar.className = 'h-4 rounded-full bg-red-500';
            riskBadge.className = 'px-4 py-1 rounded-full text-sm font-medium bg-red-100 text-red-800';
            riskBadge.textContent = 'High Risk';
        }
        
        // Clear previous check results
        checkResultsElement.innerHTML = '';
        
        // Add each check result
        for (const [checkName, checkData] of Object.entries(data.checks)) {
            const checkElement = document.createElement('div');
            checkElement.className = 'p-4 border rounded-lg';
            
            const title = checkName.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
            const isSuspicious = checkData.is_suspicious;
            
            checkElement.innerHTML = `
                <div class="flex justify-between items-center mb-2">
                    <h4 class="font-medium">${title}</h4>
                    <span class="px-2 py-1 text-xs font-medium rounded-full ${isSuspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}">
                        ${isSuspicious ? 'Suspicious' : 'Safe'}
                    </span>
                </div>
                <ul class="text-sm text-gray-600 space-y-1">
                    ${checkData.reasons.map(reason => `<li>• ${reason}</li>`).join('')}
                </ul>
            `;
            
            checkResultsElement.appendChild(checkElement);
        }
        
        // Show results
        resultsElement.classList.remove('hidden');
    }

    function showError(message) {
        errorMessage.textContent = message;
        errorElement.classList.remove('hidden');
        
        // Scroll to error message
        errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }
});
