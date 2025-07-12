/**
 * Authentication System
 * Security questions to protect access to the encoder/decoder
 */

// Security questions and answers
const securityQuestions = {
    question1: {
        question: "What is Aman's favorite actor?",
        answers: ["mohan lal", "mohanlal"]
    },
    question2: {
        question: "What is Aman's favorite animal?",
        answers: ["cat"]
    },
    question3: {
        question: "Who is Aman's best friend?",
        answers: ["hasan", "siddharth"]
    }
};

// Authentication state
let isAuthenticated = false;

// Initialize authentication on page load
document.addEventListener('DOMContentLoaded', function() {
    checkAuthentication();
    initializeAuthForm();
    initializeTabs();
    initializeEventListeners();
});

function checkAuthentication() {
    // Check if user is already authenticated (session storage)
    const authSession = sessionStorage.getItem('highlyConfidentialAuth');
    if (authSession === 'authenticated') {
        isAuthenticated = true;
        showMainApp();
    } else {
        showAuthModal();
    }
}

function initializeAuthForm() {
    const authForm = document.getElementById('authForm');
    if (authForm) {
        authForm.addEventListener('submit', handleAuthentication);
    }
}

function handleAuthentication(event) {
    event.preventDefault();
    
    const answer1 = document.getElementById('question1').value.trim().toLowerCase();
    const answer2 = document.getElementById('question2').value.trim().toLowerCase();
    const answer3 = document.getElementById('question3').value.trim().toLowerCase();
    
    // Validate answers
    const isAnswer1Correct = securityQuestions.question1.answers.includes(answer1);
    const isAnswer2Correct = securityQuestions.question2.answers.includes(answer2);
    const isAnswer3Correct = securityQuestions.question3.answers.includes(answer3);
    
    if (isAnswer1Correct && isAnswer2Correct && isAnswer3Correct) {
        // Authentication successful
        isAuthenticated = true;
        sessionStorage.setItem('highlyConfidentialAuth', 'authenticated');
        showMainApp();
        showNotification('Authentication successful! Welcome to the secure encoder/decoder.', 'success');
    } else {
        // Authentication failed
        showAuthError();
        showNotification('Authentication failed. Please check your answers.', 'error');
        
        // Clear the form
        document.getElementById('authForm').reset();
    }
}

function showAuthModal() {
    document.getElementById('authOverlay').style.display = 'flex';
    document.getElementById('mainApp').style.display = 'none';
    
    // Focus on first input
    setTimeout(() => {
        document.getElementById('question1').focus();
    }, 500);
}

function showMainApp() {
    document.getElementById('authOverlay').style.display = 'none';
    document.getElementById('mainApp').style.display = 'block';
}

function showAuthError() {
    const errorDiv = document.getElementById('authError');
    errorDiv.style.display = 'flex';
    
    // Hide error after 5 seconds
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

// Add logout functionality
function logout() {
    isAuthenticated = false;
    sessionStorage.removeItem('highlyConfidentialAuth');
    showAuthModal();
    
    // Clear all sensitive data
    const textAreas = document.querySelectorAll('textarea');
    textAreas.forEach(area => area.value = '');
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => field.value = '');
    
    showNotification('Logged out successfully.', 'success');
}

// Security: Clear authentication on page unload
window.addEventListener('beforeunload', function() {
    // Optional: Remove session storage on page close (uncomment if needed)
    // sessionStorage.removeItem('highlyConfidentialAuth');
});

// Prevent access to main functions if not authenticated
function requireAuthentication() {
    if (!isAuthenticated) {
        showNotification('Please authenticate first to use this feature.', 'error');
        showAuthModal();
        return false;
    }
    return true;
}

/**
 * Main JavaScript file for the Highly Confidential Encoder & Decoder
 */

// Initialize crypto manager
const cryptoManager = new CryptoManager();

// Tab functionality
function initializeTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.dataset.tab;
            
            // Remove active class from all tabs and contents
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            btn.classList.add('active');
            document.getElementById(targetTab).classList.add('active');
        });
    });
}

function initializeEventListeners() {
    // Enter key listeners for password fields
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            encryptData();
        }
    });
    
    document.getElementById('decrypt-password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            decryptData();
        }
    });
    
    // Real-time hash verification
    document.getElementById('verify-hash').addEventListener('input', function() {
        if (this.value.trim()) {
            verifyHash();
        } else {
            document.getElementById('verification-result').style.display = 'none';
        }
    });
    
    // Auto-detect encoding format
    document.getElementById('encrypted-input').addEventListener('input', function() {
        if (this.value.trim()) {
            analyzeData();
        }
    });
}

/**
 * Encryption Functions
 */
async function encryptData() {
    if (!requireAuthentication()) return;
    
    const plaintext = document.getElementById('plaintext').value;
    const password = document.getElementById('password').value;
    const algorithm = document.getElementById('algorithm').value;
    const encoding = document.getElementById('encoding').value;
    const iterations = parseInt(document.getElementById('iterations').value);
    
    if (!plaintext.trim()) {
        showNotification('Please enter a message to encrypt', 'error');
        return;
    }
    
    if (!password.trim()) {
        showNotification('Please enter a password', 'error');
        return;
    }
    
    if (password.length < 8) {
        showNotification('Password should be at least 8 characters long', 'warning');
    }
    
    try {
        showLoading('encrypt');
        
        let encryptedData;
        
        switch (algorithm) {
            case 'aes-gcm':
                encryptedData = await cryptoManager.encryptAESGCM(plaintext, password, iterations);
                break;
            case 'aes-cbc':
                encryptedData = await cryptoManager.encryptAESCBC(plaintext, password, iterations);
                break;
            case 'chacha20':
                // Note: ChaCha20 is not directly supported by Web Crypto API
                // For demo purposes, we'll use AES-GCM as fallback
                showNotification('ChaCha20 not available in browser, using AES-GCM', 'warning');
                encryptedData = await cryptoManager.encryptAESGCM(plaintext, password, iterations);
                break;
            default:
                throw new Error('Unsupported algorithm');
        }
        
        let encodedData;
        switch (encoding) {
            case 'base64':
                encodedData = cryptoManager.encodeBase64(encryptedData);
                break;
            case 'base64url':
                encodedData = cryptoManager.encodeBase64URL(encryptedData);
                break;
            case 'hex':
                encodedData = cryptoManager.encodeHex(encryptedData);
                break;
            case 'base32':
                encodedData = cryptoManager.encodeBase32(encryptedData);
                break;
            default:
                throw new Error('Unsupported encoding');
        }
        
        document.getElementById('encrypted-output').value = encodedData;
        showNotification('Data encrypted successfully!', 'success');
        
    } catch (error) {
        showNotification(`Encryption failed: ${error.message}`, 'error');
        console.error('Encryption error:', error);
    } finally {
        hideLoading('encrypt');
    }
}

/**
 * Decryption Functions
 */
async function decryptData() {
    if (!requireAuthentication()) return;
    
    const encryptedInput = document.getElementById('encrypted-input').value;
    const password = document.getElementById('decrypt-password').value;
    const algorithm = document.getElementById('decrypt-algorithm').value;
    const encoding = document.getElementById('input-encoding').value;
    const iterations = parseInt(document.getElementById('decrypt-iterations').value);
    
    if (!encryptedInput.trim()) {
        showNotification('Please enter encrypted data to decrypt', 'error');
        return;
    }
    
    if (!password.trim()) {
        showNotification('Please enter the password', 'error');
        return;
    }
    
    try {
        showLoading('decrypt');
        
        let encryptedData;
        switch (encoding) {
            case 'base64':
                encryptedData = cryptoManager.decodeBase64(encryptedInput);
                break;
            case 'base64url':
                encryptedData = cryptoManager.decodeBase64URL(encryptedInput);
                break;
            case 'hex':
                encryptedData = cryptoManager.decodeHex(encryptedInput);
                break;
            case 'base32':
                encryptedData = cryptoManager.decodeBase32(encryptedInput);
                break;
            default:
                throw new Error('Unsupported encoding');
        }
        
        let decryptedText;
        switch (algorithm) {
            case 'aes-gcm':
                decryptedText = await cryptoManager.decryptAESGCM(encryptedData, password, iterations);
                break;
            case 'aes-cbc':
                decryptedText = await cryptoManager.decryptAESCBC(encryptedData, password, iterations);
                break;
            case 'chacha20':
                // Fallback to AES-GCM
                decryptedText = await cryptoManager.decryptAESGCM(encryptedData, password, iterations);
                break;
            default:
                throw new Error('Unsupported algorithm');
        }
        
        document.getElementById('decrypted-output').value = decryptedText;
        showNotification('Data decrypted successfully!', 'success');
        
    } catch (error) {
        showNotification(`Decryption failed: ${error.message}`, 'error');
        console.error('Decryption error:', error);
    } finally {
        hideLoading('decrypt');
    }
}

/**
 * Hash Functions
 */
async function generateHash() {
    if (!requireAuthentication()) return;
    
    const input = document.getElementById('hash-input').value;
    const algorithm = document.getElementById('hash-algorithm').value;
    const format = document.getElementById('hash-format').value;
    
    if (!input.trim()) {
        showNotification('Please enter data to hash', 'error');
        return;
    }
    
    try {
        showLoading('hash');
        
        let hashData;
        switch (algorithm) {
            case 'sha256':
                hashData = await cryptoManager.generateHash(input, 'SHA-256');
                break;
            case 'sha512':
                hashData = await cryptoManager.generateHash(input, 'SHA-512');
                break;
            case 'sha1':
                hashData = await cryptoManager.generateHash(input, 'SHA-1');
                break;
            case 'md5':
                // MD5 is not supported by Web Crypto API, show warning
                showNotification('MD5 is not supported by Web Crypto API. Use SHA-256 instead.', 'warning');
                return;
            default:
                throw new Error('Unsupported hash algorithm');
        }
        
        let formattedHash;
        switch (format) {
            case 'hex':
                formattedHash = cryptoManager.encodeHex(hashData);
                break;
            case 'base64':
                formattedHash = cryptoManager.encodeBase64(hashData);
                break;
            case 'base32':
                formattedHash = cryptoManager.encodeBase32(hashData);
                break;
            default:
                throw new Error('Unsupported format');
        }
        
        document.getElementById('hash-output').value = formattedHash;
        showNotification('Hash generated successfully!', 'success');
        
    } catch (error) {
        showNotification(`Hash generation failed: ${error.message}`, 'error');
        console.error('Hash error:', error);
    } finally {
        hideLoading('hash');
    }
}

async function verifyHash() {
    const input = document.getElementById('hash-input').value;
    const expectedHash = document.getElementById('verify-hash').value;
    const algorithm = document.getElementById('hash-algorithm').value;
    const format = document.getElementById('hash-format').value;
    const resultDiv = document.getElementById('verification-result');
    
    if (!input.trim() || !expectedHash.trim()) {
        resultDiv.style.display = 'none';
        return;
    }
    
    try {
        let hashData;
        switch (algorithm) {
            case 'sha256':
                hashData = await cryptoManager.generateHash(input, 'SHA-256');
                break;
            case 'sha512':
                hashData = await cryptoManager.generateHash(input, 'SHA-512');
                break;
            case 'sha1':
                hashData = await cryptoManager.generateHash(input, 'SHA-1');
                break;
            default:
                return;
        }
        
        let computedHash;
        switch (format) {
            case 'hex':
                computedHash = cryptoManager.encodeHex(hashData);
                break;
            case 'base64':
                computedHash = cryptoManager.encodeBase64(hashData);
                break;
            case 'base32':
                computedHash = cryptoManager.encodeBase32(hashData);
                break;
            default:
                return;
        }
        
        const isMatch = computedHash.toLowerCase() === expectedHash.toLowerCase();
        
        resultDiv.style.display = 'block';
        resultDiv.className = isMatch ? 'success' : 'error';
        resultDiv.innerHTML = isMatch ? 
            '<i class="fas fa-check"></i> Hash verification successful! Hashes match.' :
            '<i class="fas fa-times"></i> Hash verification failed! Hashes do not match.';
            
    } catch (error) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'error';
        resultDiv.innerHTML = '<i class="fas fa-times"></i> Hash verification error: ' + error.message;
    }
}

/**
 * Utility Functions
 */
function generatePassword() {
    const password = cryptoManager.generateSecurePassword(32);
    document.getElementById('password').value = password;
    showNotification('Secure password generated!', 'success');
}

function analyzeData() {
    const data = document.getElementById('encrypted-input').value.trim();
    
    if (!data) {
        return;
    }
    
    const formats = cryptoManager.analyzeFormat(data);
    
    if (formats.length > 0) {
        const formatStr = formats.join(', ');
        showNotification(`Detected possible formats: ${formatStr}`, 'success');
        
        // Auto-select the first detected format
        const encodingSelect = document.getElementById('input-encoding');
        const formatMap = {
            'Base64': 'base64',
            'Base64URL': 'base64url',
            'Hexadecimal': 'hex',
            'Base32': 'base32'
        };
        
        if (formatMap[formats[0]]) {
            encodingSelect.value = formatMap[formats[0]];
        }
    } else {
        showNotification('Could not detect encoding format', 'warning');
    }
}

function togglePassword(inputId) {
    const input = document.getElementById(inputId);
    const button = input.nextElementSibling;
    const icon = button.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    
    if (!element.value.trim()) {
        showNotification('Nothing to copy', 'warning');
        return;
    }
    
    navigator.clipboard.writeText(element.value).then(() => {
        showNotification('Copied to clipboard!', 'success');
    }).catch(err => {
        // Fallback for older browsers
        element.select();
        document.execCommand('copy');
        showNotification('Copied to clipboard!', 'success');
    });
}

function showNotification(message, type = 'success') {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.className = `notification ${type}`;
    notification.classList.add('show');
    
    setTimeout(() => {
        notification.classList.remove('show');
    }, 4000);
}

function showLoading(operation) {
    const buttons = {
        'encrypt': document.querySelector('[onclick="encryptData()"]'),
        'decrypt': document.querySelector('[onclick="decryptData()"]'),
        'hash': document.querySelector('[onclick="generateHash()"]')
    };
    
    const button = buttons[operation];
    if (button) {
        button.classList.add('loading');
        button.disabled = true;
    }
}

function hideLoading(operation) {
    const buttons = {
        'encrypt': document.querySelector('[onclick="encryptData()"]'),
        'decrypt': document.querySelector('[onclick="decryptData()"]'),
        'hash': document.querySelector('[onclick="generateHash()"]')
    };
    
    const button = buttons[operation];
    if (button) {
        button.classList.remove('loading');
        button.disabled = false;
    }
}

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+Enter to encrypt/decrypt
    if (e.ctrlKey && e.key === 'Enter') {
        e.preventDefault();
        const activeTab = document.querySelector('.tab-content.active');
        if (activeTab.id === 'encrypt') {
            encryptData();
        } else if (activeTab.id === 'decrypt') {
            decryptData();
        } else if (activeTab.id === 'hash') {
            generateHash();
        }
    }
    
    // Ctrl+G to generate password
    if (e.ctrlKey && e.key === 'g') {
        e.preventDefault();
        generatePassword();
    }
});

// Security: Clear sensitive data on page unload
window.addEventListener('beforeunload', function() {
    // Clear password fields
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => field.value = '');
    
    // Clear text areas with potentially sensitive data
    const textAreas = document.querySelectorAll('textarea');
    textAreas.forEach(area => area.value = '');
});
