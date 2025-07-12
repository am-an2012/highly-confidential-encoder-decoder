/**
 * Highly Confidential Encoder & Decoder
 * Cryptographic functions using Web Crypto API
 */

class CryptoManager {
    constructor() {
        this.encoder = new TextEncoder();
        this.decoder = new TextDecoder();
    }

    /**
     * Generate a cryptographically secure random salt
     */
    generateSalt(length = 32) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    /**
     * Generate a random IV for encryption
     */
    generateIV(length = 16) {
        return crypto.getRandomValues(new Uint8Array(length));
    }

    /**
     * Derive key from password using PBKDF2
     */
    async deriveKey(password, salt, iterations = 250000) {
        const passwordKey = await crypto.subtle.importKey(
            'raw',
            this.encoder.encode(password),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        return await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: iterations,
                hash: 'SHA-256'
            },
            passwordKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );
    }

    /**
     * Encrypt data using AES-GCM
     */
    async encryptAESGCM(plaintext, password, iterations = 250000) {
        try {
            const salt = this.generateSalt();
            const iv = this.generateIV(12); // GCM uses 12-byte IV
            const key = await this.deriveKey(password, salt, iterations);
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                this.encoder.encode(plaintext)
            );

            // Combine salt + iv + encrypted data
            const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            result.set(salt, 0);
            result.set(iv, salt.length);
            result.set(new Uint8Array(encrypted), salt.length + iv.length);

            return result;
        } catch (error) {
            throw new Error(`AES-GCM encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt data using AES-GCM
     */
    async decryptAESGCM(encryptedData, password, iterations = 250000) {
        try {
            const salt = encryptedData.slice(0, 32);
            const iv = encryptedData.slice(32, 44);
            const ciphertext = encryptedData.slice(44);
            
            const key = await this.deriveKey(password, salt, iterations);
            
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: iv
                },
                key,
                ciphertext
            );

            return this.decoder.decode(decrypted);
        } catch (error) {
            throw new Error(`AES-GCM decryption failed: ${error.message}`);
        }
    }

    /**
     * Encrypt data using AES-CBC
     */
    async encryptAESCBC(plaintext, password, iterations = 250000) {
        try {
            const salt = this.generateSalt();
            const iv = this.generateIV(16); // CBC uses 16-byte IV
            
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                this.encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-CBC', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            const encrypted = await crypto.subtle.encrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                this.encoder.encode(plaintext)
            );

            // Combine salt + iv + encrypted data
            const result = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
            result.set(salt, 0);
            result.set(iv, salt.length);
            result.set(new Uint8Array(encrypted), salt.length + iv.length);

            return result;
        } catch (error) {
            throw new Error(`AES-CBC encryption failed: ${error.message}`);
        }
    }

    /**
     * Decrypt data using AES-CBC
     */
    async decryptAESCBC(encryptedData, password, iterations = 250000) {
        try {
            const salt = encryptedData.slice(0, 32);
            const iv = encryptedData.slice(32, 48);
            const ciphertext = encryptedData.slice(48);
            
            const passwordKey = await crypto.subtle.importKey(
                'raw',
                this.encoder.encode(password),
                'PBKDF2',
                false,
                ['deriveKey']
            );

            const key = await crypto.subtle.deriveKey(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iterations,
                    hash: 'SHA-256'
                },
                passwordKey,
                { name: 'AES-CBC', length: 256 },
                false,
                ['encrypt', 'decrypt']
            );
            
            const decrypted = await crypto.subtle.decrypt(
                {
                    name: 'AES-CBC',
                    iv: iv
                },
                key,
                ciphertext
            );

            return this.decoder.decode(decrypted);
        } catch (error) {
            throw new Error(`AES-CBC decryption failed: ${error.message}`);
        }
    }

    /**
     * Generate hash using Web Crypto API
     */
    async generateHash(data, algorithm = 'SHA-256') {
        try {
            const hashBuffer = await crypto.subtle.digest(algorithm, this.encoder.encode(data));
            return new Uint8Array(hashBuffer);
        } catch (error) {
            throw new Error(`Hash generation failed: ${error.message}`);
        }
    }

    /**
     * Encoding functions
     */
    encodeBase64(data) {
        if (typeof data === 'string') {
            data = this.encoder.encode(data);
        }
        return btoa(String.fromCharCode(...data));
    }

    decodeBase64(encoded) {
        try {
            const binary = atob(encoded);
            return new Uint8Array([...binary].map(char => char.charCodeAt(0)));
        } catch (error) {
            throw new Error('Invalid Base64 data');
        }
    }

    encodeBase64URL(data) {
        if (typeof data === 'string') {
            data = this.encoder.encode(data);
        }
        return btoa(String.fromCharCode(...data))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    decodeBase64URL(encoded) {
        try {
            // Add padding if necessary
            let padded = encoded + '==='.slice((encoded.length + 3) % 4);
            // Convert URL-safe characters back
            padded = padded.replace(/-/g, '+').replace(/_/g, '/');
            const binary = atob(padded);
            return new Uint8Array([...binary].map(char => char.charCodeAt(0)));
        } catch (error) {
            throw new Error('Invalid Base64URL data');
        }
    }

    encodeHex(data) {
        if (typeof data === 'string') {
            data = this.encoder.encode(data);
        }
        return Array.from(data)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    decodeHex(encoded) {
        try {
            if (encoded.length % 2 !== 0) {
                throw new Error('Invalid hex string length');
            }
            const bytes = [];
            for (let i = 0; i < encoded.length; i += 2) {
                bytes.push(parseInt(encoded.substr(i, 2), 16));
            }
            return new Uint8Array(bytes);
        } catch (error) {
            throw new Error('Invalid hexadecimal data');
        }
    }

    encodeBase32(data) {
        if (typeof data === 'string') {
            data = this.encoder.encode(data);
        }
        
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        let result = '';
        let buffer = 0;
        let bitsLeft = 0;
        
        for (let byte of data) {
            buffer = (buffer << 8) | byte;
            bitsLeft += 8;
            
            while (bitsLeft >= 5) {
                result += alphabet[(buffer >> (bitsLeft - 5)) & 31];
                bitsLeft -= 5;
            }
        }
        
        if (bitsLeft > 0) {
            result += alphabet[(buffer << (5 - bitsLeft)) & 31];
        }
        
        // Add padding
        while (result.length % 8 !== 0) {
            result += '=';
        }
        
        return result;
    }

    decodeBase32(encoded) {
        try {
            const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            encoded = encoded.toUpperCase().replace(/=+$/, '');
            
            let buffer = 0;
            let bitsLeft = 0;
            const result = [];
            
            for (let char of encoded) {
                const index = alphabet.indexOf(char);
                if (index === -1) {
                    throw new Error('Invalid Base32 character');
                }
                
                buffer = (buffer << 5) | index;
                bitsLeft += 5;
                
                if (bitsLeft >= 8) {
                    result.push((buffer >> (bitsLeft - 8)) & 255);
                    bitsLeft -= 8;
                }
            }
            
            return new Uint8Array(result);
        } catch (error) {
            throw new Error('Invalid Base32 data');
        }
    }

    /**
     * Generate a secure random password
     */
    generateSecurePassword(length = 32) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        return Array.from(array, byte => chars[byte % chars.length]).join('');
    }

    /**
     * Analyze data format
     */
    analyzeFormat(data) {
        const formats = [];
        
        // Check if it's valid Base64
        try {
            if (/^[A-Za-z0-9+/]*={0,2}$/.test(data)) {
                this.decodeBase64(data);
                formats.push('Base64');
            }
        } catch (e) {}
        
        // Check if it's valid Base64URL
        try {
            if (/^[A-Za-z0-9_-]*$/.test(data)) {
                this.decodeBase64URL(data);
                formats.push('Base64URL');
            }
        } catch (e) {}
        
        // Check if it's valid Hex
        try {
            if (/^[0-9A-Fa-f]*$/.test(data) && data.length % 2 === 0) {
                this.decodeHex(data);
                formats.push('Hexadecimal');
            }
        } catch (e) {}
        
        // Check if it's valid Base32
        try {
            if (/^[A-Z2-7=]*$/.test(data.toUpperCase())) {
                this.decodeBase32(data);
                formats.push('Base32');
            }
        } catch (e) {}
        
        return formats;
    }
}

// Export for use in other files
window.CryptoManager = CryptoManager;
