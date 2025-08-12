// Add a small header to identify encrypted files
const ENCRYPTION_HEADER = "IMGCRYPT::";

async function encryptImage() {
    const fileInput = document.getElementById('encryptFile');
    const password = document.getElementById('encryptPassword').value;

    if (!fileInput.files.length || !password) {
        alert("Please select an image and enter a password.");
        return;
    }

    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();

    // Convert password to key
    const keyMaterial = await getKeyMaterial(password);
    const key = await getKey(keyMaterial);

    // Encrypt
    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: new Uint8Array(12) },
        key,
        arrayBuffer
    );

    // Add header before encrypted data
    const headerBytes = new TextEncoder().encode(ENCRYPTION_HEADER);
    const finalData = new Uint8Array(headerBytes.length + encryptedContent.byteLength);
    finalData.set(headerBytes, 0);
    finalData.set(new Uint8Array(encryptedContent), headerBytes.length);

    // Download encrypted file
    downloadFile(finalData, "encrypted.imgcrypt");
}

async function decryptImage() {
    const fileInput = document.getElementById('decryptFile');
    const password = document.getElementById('decryptPassword').value;

    if (!fileInput.files.length || !password) {
        alert("Please select a file and enter a password.");
        return;
    }

    const file = fileInput.files[0];
    const arrayBuffer = await file.arrayBuffer();
    const uint8Array = new Uint8Array(arrayBuffer);

    // Check for header
    const headerBytes = uint8Array.slice(0, ENCRYPTION_HEADER.length);
    const headerText = new TextDecoder().decode(headerBytes);

    if (headerText !== ENCRYPTION_HEADER) {
        alert("Please upload a valid encrypted image file.");
        return;
    }

    // Extract only the encrypted part
    const encryptedBytes = uint8Array.slice(ENCRYPTION_HEADER.length);

    try {
        const keyMaterial = await getKeyMaterial(password);
        const key = await getKey(keyMaterial);

        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(12) },
            key,
            encryptedBytes
        );

        downloadFile(decryptedContent, "decrypted.png");
    } catch (err) {
        alert("Incorrect password.");
    }
}

function downloadFile(data, filename) {
    const blob = new Blob([data]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

async function getKeyMaterial(password) {
    return crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
}

async function getKey(keyMaterial) {
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: new Uint8Array(16),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}
