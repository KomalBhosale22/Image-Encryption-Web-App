async function encryptImage() {
    const fileInput = document.getElementById("encryptFile").files[0];
    const password = document.getElementById("encryptPassword").value;

    if (!fileInput || !password) {
        alert("Please select an image and enter a password.");
        return;
    }

    const fileData = await fileInput.arrayBuffer();
    const keyMaterial = await getKeyMaterial(password);
    const key = await getKey(keyMaterial, "encrypt");

    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, fileData);

    const blob = new Blob([iv, encrypted]);
    downloadFile(blob, "encrypted_image.bin");
}

async function decryptImage() {
    const fileInput = document.getElementById("decryptFile").files[0];
    const password = document.getElementById("decryptPassword").value;

    if (!fileInput || !password) {
        alert("Please select a file and enter a password.");
        return;
    }

    const fileData = await fileInput.arrayBuffer();
    const iv = fileData.slice(0, 12);
    const encryptedData = fileData.slice(12);

    const keyMaterial = await getKeyMaterial(password);
    const key = await getKey(keyMaterial, "decrypt");

    try {
        const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encryptedData);
        const blob = new Blob([decrypted]);
        downloadFile(blob, "decrypted_image.png");
    } catch (error) {
        alert("Decryption failed. Check your password.");
    }
}

function downloadFile(blob, fileName) {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = fileName;
    link.click();
}

function getKeyMaterial(password) {
    const enc = new TextEncoder();
    return crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
}

function getKey(keyMaterial, usage) {
    return crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: new Uint8Array(16), iterations: 100000, hash: "SHA-256" },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        [usage]
    );
}
