// Updated script.js
// Keeps original JSON .enc structure (salt, iv, ciphertext base64)
// PBKDF2 iterations and AES-GCM usage preserved

// --- helpers ---
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function randBytes(len) {
  const b = new Uint8Array(len);
  crypto.getRandomValues(b);
  return b;
}

async function deriveKeyFromPassword(password, salt, iterations = 150000) {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  const saltBuf = (salt instanceof Uint8Array) ? salt : new Uint8Array(salt);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations, hash: 'SHA-256' },
    passKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// --- hookup to DOM elements ---
const encryptFileInput = document.getElementById('encryptFile');
const encryptPreview = document.getElementById('encryptPreview');
const encryptPasswordInput = document.getElementById('encryptPassword');

const decryptFileInput = document.getElementById('decryptFile');
const decryptPreview = document.getElementById('decryptPreview');
const decryptPasswordInput = document.getElementById('decryptPassword');

const encryptBtn = document.querySelector('button[onclick="encryptImage()"]');
const decryptBtn = document.querySelector('button[onclick="decryptImage()"]');

if (decryptBtn) decryptBtn.disabled = true;

// --- Enable decrypt button when file & password are present ---
const checkDecryptReady = () => {
  const fileChosen = decryptFileInput.files.length > 0;
  const passwordEntered = decryptPasswordInput.value.trim() !== "";
  if (fileChosen && passwordEntered) {
    decryptBtn.disabled = false;
  } else {
    decryptBtn.disabled = true;
  }
};
decryptFileInput.addEventListener('change', checkDecryptReady);
decryptPasswordInput.addEventListener('input', checkDecryptReady);

// --- preview for encryption input ---
if (encryptFileInput && encryptPreview) {
  encryptFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      encryptPreview.src = URL.createObjectURL(file);
      encryptPreview.style.display = 'block';
    } else {
      encryptPreview.style.display = 'none';
    }
  });
}

// --- intelligent check for decrypt input ---
if (decryptFileInput) {
  decryptFileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    decryptPreview.style.display = 'none';
    if (!file) {
      checkDecryptReady();
      return;
    }

    let text;
    try {
      text = await file.text();
    } catch (err) {
      alert('Cannot read file. Please try again.');
      checkDecryptReady();
      return;
    }

    let payload;
    try {
      payload = JSON.parse(text);
    } catch (err) {
      payload = null;
    }

    if (payload && payload.ciphertext && payload.salt && payload.iv) {
      console.log('Encrypted file detected: ready to decrypt.');
      checkDecryptReady();
      return;
    }

    if (file.type && file.type.startsWith('image/')) {
      decryptPreview.src = URL.createObjectURL(file);
      decryptPreview.style.display = 'block';
      alert('This looks like a regular image file, not an encrypted file. Please upload the .enc file created by the app.');
      checkDecryptReady();
      return;
    }

    alert('Please upload a valid encrypted file (.enc) created by this app.');
    checkDecryptReady();
  });
}

// --- encryption logic ---
async function encryptImage() {
  const file = encryptFileInput.files[0];
  const password = encryptPasswordInput.value;

  if (!file) { alert('Please select an image to encrypt.'); return; }
  if (!password) { alert('Enter a password'); return; }

  try {
    const arrayBuffer = await file.arrayBuffer();

    const salt = randBytes(16);
    const key = await deriveKeyFromPassword(password, salt);

    const iv = randBytes(12);
    const cipherBuffer = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, arrayBuffer);

    const payload = {
      filename: file.name,
      type: file.type || 'application/octet-stream',
      salt: arrayBufferToBase64(salt.buffer),
      iv: arrayBufferToBase64(iv.buffer),
      ciphertext: arrayBufferToBase64(cipherBuffer)
    };

    const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
    downloadBlob(blob, file.name + '.enc');

    alert('Encrypted and downloaded. Keep your password safe.');
  } catch (err) {
    console.error(err);
    alert('Encryption failed: ' + (err.message || err));
  }
}

// --- decryption logic ---
async function decryptImage() {
  const file = decryptFileInput.files[0];
  const password = decryptPasswordInput.value;

  if (!file) { alert('Please select the .enc file to decrypt.'); return; }
  if (!password) { alert('Enter password'); return; }

  let text;
  try {
    text = await file.text();
  } catch (err) {
    alert('Cannot read file.'); return;
  }

  let payload;
  try {
    payload = JSON.parse(text);
  } catch (err) {
    alert('Please upload a valid encrypted file (.enc) created by this app.');
    return;
  }

  if (!payload.ciphertext || !payload.salt || !payload.iv) {
    alert('Please upload a valid encrypted file (.enc) created by this app.');
    return;
  }

  try {
    const saltBuf = base64ToArrayBuffer(payload.salt);
    const ivBuf = base64ToArrayBuffer(payload.iv);
    const cipherBuf = base64ToArrayBuffer(payload.ciphertext);

    const key = await deriveKeyFromPassword(password, new Uint8Array(saltBuf));

    const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivBuf) }, key, cipherBuf);

    const mimeType = payload.type || 'image/png';
    const blob = new Blob([plainBuf], { type: mimeType });
    const url = URL.createObjectURL(blob);

    if (decryptPreview) {
      decryptPreview.src = url;
      decryptPreview.style.display = 'block';
    }

    downloadBlob(blob, payload.filename || 'decrypted-image');

    alert('Decryption successful.');
  } catch (err) {
    console.error(err);
    alert('Incorrect password or corrupted encrypted file.');
  }
}
