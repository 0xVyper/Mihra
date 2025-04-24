package shell_anon

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// FileHider provides functionality for hiding files and cleaning logs
type FileHider struct {
}

// NewFileHider creates a new file hider
func NewFileHider() *FileHider {
	return &FileHider{}
}

// HideFile hides a file from ls command
func (f *FileHider) HideFile(path string) error {
	// This is a simplified implementation
	// In a real implementation, you would use extended attributes or other techniques
	
	// Check if the file exists
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not found: %v", err)
	}
	
	// Rename the file to start with a dot to hide it from normal ls
	dir := ""
	filename := path
	
	if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
		dir = path[:lastSlash+1]
		filename = path[lastSlash+1:]
	}
	
	// If the file doesn't already start with a dot, rename it
	if !strings.HasPrefix(filename, ".") {
		newPath := dir + "." + filename
		err := os.Rename(path, newPath)
		if err != nil {
			return fmt.Errorf("failed to rename file: %v", err)
		}
		return nil
	}
	
	return nil
}

// CleanLogFile removes entries from a log file
func (f *FileHider) CleanLogFile(logPath string, pattern string) error {
	// Check if the log file exists
	_, err := os.Stat(logPath)
	if err != nil {
		return fmt.Errorf("log file not found: %v", err)
	}
	
	// Read the log file
	content, err := os.ReadFile(logPath)
	if err != nil {
		return fmt.Errorf("failed to read log file: %v", err)
	}
	
	// Compile the pattern
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %v", err)
	}
	
	// Remove matching lines
	var newLines []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if !re.MatchString(line) {
			newLines = append(newLines, line)
		}
	}
	
	// Write the cleaned content back to the file
	err = os.WriteFile(logPath, []byte(strings.Join(newLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write log file: %v", err)
	}
	
	return nil
}

// SecureDelete securely deletes a file
func (f *FileHider) SecureDelete(path string) error {
	// Check if the file exists
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not found: %v", err)
	}
	
	// Check if shred is available
	_, err = exec.LookPath("shred")
	if err == nil {
		// Use shred to securely delete the file
		cmd := exec.Command("shred", "-zu", path)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("shred failed: %v", err)
		}
		return nil
	}
	
	// If shred is not available, implement a basic secure delete
	// Open the file
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	// Get file size
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	
	// Overwrite the file with zeros
	zeros := make([]byte, 4096)
	for i := int64(0); i < info.Size(); i += 4096 {
		writeSize := int64(4096)
		if i+writeSize > info.Size() {
			writeSize = info.Size() - i
		}
		_, err = file.WriteAt(zeros[:writeSize], i)
		if err != nil {
			return fmt.Errorf("failed to overwrite file: %v", err)
		}
	}
	
	// Close the file
	file.Close()
	
	// Delete the file
	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to remove file: %v", err)
	}
	
	return nil
}

// GetFileHidingTips returns tips for hiding files
func (f *FileHider) GetFileHidingTips() []string {
	return []string{
		"Prefix filenames with a dot to hide from normal ls",
		"Use extended attributes to hide files",
		"Store sensitive data in alternate data streams (Windows)",
		"Use steganography to hide data in images or other files",
		"Use secure delete tools like shred to remove files",
		"Clean log files regularly to remove traces",
	}
}
