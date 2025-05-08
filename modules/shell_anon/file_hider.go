package shell_anon
import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)
type FileHider struct {
}
func NewFileHider() *FileHider {
	return &FileHider{}
}
func (f *FileHider) HideFile(path string) error {
	
	
	
	
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not found: %v", err)
	}
	
	
	dir := ""
	filename := path
	
	if lastSlash := strings.LastIndex(path, "/"); lastSlash != -1 {
		dir = path[:lastSlash+1]
		filename = path[lastSlash+1:]
	}
	
	
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
func (f *FileHider) CleanLogFile(logPath string, pattern string) error {
	
	_, err := os.Stat(logPath)
	if err != nil {
		return fmt.Errorf("log file not found: %v", err)
	}
	
	
	content, err := os.ReadFile(logPath)
	if err != nil {
		return fmt.Errorf("failed to read log file: %v", err)
	}
	
	
	re, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid pattern: %v", err)
	}
	
	
	var newLines []string
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if !re.MatchString(line) {
			newLines = append(newLines, line)
		}
	}
	
	
	err = os.WriteFile(logPath, []byte(strings.Join(newLines, "\n")), 0644)
	if err != nil {
		return fmt.Errorf("failed to write log file: %v", err)
	}
	
	return nil
}
func (f *FileHider) SecureDelete(path string) error {
	
	_, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("file not found: %v", err)
	}
	
	
	_, err = exec.LookPath("shred")
	if err == nil {
		
		cmd := exec.Command("shred", "-zu", path)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("shred failed: %v", err)
		}
		return nil
	}
	
	
	
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()
	
	
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %v", err)
	}
	
	
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
	
	
	file.Close()
	
	
	err = os.Remove(path)
	if err != nil {
		return fmt.Errorf("failed to remove file: %v", err)
	}
	
	return nil
}
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
