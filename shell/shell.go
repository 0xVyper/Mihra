package shell
import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)
type Shell struct {
	WorkingDir string
}
func NewShell() *Shell {
	wd, _ := os.Getwd()
	return &Shell{
		WorkingDir: wd,
	}
}
func (s *Shell) ExecuteCommand(command string) (string, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	
	cmd.Dir = s.WorkingDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command execution failed: %v", err)
	}
	
	return string(output), nil
}
func (s *Shell) ChangeDirectory(dir string) error {
	
	absPath, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %v", err)
	}
	
	
	info, err := os.Stat(absPath)
	if err != nil {
		return fmt.Errorf("failed to access directory: %v", err)
	}
	
	if !info.IsDir() {
		return fmt.Errorf("not a directory: %s", absPath)
	}
	
	
	s.WorkingDir = absPath
	return nil
}
func (s *Shell) UploadFile(localPath, remotePath string) error {
	
	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("failed to open local file: %v", err)
	}
	defer file.Close()
	
	
	remoteFile, err := os.Create(remotePath)
	if err != nil {
		return fmt.Errorf("failed to create remote file: %v", err)
	}
	defer remoteFile.Close()
	
	
	_, err = io.Copy(remoteFile, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}
	
	return nil
}
func (s *Shell) DownloadFile(remotePath, localPath string) error {
	
	file, err := os.Open(remotePath)
	if err != nil {
		return fmt.Errorf("failed to open remote file: %v", err)
	}
	defer file.Close()
	
	
	localFile, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("failed to create local file: %v", err)
	}
	defer localFile.Close()
	
	
	_, err = io.Copy(localFile, file)
	if err != nil {
		return fmt.Errorf("failed to copy file: %v", err)
	}
	
	return nil
}
func (s *Shell) ListFiles(dir string) ([]string, error) {
	
	if dir == "" {
		dir = s.WorkingDir
	}
	
	
	dirObj, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory: %v", err)
	}
	defer dirObj.Close()
	
	
	entries, err := dirObj.Readdir(-1)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %v", err)
	}
	
	
	var files []string
	for _, entry := range entries {
		fileType := "f"
		if entry.IsDir() {
			fileType = "d"
		}
		
		files = append(files, fmt.Sprintf("%s %s %d %s", fileType, entry.Mode().String(), entry.Size(), entry.Name()))
	}
	
	return files, nil
}
func (s *Shell) ParseCommand(command string) (string, []string) {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return "", nil
	}
	
	return parts[0], parts[1:]
}
func (s *Shell) HandleCommand(command string) (string, error) {
	cmd, args := s.ParseCommand(command)
	
	switch strings.ToLower(cmd) {
	case "cd":
		if len(args) == 0 {
			return "", fmt.Errorf("cd: missing directory")
		}
		return "", s.ChangeDirectory(args[0])
		
	case "pwd":
		return s.WorkingDir, nil
		
	case "ls":
		dir := ""
		if len(args) > 0 {
			dir = args[0]
		}
		files, err := s.ListFiles(dir)
		if err != nil {
			return "", err
		}
		return strings.Join(files, "\n"), nil
		
	case "upload":
		if len(args) < 2 {
			return "", fmt.Errorf("upload: missing source or destination")
		}
		return "", s.UploadFile(args[0], args[1])
		
	case "download":
		if len(args) < 2 {
			return "", fmt.Errorf("download: missing source or destination")
		}
		return "", s.DownloadFile(args[0], args[1])
		
	default:
		
		return s.ExecuteCommand(command)
	}
}
