package unpacker
import (
	"fmt"
	"os"
	"strings"
	"github.com/simplified_c2/module"
)
type Module struct {
	Name        string
	Description string
	Version     string
	Author      string
	unpacker    *Unpacker
}
func NewModule() *Module {
	return &Module{
		Name:        "unpacker",
		Description: "Module for detecting and unpacking packed malware",
		Version:     "1.0.0",
		Author:      "Simplified C2",
		unpacker:    NewUnpacker(UnpackerConfig{}),
	}
}
func (m *Module) GetInfo() *module.ModuleInfo {
	return &module.ModuleInfo{
		Name:        m.Name,
		Version:     m.Version,
		Description: m.Description,
		Author:      m.Author,
		Commands: []module.CommandInfo{
			{
				Name:        "scan",
				Description: "Scan a process for packed content",
				Usage:       "scan <pid>",
				Options:     map[string]string{},
			},
			{
				Name:        "unpack",
				Description: "Unpack a process and save the unpacked binary",
				Usage:       "unpack <pid> <output_path>",
				Options:     map[string]string{},
			},
			{
				Name:        "analyze",
				Description: "Analyze a binary file",
				Usage:       "analyze <file_path>",
				Options:     map[string]string{},
			},
		},
		Options: map[string]string{
			"enabled": "true",
		},
	}
}
func (m *Module) Initialize() error {
	return nil
}
func (m *Module) ExecuteCommand(command string, args []string) (interface{}, error) {
	switch command {
	case "scan":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing process ID")
		}
		
		pid := 0
		fmt.Sscanf(args[0], "%d", &pid)
		if pid <= 0 {
			return nil, fmt.Errorf("invalid process ID")
		}
		
		
		m.unpacker.Config = UnpackerConfig{
			TargetProcess: pid,
			Verbose:       true,
		}
		
		
		tempDir, err := os.MkdirTemp("", "unpacker-scan-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp directory: %v", err)
		}
		defer os.RemoveAll(tempDir)
		
		m.unpacker.Config.OutputPath = tempDir + "/temp_unpacked"
		
		
		isPacked, err := m.Scan(pid)
		if err != nil {
			return nil, err
		}
		
		if isPacked {
			return "Process appears to be packed", nil
		} else {
			return "No packed content detected in process", nil
		}
		
	case "unpack":
		if len(args) < 2 {
			return nil, fmt.Errorf("missing process ID or output path")
		}
		
		pid := 0
		fmt.Sscanf(args[0], "%d", &pid)
		if pid <= 0 {
			return nil, fmt.Errorf("invalid process ID")
		}
		
		outputPath := args[1]
		
		
		outputFile, err := m.Unpack(pid, outputPath)
		if err != nil {
			return nil, err
		}
		
		return fmt.Sprintf("Process unpacked to %s", outputFile), nil
		
	case "analyze":
		if len(args) < 1 {
			return nil, fmt.Errorf("missing file path")
		}
		
		filePath := args[0]
		
		
		analysis, err := m.Analyze(filePath)
		if err != nil {
			return nil, err
		}
		
		
		var result strings.Builder
		result.WriteString(fmt.Sprintf("Analysis of %s:\n", filePath))
		
		if fileType, ok := analysis["file_type"].(string); ok {
			result.WriteString(fmt.Sprintf("File type: %s\n", fileType))
		}
		
		if stillPacked, ok := analysis["possibly_still_packed"].(bool); ok {
			if stillPacked {
				result.WriteString("Warning: File may still be packed\n")
			} else {
				result.WriteString("File does not appear to be packed\n")
			}
		}
		
		if binaryInfo, ok := analysis["binary_info"].(map[string]interface{}); ok {
			result.WriteString("Binary information:\n")
			for k, v := range binaryInfo {
				result.WriteString(fmt.Sprintf("  %s: %v\n", k, v))
			}
		}
		
		if patterns, ok := analysis["suspicious_patterns"].([]string); ok && len(patterns) > 0 {
			result.WriteString("Suspicious patterns found:\n")
			for _, pattern := range patterns {
				result.WriteString(fmt.Sprintf("  - %s\n", pattern))
			}
		}
		
		return result.String(), nil
		
	default:
		return nil, fmt.Errorf("unknown command: %s", command)
	}
}
func (m *Module) Scan(pid int) (bool, error) {
	
	m.unpacker.Config = UnpackerConfig{
		TargetProcess: pid,
		Verbose:       false,
	}
	
	
	tempDir, err := os.MkdirTemp("", "unpacker-scan-*")
	if err != nil {
		return false, fmt.Errorf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	m.unpacker.Config.OutputPath = tempDir + "/temp_unpacked"
	
	
	err = m.unpacker.ScanProcess()
	if err != nil {
		
		if err.Error() == "no packed content found" {
			return false, nil
		}
		return false, err
	}
	
	
	return true, nil
}
func (m *Module) Unpack(pid int, outputPath string) (string, error) {
	
	m.unpacker.Config = UnpackerConfig{
		TargetProcess: pid,
		OutputPath:    outputPath,
		Verbose:       true,
	}
	
	
	err := m.unpacker.ScanProcess()
	if err != nil {
		return "", fmt.Errorf("unpacking failed: %v", err)
	}
	
	
	analysis, err := m.unpacker.AnalyzeUnpackedBinary()
	if err != nil {
		return outputPath, fmt.Errorf("unpacking succeeded but analysis failed: %v", err)
	}
	
	
	if analysis["possibly_still_packed"].(bool) {
		fmt.Println("Binary may still be packed, attempting second pass...")
		
		
		secondPassConfig := UnpackerConfig{
			TargetProcess: -1, 
			OutputPath:    outputPath + ".2nd_pass",
			Verbose:       true,
		}
		
		secondUnpacker := NewUnpacker(secondPassConfig)
		
		
		firstPassData, err := os.ReadFile(outputPath)
		if err != nil {
			return outputPath, fmt.Errorf("failed to read first-pass binary: %v", err)
		}
		
		
		region := MemoryRegion{
			Address:     0,
			Size:        uint64(len(firstPassData)),
			Permissions: 0x7, 
			Content:     firstPassData,
		}
		
		secondUnpacker.MemoryMaps = append(secondUnpacker.MemoryMaps, region)
		
		
		unpacked, err := secondUnpacker.unpackRegion(firstPassData)
		if err == nil && len(unpacked) > 0 {
			secondUnpacker.UnpackedBin = unpacked
			err = secondUnpacker.saveUnpackedBinary()
			if err == nil {
				return secondPassConfig.OutputPath, nil
			}
		}
	}
	
	return outputPath, nil
}
func (m *Module) Analyze(filePath string) (map[string]interface{}, error) {
	
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %v", err)
	}
	
	
	tempUnpacker := NewUnpacker(UnpackerConfig{})
	tempUnpacker.UnpackedBin = data
	
	
	return tempUnpacker.AnalyzeUnpackedBinary()
}
