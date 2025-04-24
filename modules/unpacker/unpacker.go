package unpacker

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// MemoryRegion represents a memory region
type MemoryRegion struct {
	Address     uintptr
	Size        uint64
	Permissions uint8
	Content     []byte
}

// UnpackerConfig holds configuration for the unpacker
type UnpackerConfig struct {
	TargetProcess int
	OutputPath    string
	Verbose       bool
}

// Unpacker provides functionality for unpacking packed binaries
type Unpacker struct {
	Config      UnpackerConfig
	MemoryMaps  []MemoryRegion
	UnpackedBin []byte
}

// NewUnpacker creates a new unpacker
func NewUnpacker(config UnpackerConfig) *Unpacker {
	return &Unpacker{
		Config:     config,
		MemoryMaps: []MemoryRegion{},
	}
}

// ScanProcess scans a process for packed content
func (u *Unpacker) ScanProcess() error {
	// This is a simplified implementation
	// In a real implementation, you would use ptrace or other techniques to scan the process memory

	if u.Config.TargetProcess <= 0 {
		return errors.New("invalid process ID")
	}

	// For demonstration purposes, we'll create a fake memory map
	// In a real implementation, you would read the actual process memory

	// Create a fake memory region with some "packed" content
	region := MemoryRegion{
		Address:     0x400000,
		Size:        0x1000,
		Permissions: 0x7, // rwx
		Content:     []byte("This is a simulated packed binary content"),
	}

	u.MemoryMaps = append(u.MemoryMaps, region)

	// Try to unpack the regions
	for _, region := range u.MemoryMaps {
		unpacked, err := u.unpackRegion(region.Content)
		if err == nil && len(unpacked) > 0 {
			u.UnpackedBin = unpacked
			return u.saveUnpackedBinary()
		}
	}

	return errors.New("no packed content found")
}

// unpackRegion attempts to unpack a memory region
func (u *Unpacker) unpackRegion(data []byte) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would use various unpacking techniques

	// Check for common packers
	if u.isPossiblyUPX(data) {
		return u.unpackUPX(data)
	}

	if u.isPossiblyDyamorphine(data) {
		return u.unpackDyamorphine(data)
	}

	// Generic unpacking attempt
	return u.genericUnpack(data)
}

// isPossiblyUPX checks if the data might be packed with UPX
func (u *Unpacker) isPossiblyUPX(data []byte) bool {
	// Look for UPX signature
	return bytes.Contains(data, []byte("UPX"))
}

// isPossiblyDyamorphine checks if the data might be packed with Dyamorphine
func (u *Unpacker) isPossiblyDyamorphine(data []byte) bool {
	// This is a simplified check
	// In a real implementation, you would look for specific signatures

	// Look for potential Dyamorphine signatures
	return bytes.Contains(data, []byte("Dyamorphine")) ||
		bytes.Contains(data, []byte("Diamorphine"))
}

// unpackUPX attempts to unpack UPX-packed data
func (u *Unpacker) unpackUPX(data []byte) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would implement UPX unpacking

	if u.Config.Verbose {
		fmt.Println("Attempting UPX unpacking...")
	}

	// For demonstration purposes, we'll just return a modified version of the input
	return append([]byte("UPX-unpacked: "), data...), nil
}

// unpackDyamorphine attempts to unpack Dyamorphine-packed data
func (u *Unpacker) unpackDyamorphine(data []byte) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would implement Dyamorphine unpacking

	if u.Config.Verbose {
		fmt.Println("Attempting Dyamorphine unpacking...")
	}

	// For demonstration purposes, we'll just return a modified version of the input
	return append([]byte("Dyamorphine-unpacked: "), data...), nil
}

// genericUnpack attempts a generic unpacking
func (u *Unpacker) genericUnpack(data []byte) ([]byte, error) {
	// This is a simplified implementation
	// In a real implementation, you would implement generic unpacking techniques

	if u.Config.Verbose {
		fmt.Println("Attempting generic unpacking...")
	}

	// For demonstration purposes, we'll just return the input
	return data, nil
}

// saveUnpackedBinary saves the unpacked binary to a file
func (u *Unpacker) saveUnpackedBinary() error {
	if u.UnpackedBin == nil || len(u.UnpackedBin) == 0 {
		return errors.New("no unpacked binary to save")
	}

	if u.Config.OutputPath == "" {
		return errors.New("no output path specified")
	}

	return os.WriteFile(u.Config.OutputPath, u.UnpackedBin, 0644)
}

// AnalyzeUnpackedBinary analyzes the unpacked binary
func (u *Unpacker) AnalyzeUnpackedBinary() (map[string]interface{}, error) {
	if u.UnpackedBin == nil || len(u.UnpackedBin) == 0 {
		return nil, errors.New("no unpacked binary to analyze")
	}

	analysis := make(map[string]interface{})

	// Determine file type
	fileType := u.determineFileType(u.UnpackedBin)
	analysis["file_type"] = fileType

	// Check if the binary might still be packed
	analysis["possibly_still_packed"] = u.isPossiblyStillPacked(u.UnpackedBin)

	// Get basic binary information
	info, err := u.getBinaryInfo(u.UnpackedBin, fileType)
	if err == nil {
		analysis["binary_info"] = info
	}

	// Look for suspicious patterns
	suspiciousPatterns := u.findSuspiciousPatterns(u.UnpackedBin)
	if len(suspiciousPatterns) > 0 {
		analysis["suspicious_patterns"] = suspiciousPatterns
	}

	return analysis, nil
}

// determineFileType determines the type of the binary
func (u *Unpacker) determineFileType(data []byte) string {
	// Check for ELF
	if len(data) > 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return "ELF"
	}

	// Check for PE
	if len(data) > 2 && data[0] == 'M' && data[1] == 'Z' {
		return "PE"
	}

	// Check for Mach-O
	if len(data) > 4 && ((data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) ||
		(data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)) {
		return "Mach-O"
	}

	return "Unknown"
}

// isPossiblyStillPacked checks if the binary might still be packed
func (u *Unpacker) isPossiblyStillPacked(data []byte) bool {
	// This is a simplified check
	// In a real implementation, you would use more sophisticated techniques

	// Check entropy
	entropy := u.calculateEntropy(data)

	// High entropy might indicate encryption or packing
	return entropy > 7.0
}

// calculateEntropy calculates the entropy of the data
func (u *Unpacker) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	frequencies := make(map[byte]int)
	for _, b := range data {
		frequencies[b]++
	}

	// Calculate entropy
	entropy := 0.0
	for _, count := range frequencies {
		probability := float64(count) / float64(len(data))
		entropy -= probability * (float64(binary.Size(probability)) / float64(binary.Size(1.0)))
	}

	return entropy
}

// getBinaryInfo gets basic information about the binary
func (u *Unpacker) getBinaryInfo(data []byte, fileType string) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	switch fileType {
	case "ELF":
		return u.getELFInfo(data)
	case "PE":
		return u.getPEInfo(data)
	default:
		info["size"] = len(data)
	}

	return info, nil
}

// getELFInfo gets information about an ELF binary
func (u *Unpacker) getELFInfo(data []byte) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	// Parse ELF
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// Get basic information
	info["machine"] = elfFile.Machine.String()
	info["type"] = elfFile.Type.String()
	info["entry_point"] = elfFile.Entry

	// Get sections
	sections := make([]string, 0)
	for _, section := range elfFile.Sections {
		sections = append(sections, section.Name)
	}
	info["sections"] = sections

	return info, nil
}

// getPEInfo gets information about a PE binary
func (u *Unpacker) getPEInfo(data []byte) (map[string]interface{}, error) {
	info := make(map[string]interface{})

	// Parse PE
	peFile, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	// Get basic information
	info["machine"] = peFile.Machine
	info["characteristics"] = peFile.Characteristics

	if peFile.OptionalHeader != nil {
		oh32, ok := peFile.OptionalHeader.(*pe.OptionalHeader32)
		if ok {
			info["entry_point"] = oh32.AddressOfEntryPoint
			info["image_base"] = oh32.ImageBase
		} else {
			oh64, ok := peFile.OptionalHeader.(*pe.OptionalHeader64)
			if ok {
				info["entry_point"] = oh64.AddressOfEntryPoint
				info["image_base"] = oh64.ImageBase
			}
		}
	}

	// Get sections
	sections := make([]string, 0)
	for _, section := range peFile.Sections {
		sections = append(sections, section.Name)
	}
	info["sections"] = sections

	return info, nil
}

// findSuspiciousPatterns looks for suspicious patterns in the binary
func (u *Unpacker) findSuspiciousPatterns(data []byte) []string {
	var patterns []string

	// Look for common suspicious strings
	suspiciousStrings := []string{
		"CreateRemoteThread",
		"VirtualAlloc",
		"VirtualProtect",
		"WriteProcessMemory",
		"LoadLibrary",
		"GetProcAddress",
		"WSASocket",
		"connect",
		"bind",
		"listen",
		"accept",
		"cmd.exe",
		"powershell",
		"bash",
		"sh",
		"/bin/sh",
		"system",
		"exec",
		"fork",
	}

	for _, s := range suspiciousStrings {
		if bytes.Contains(data, []byte(s)) {
			patterns = append(patterns, s)
		}
	}

	return patterns
}
