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
type MemoryRegion struct {
	Address     uintptr
	Size        uint64
	Permissions uint8
	Content     []byte
}
type UnpackerConfig struct {
	TargetProcess int
	OutputPath    string
	Verbose       bool
}
type Unpacker struct {
	Config      UnpackerConfig
	MemoryMaps  []MemoryRegion
	UnpackedBin []byte
}
func NewUnpacker(config UnpackerConfig) *Unpacker {
	return &Unpacker{
		Config:     config,
		MemoryMaps: []MemoryRegion{},
	}
}
func (u *Unpacker) ScanProcess() error {
	
	
	if u.Config.TargetProcess <= 0 {
		return errors.New("invalid process ID")
	}
	
	
	
	region := MemoryRegion{
		Address:     0x400000,
		Size:        0x1000,
		Permissions: 0x7, 
		Content:     []byte("This is a simulated packed binary content"),
	}
	u.MemoryMaps = append(u.MemoryMaps, region)
	
	for _, region := range u.MemoryMaps {
		unpacked, err := u.unpackRegion(region.Content)
		if err == nil && len(unpacked) > 0 {
			u.UnpackedBin = unpacked
			return u.saveUnpackedBinary()
		}
	}
	return errors.New("no packed content found")
}
func (u *Unpacker) unpackRegion(data []byte) ([]byte, error) {
	
	
	
	if u.isPossiblyUPX(data) {
		return u.unpackUPX(data)
	}
	if u.isPossiblyDyamorphine(data) {
		return u.unpackDyamorphine(data)
	}
	
	return u.genericUnpack(data)
}
func (u *Unpacker) isPossiblyUPX(data []byte) bool {
	
	return bytes.Contains(data, []byte("UPX"))
}
func (u *Unpacker) isPossiblyDyamorphine(data []byte) bool {
	
	
	
	return bytes.Contains(data, []byte("Dyamorphine")) ||
		bytes.Contains(data, []byte("Diamorphine"))
}
func (u *Unpacker) unpackUPX(data []byte) ([]byte, error) {
	
	
	if u.Config.Verbose {
		fmt.Println("Attempting UPX unpacking...")
	}
	
	return append([]byte("UPX-unpacked: "), data...), nil
}
func (u *Unpacker) unpackDyamorphine(data []byte) ([]byte, error) {
	
	
	if u.Config.Verbose {
		fmt.Println("Attempting Dyamorphine unpacking...")
	}
	
	return append([]byte("Dyamorphine-unpacked: "), data...), nil
}
func (u *Unpacker) genericUnpack(data []byte) ([]byte, error) {
	
	
	if u.Config.Verbose {
		fmt.Println("Attempting generic unpacking...")
	}
	
	return data, nil
}
func (u *Unpacker) saveUnpackedBinary() error {
	if u.UnpackedBin == nil || len(u.UnpackedBin) == 0 {
		return errors.New("no unpacked binary to save")
	}
	if u.Config.OutputPath == "" {
		return errors.New("no output path specified")
	}
	return os.WriteFile(u.Config.OutputPath, u.UnpackedBin, 0644)
}
func (u *Unpacker) AnalyzeUnpackedBinary() (map[string]interface{}, error) {
	if u.UnpackedBin == nil || len(u.UnpackedBin) == 0 {
		return nil, errors.New("no unpacked binary to analyze")
	}
	analysis := make(map[string]interface{})
	
	fileType := u.determineFileType(u.UnpackedBin)
	analysis["file_type"] = fileType
	
	analysis["possibly_still_packed"] = u.isPossiblyStillPacked(u.UnpackedBin)
	
	info, err := u.getBinaryInfo(u.UnpackedBin, fileType)
	if err == nil {
		analysis["binary_info"] = info
	}
	
	suspiciousPatterns := u.findSuspiciousPatterns(u.UnpackedBin)
	if len(suspiciousPatterns) > 0 {
		analysis["suspicious_patterns"] = suspiciousPatterns
	}
	return analysis, nil
}
func (u *Unpacker) determineFileType(data []byte) string {
	
	if len(data) > 4 && data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return "ELF"
	}
	
	if len(data) > 2 && data[0] == 'M' && data[1] == 'Z' {
		return "PE"
	}
	
	if len(data) > 4 && ((data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) ||
		(data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)) {
		return "Mach-O"
	}
	return "Unknown"
}
func (u *Unpacker) isPossiblyStillPacked(data []byte) bool {
	
	
	
	entropy := u.calculateEntropy(data)
	
	return entropy > 7.0
}
func (u *Unpacker) calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	
	frequencies := make(map[byte]int)
	for _, b := range data {
		frequencies[b]++
	}
	
	entropy := 0.0
	for _, count := range frequencies {
		probability := float64(count) / float64(len(data))
		entropy -= probability * (float64(binary.Size(probability)) / float64(binary.Size(1.0)))
	}
	return entropy
}
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
func (u *Unpacker) getELFInfo(data []byte) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	elfFile, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	
	info["machine"] = elfFile.Machine.String()
	info["type"] = elfFile.Type.String()
	info["entry_point"] = elfFile.Entry
	
	sections := make([]string, 0)
	for _, section := range elfFile.Sections {
		sections = append(sections, section.Name)
	}
	info["sections"] = sections
	return info, nil
}
func (u *Unpacker) getPEInfo(data []byte) (map[string]interface{}, error) {
	info := make(map[string]interface{})
	
	peFile, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	
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
	
	sections := make([]string, 0)
	for _, section := range peFile.Sections {
		sections = append(sections, section.Name)
	}
	info["sections"] = sections
	return info, nil
}
func (u *Unpacker) findSuspiciousPatterns(data []byte) []string {
	var patterns []string
	
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
