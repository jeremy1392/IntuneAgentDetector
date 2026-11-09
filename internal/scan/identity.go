package scan

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// FileIdentity is what a binary says about itself.
type FileIdentity struct {
	Product string
	Company string
	Signer  string
}

var (
	modCrypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose    = modCrypt32.NewProc("CryptMsgClose")

	identityMu    sync.Mutex
	identityCache = map[string]*cachedIdentity{}
)

type cachedIdentity struct {
	id         FileIdentity
	signerDone bool
}

const (
	certQueryObjectFile                  = 1
	certQueryContentFlagPKCS7SignedEmbed = 1 << 10
	certQueryFormatFlagBinary            = 1 << 1
	cmsgSignerInfoParam                  = 6
	certFindSubjectCert                  = 11 << 16
	certNameSimpleDisplayType            = 4
	certEncoding                         = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING
)

// cmsgSignerInfo mirrors the beginning of CMSG_SIGNER_INFO.
type cmsgSignerInfo struct {
	Version      uint32
	Issuer       windows.CertNameBlob
	SerialNumber windows.CryptIntegerBlob
}

// identify returns the version information and the Authenticode signer of a
// binary. Results are cached per path for the duration of the scan.
func identify(path string, withSigner bool) FileIdentity {
	if path == "" {
		return FileIdentity{}
	}
	key := strings.ToLower(path)
	identityMu.Lock()
	c, ok := identityCache[key]
	identityMu.Unlock()
	if ok && (c.signerDone || !withSigner) {
		return c.id
	}
	if !ok {
		c = &cachedIdentity{}
		c.id.Product, c.id.Company = versionInfo(path)
	}
	if withSigner && !c.signerDone {
		// A signer name only counts when the signature verifies: anyone can
		// embed a self-issued certificate that bears a vendor's name.
		if s := embeddedSigner(path); s != "" && verifySignature(path) {
			c.id.Signer = s
		}
		c.signerDone = true
	}
	identityMu.Lock()
	identityCache[key] = c
	identityMu.Unlock()
	return c.id
}

// versionInfo reads ProductName and CompanyName from the version resource.
func versionInfo(path string) (product, company string) {
	size, err := windows.GetFileVersionInfoSize(path, nil)
	if err != nil || size == 0 {
		return "", ""
	}
	buf := make([]byte, size)
	if err := windows.GetFileVersionInfo(path, 0, size, unsafe.Pointer(&buf[0])); err != nil {
		return "", ""
	}
	block := unsafe.Pointer(&buf[0])

	var langs []string
	var ptr unsafe.Pointer
	var n uint32
	if windows.VerQueryValue(block, `\VarFileInfo\Translation`, unsafe.Pointer(&ptr), &n) == nil && n >= 4 {
		pairs := unsafe.Slice((*uint16)(ptr), n/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			langs = append(langs, fmt.Sprintf("%04x%04x", pairs[i], pairs[i+1]))
		}
	}
	langs = append(langs, "040904b0", "040904e4", "000004b0")

	query := func(name string) string {
		for _, lc := range langs {
			var p unsafe.Pointer
			var l uint32
			if windows.VerQueryValue(block, `\StringFileInfo\`+lc+`\`+name, unsafe.Pointer(&p), &l) == nil && l > 0 && p != nil {
				return strings.TrimSpace(windows.UTF16PtrToString((*uint16)(p)))
			}
		}
		return ""
	}
	return query("ProductName"), query("CompanyName")
}

// verifySignature verifies the embedded Authenticode signature of a file
// offline: the file hash and the certificate chain are checked against the
// local trust store, revocation is not checked and no URL is retrieved, so a
// scan never touches the network. It is called only for candidate binaries
// whose catalog entry lists signers.
func verifySignature(path string) bool {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	file := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p16}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
		ProvFlags:                       windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	runtime.KeepAlive(file)
	return verifyErr == nil
}

// embeddedSigner returns the subject name of the embedded Authenticode
// signer; verifySignature tells whether the signature is valid. Binaries
// signed through a catalog file have no embedded signer and are identified
// by other evidence. Packaged apps are identified by their package family
// name instead.
func embeddedSigner(path string) string {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	var enc, contentType, formatType uint32
	var store, msg windows.Handle
	err = windows.CryptQueryObject(certQueryObjectFile, unsafe.Pointer(p16),
		certQueryContentFlagPKCS7SignedEmbed, certQueryFormatFlagBinary, 0,
		&enc, &contentType, &formatType, &store, &msg, nil)
	if err != nil {
		return ""
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	var size uint32
	if r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 || size == 0 {
		return ""
	}
	buf := make([]uint64, (size+7)/8)
	if r, _, _ := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerInfoParam, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return ""
	}
	si := (*cmsgSignerInfo)(unsafe.Pointer(&buf[0]))
	var ci windows.CertInfo
	ci.Issuer = si.Issuer
	ci.SerialNumber = si.SerialNumber
	ctx, err := windows.CertFindCertificateInStore(store, certEncoding, 0, certFindSubjectCert, unsafe.Pointer(&ci), nil)
	if err != nil || ctx == nil {
		return ""
	}
	defer windows.CertFreeCertificateContext(ctx)
	name := make([]uint16, 512)
	n := windows.CertGetNameString(ctx, certNameSimpleDisplayType, 0, nil, &name[0], uint32(len(name)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(name[:n])
}
