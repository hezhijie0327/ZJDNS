package dnssec

import (
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/miekg/dns"
)

const testXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
	<Zone>.</Zone>
	<KeyDigest id="K1" validFrom="2017-02-02T00:00:00+00:00">
		<KeyTag>20326</KeyTag>
		<Algorithm>8</Algorithm>
		<DigestType>2</DigestType>
		<Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
		<PublicKey>AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=</PublicKey>
		<Flags>257</Flags>
	</KeyDigest>
	<KeyDigest id="K2" validFrom="2010-07-15T00:00:00+00:00" validUntil="2019-01-11T00:00:00+00:00">
		<KeyTag>19036</KeyTag>
		<Algorithm>8</Algorithm>
		<DigestType>2</DigestType>
		<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
		<PublicKey>AwEAAa98fakekeyforexpiredanchor000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000=</PublicKey>
		<Flags>257</Flags>
	</KeyDigest>
	<KeyDigest id="K3" validFrom="2024-07-18T00:00:00+00:00">
		<KeyTag>38696</KeyTag>
		<Algorithm>8</Algorithm>
		<DigestType>2</DigestType>
		<Digest>683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16</Digest>
		<PublicKey>AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=</PublicKey>
		<Flags>257</Flags>
	</KeyDigest>
	<KeyDigest id="K4" validFrom="2020-01-01T00:00:00+00:00">
		<KeyTag>99999</KeyTag>
		<Algorithm>8</Algorithm>
		<DigestType>2</DigestType>
		<Digest>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Digest>
		<!-- Missing PublicKey and Flags — should be skipped -->
	</KeyDigest>
</TrustAnchor>`

func TestLoadTrustAnchorsFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.xml")
	if err := os.WriteFile(path, []byte(testXML), 0o600); err != nil {
		t.Fatal(err)
	}

	keys, err := loadTrustAnchorsFromFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys (expired K2 + K4 without PublicKey skipped), got %d", len(keys))
	}

	// K1 (key tag 20326) should be loaded.
	if keys[0].KeyTag() != 20326 {
		t.Errorf("first key tag should be 20326, got %d", keys[0].KeyTag())
	}
	if keys[0].Flags&dns.FlagSEP == 0 {
		t.Error("first key missing SEP flag")
	}

	// K3 (key tag 38696) should be loaded.
	if keys[1].KeyTag() != 38696 {
		t.Errorf("second key tag should be 38696, got %d", keys[1].KeyTag())
	}
}

func TestLoadTrustAnchorsFromFile_NotFound(t *testing.T) {
	_, err := loadTrustAnchorsFromFile("/nonexistent/root-anchors.xml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadTrustAnchorsFromFile_InvalidXML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.xml")
	if err := os.WriteFile(path, []byte("not xml"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTrustAnchorsFromFile(path)
	if err == nil {
		t.Error("expected error for invalid XML")
	}
}

func TestLoadTrustAnchorsFromFile_NoPublicKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "root-anchors.xml")
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="test" source="test">
	<Zone>.</Zone>
	<KeyDigest id="K4" validFrom="2020-01-01T00:00:00+00:00">
		<KeyTag>99999</KeyTag>
		<Algorithm>8</Algorithm>
		<DigestType>2</DigestType>
		<Digest>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</Digest>
	</KeyDigest>
</TrustAnchor>`
	if err := os.WriteFile(path, []byte(xml), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadTrustAnchorsFromFile(path)
	if err == nil {
		t.Error("expected error when no KeyDigest has a public key")
	}
}
