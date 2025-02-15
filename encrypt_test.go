package adyen_encrypt

import (
	"encoding/base64"
	"testing"

	encryptions "github.com/JohnGrimm/adyen-encrypt-4.9/encryption"
	"github.com/corpix/uarand"
)

func TestEncryptSingle(t *testing.T) {
	enc, _ := PrepareEncryptor(
		"10001|C621C7E8267CF5A0758EC2E0530AF2B59625EFA2A26174690B401476BA5FF1AD079D881838CD625384D546DAB4E82CF1E414F1F2C7EB5420AFD9F8FF516479FD2F7EDA66572BB9C08672961C8BF528FFD0B1951B29C2332FBF301A96BA1D41DA28F39718095222C4CCFF0C0BCAECDEF944D2994D45FB81FE210090B46E5BE22CCCBAC4F413C08F90229D0E9096046BDB6745E5C549A7FEDC907646661C79A0A14ECE4EA351A07832D7228AA8D3398874D173076E475196E1DFBF35E0FDA83C047DED0156D6839D67DF1DC0D00509E8876DF209169832607B3FAE834F0DD8E78123A991E50EFD485740622FBE3EAAE6FA33BEE2DDA42465DA36D468500AF7BD01",
		"live_YCN5QJ4BXJHSTL24DUQMIHO4JQP2XDLK",
		"https://www.bstn.com",
	)
	ts := NowTimeISO()
	data := []byte(`{"expiryMonth":"12","generationtime":"` + ts + `"}`)
	encrypted, err := enc.EncryptSingle(data)
	if err != nil {
		t.Logf(err.Error())
	} else {
		t.Logf("%s", encrypted)
	}
}

func TestEncryptData(t *testing.T) {
	enc, _ := PrepareEncryptor(
		"10001|C621C7E8267CF5A0758EC2E0530AF2B59625EFA2A26174690B401476BA5FF1AD079D881838CD625384D546DAB4E82CF1E414F1F2C7EB5420AFD9F8FF516479FD2F7EDA66572BB9C08672961C8BF528FFD0B1951B29C2332FBF301A96BA1D41DA28F39718095222C4CCFF0C0BCAECDEF944D2994D45FB81FE210090B46E5BE22CCCBAC4F413C08F90229D0E9096046BDB6745E5C549A7FEDC907646661C79A0A14ECE4EA351A07832D7228AA8D3398874D173076E475196E1DFBF35E0FDA83C047DED0156D6839D67DF1DC0D00509E8876DF209169832607B3FAE834F0DD8E78123A991E50EFD485740622FBE3EAAE6FA33BEE2DDA42465DA36D468500AF7BD01",
		"live_YCN5QJ4BXJHSTL24DUQMIHO4JQP2XDLK",
		"https://www.bstn.com",
	)
	encryptedData, err := enc.EncryptData("4242424242424242", "12", "2023", "123")
	if err != nil {
		t.Logf(err.Error())
	} else {
		t.Logf("encryptedCardNumber: %s\nencryptedExpiryMonth: %s\nencryptedExpiryYear: %s\nencryptedSecurityCode: %s\n", encryptedData.EncryptedCardNumber, encryptedData.EncryptedExpiryMonth, encryptedData.EncryptedExpiryYear, encryptedData.EncryptedSecurityCode)
	}
}

func TestRiskData(t *testing.T) {
	ua := uarand.GetRandom()

	null := ""
	rd := encryptions.NewRiskData(
		ua,
		"en-US",
		24,
		4,
		8,
		360,
		640,
		360,
		640,
		-300,
		"America/Chicago",
		"MacIntel",
		&null,
		&null,
	)

	token, err := rd.Generate()
	if err != nil {
		t.Logf(err.Error())
	}

	t.Logf("token: %s", base64.StdEncoding.EncodeToString([]byte(token)))

}
